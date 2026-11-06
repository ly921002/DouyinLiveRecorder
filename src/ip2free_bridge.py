# -*- coding: utf-8 -*-
"""本地 HTTP 代理桥接：把 ffmpeg 的 -http_proxy 转给上游 socks5 代理。

FFmpeg 的 ``http`` 协议只支持 HTTP 代理（``-http_proxy``），无法直连 socks5；
而 ip2free 只提供 socks5。为避免「接口探测走 socks5、录像却直连泄露本机 IP」，
这里在 127.0.0.1 上起一个极简 HTTP 代理：每来一个连接，就从代理池取当前代理，
完成 SOCKS5 握手后双向转发。

支持的请求形态（足够 ffmpeg 使用）：
* ``CONNECT host:port HTTP/1.1``  —— https / m3u8 常用，握手后原样双向转发；
* 绝对 URI 的普通请求（``GET http://host/path HTTP/1.1``）—— 改写成 origin-form 转发，
  并强制 ``Connection: close``，避免实现复杂的 keep-alive 复用。
"""

from __future__ import annotations

import inspect
import socket
import struct
import threading
import time
from typing import Callable, Optional

try:
    from .logger import logger
except ImportError:  # 单文件加载（离线单测）时回退
    import logging

    logger = logging.getLogger("ip2free.bridge")

MAX_HEADER_BYTES = 64 * 1024
BUFFER_SIZE = 64 * 1024
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_USERNAME = 0x02


class Socks5Error(RuntimeError):
    """SOCKS5 握手或转发失败。"""


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    while size > 0:
        chunk = sock.recv(size)
        if not chunk:
            raise Socks5Error("上游代理连接被关闭")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def socks5_handshake(
    sock: socket.socket,
    host: str,
    port: int,
    username: str = "",
    password: str = "",
) -> None:
    """在已建立的 TCP 连接上完成 socks5 握手 + CONNECT。"""
    if username:
        sock.sendall(bytes([SOCKS5_VERSION, 2, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERNAME]))
    else:
        sock.sendall(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))

    version, method = _recv_exact(sock, 2)
    if version != SOCKS5_VERSION:
        raise Socks5Error("上游代理返回了非 socks5 响应")
    if method == 0xFF:
        raise Socks5Error("上游代理不接受任何认证方式")

    if method == SOCKS5_AUTH_USERNAME:
        if not username:
            raise Socks5Error("上游代理要求用户名密码，但未配置")
        user_bytes = username.encode("utf-8")[:255]
        pass_bytes = password.encode("utf-8")[:255]
        request = bytes([0x01, len(user_bytes)]) + user_bytes
        request += bytes([len(pass_bytes)]) + pass_bytes
        sock.sendall(request)
        auth_version, status = _recv_exact(sock, 2)
        if auth_version != 0x01 or status != 0x00:
            raise Socks5Error("上游代理用户名密码认证失败")
    elif method != SOCKS5_AUTH_NONE:
        raise Socks5Error("上游代理要求不支持的认证方式: {0}".format(method))

    # 域名交给代理解析（等价 socks5h），避免本机 DNS 泄露
    target = _encode_address(host)
    sock.sendall(bytes([SOCKS5_VERSION, 0x01, 0x00]) + target + struct.pack("!H", int(port)))
    reply_version, reply_code, _reserved, address_type = _recv_exact(sock, 4)
    if reply_version != SOCKS5_VERSION or reply_code != 0x00:
        raise Socks5Error("上游代理 CONNECT 失败（code={0}）".format(reply_code))
    if address_type == 0x01:
        _recv_exact(sock, 4 + 2)
    elif address_type == 0x04:
        _recv_exact(sock, 16 + 2)
    elif address_type == 0x03:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length + 2)
    else:
        raise Socks5Error("上游代理返回了未知地址类型: {0}".format(address_type))


def _encode_address(host: str) -> bytes:
    try:
        packed = socket.inet_pton(socket.AF_INET, host)
        return bytes([0x01]) + packed
    except OSError:
        pass
    try:
        packed6 = socket.inet_pton(socket.AF_INET6, host)
        return bytes([0x04]) + packed6
    except OSError:
        pass
    try:
        raw = host.encode("idna")
    except UnicodeError:
        raw = host.encode("ascii", "ignore")
    raw = raw[:255]
    return bytes([0x03, len(raw)]) + raw


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(BUFFER_SIZE)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _accepts_target(provider: Callable[..., Optional[object]]) -> bool:
    """判断上游选择函数是否接受 (host, port) 目标参数（用于按目标粘住代理）。"""
    try:
        parameters = inspect.signature(provider).parameters
    except (TypeError, ValueError):
        return False
    positional = [
        item for item in parameters.values()
        if item.kind in (item.POSITIONAL_ONLY, item.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 2:
        return True
    return any(item.kind == item.VAR_POSITIONAL for item in parameters.values())


class StickyUpstreamPicker:
    """按目标粘住上游代理：同一路直播的所有连接走同一条，不同直播各自随机。

    直播多为 HLS（一个 m3u8 + 一连串分片请求），每个分片都是一次新的 CONNECT，
    如果每次随机换出口，同一路流会横跨多个落地 IP，容易触发平台风控；
    这里以 ``host:port`` 为键粘住代理，``ttl`` 到期或显式 ``invalidate`` 后才重新挑选。
    """

    def __init__(
        self,
        pick: Callable[[], Optional[object]],
        ttl: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._pick = pick
        self._ttl = ttl
        self._clock = clock
        self._mapping: dict[tuple[str, int], tuple[object, float]] = {}
        self._lock = threading.Lock()

    def __call__(self, host: str = "", port: int = 0) -> Optional[object]:
        key = (host.lower(), int(port or 0))
        now = self._clock()
        with self._lock:
            cached = self._mapping.get(key)
            if cached is not None and now - cached[1] < self._ttl:
                return cached[0]
        proxy = self._pick()
        if proxy is not None:
            with self._lock:
                self._mapping[key] = (proxy, now)
        return proxy

    def invalidate(self, host: str = "", port: int = 0) -> None:
        key = (host.lower(), int(port or 0))
        with self._lock:
            self._mapping.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._mapping.clear()


class LocalHttpProxyBridge:
    """监听 127.0.0.1 的 HTTP 代理，把流量转发到「当前」上游 socks5 代理。"""

    def __init__(
        self,
        upstream_provider: Callable[..., Optional[object]],
        host: str = "127.0.0.1",
        port: int = 0,
        connect_timeout: float = 15.0,
    ) -> None:
        self._upstream_provider = upstream_provider
        self._host = host
        self._port = port
        self._connect_timeout = connect_timeout
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stopped = threading.Event()
        self._client_threads: list[threading.Thread] = []
        self._provider_takes_target = _accepts_target(upstream_provider)

    # ---------------- 生命周期

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        if self._server is not None:
            return self._server.getsockname()[1]
        return self._port

    @property
    def url(self) -> str:
        return "http://{0}:{1}".format(self.host, self.port)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> "LocalHttpProxyBridge":
        if self.running:
            return self
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self._host, self._port))
        server.listen(64)
        server.settimeout(0.5)
        self._server = server
        self._stopped.clear()
        self._thread = threading.Thread(target=self._serve, name="ip2free-bridge", daemon=True)
        self._thread.start()
        logger.debug("本地代理桥接已启动：{0}".format(self.url))
        return self

    def stop(self) -> None:
        self._stopped.set()
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
        for worker in list(self._client_threads):
            if worker.is_alive():
                worker.join(timeout=1)
        self._client_threads.clear()

    # ---------------- 服务循环

    def _serve(self) -> None:
        while not self._stopped.is_set():
            server = self._server
            if server is None:
                return
            try:
                client, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stopped.is_set():
                    return
                continue
            worker = threading.Thread(
                target=self._handle_client, args=(client,), name="ip2free-bridge-conn", daemon=True
            )
            worker.start()
            self._client_threads = [item for item in self._client_threads if item.is_alive()] + [worker]

    def _handle_client(self, client: socket.socket) -> None:
        upstream_sock: Optional[socket.socket] = None
        try:
            client.settimeout(self._connect_timeout)
            header, rest = self._read_header(client)
            if not header:
                return
            request_line, headers = self._parse_header(header)
            if request_line is None:
                self._send_error(client, 400, "Bad Request")
                return
            method, target, version = request_line

            if method.upper() == "CONNECT":
                host, port = self._split_host_port(target, 443)
                upstream_sock = self._open_upstream(host, port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream_sock.sendall(rest)
            else:
                host, port, path = self._split_absolute_uri(target)
                if host is None:
                    self._send_error(client, 400, "Bad Request")
                    return
                upstream_sock = self._open_upstream(host, port)
                upstream_sock.sendall(self._build_origin_request(method, path, version, headers))
                if rest:
                    upstream_sock.sendall(rest)

            client.settimeout(None)
            upstream_sock.settimeout(None)
            self._relay(client, upstream_sock)
        except (Socks5Error, OSError, ValueError) as exc:
            logger.debug("本地代理桥接连接失败：{0}: {1}".format(type(exc).__name__, exc))
            self._send_error(client, 502, "Bad Gateway")
        finally:
            for sock in (upstream_sock, client):
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    pass

    def _open_upstream(self, host: str, port: int) -> socket.socket:
        if self._provider_takes_target:
            proxy = self._upstream_provider(host, port)
        else:
            proxy = self._upstream_provider()
        if proxy is None:
            raise Socks5Error("代理池中没有可用代理")
        upstream_ip = getattr(proxy, "ip", "")
        upstream_port = int(getattr(proxy, "port", 0))
        if not upstream_ip or not upstream_port:
            raise Socks5Error("代理信息不完整")
        sock = socket.create_connection((upstream_ip, upstream_port), timeout=self._connect_timeout)
        try:
            socks5_handshake(
                sock,
                host,
                port,
                username=str(getattr(proxy, "username", "") or ""),
                password=str(getattr(proxy, "password", "") or ""),
            )
        except Exception:
            sock.close()
            # 这条代理连不上目标：从粘性映射里摘掉，下次同目标会重新挑一条
            self._invalidate_upstream(host, port)
            raise
        return sock

    def _invalidate_upstream(self, host: str, port: int) -> None:
        invalidate = getattr(self._upstream_provider, "invalidate", None)
        if not callable(invalidate):
            return
        try:
            invalidate(host, port)
        except TypeError:
            invalidate()

    @staticmethod
    def _read_header(client: socket.socket) -> tuple[bytes, bytes]:
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = client.recv(4096)
            if not chunk:
                return b"", b""
            buffer += chunk
            if len(buffer) > MAX_HEADER_BYTES:
                raise Socks5Error("请求头过大")
        header, _, rest = buffer.partition(b"\r\n\r\n")
        return header + b"\r\n\r\n", rest

    @staticmethod
    def _parse_header(header: bytes) -> tuple[Optional[tuple[str, str, str]], list[tuple[str, str]]]:
        text = header.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return None, []
        parts = lines[0].split()
        if len(parts) != 3:
            return None, []
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                continue
            name, separator, value = line.partition(":")
            if not separator:
                continue
            headers.append((name.strip(), value.strip()))
        return (parts[0], parts[1], parts[2]), headers

    @staticmethod
    def _build_origin_request(
        method: str, path: str, version: str, headers: list[tuple[str, str]]
    ) -> bytes:
        skip = {"proxy-connection", "proxy-authorization", "connection"}
        lines = ["{0} {1} {2}".format(method, path or "/", version)]
        for name, value in headers:
            if name.lower() in skip:
                continue
            lines.append("{0}: {1}".format(name, value))
        lines.append("Connection: close")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1", errors="replace")

    @staticmethod
    def _split_host_port(authority: str, default_port: int) -> tuple[str, int]:
        authority = authority.strip()
        if authority.startswith("["):
            host, _, remainder = authority[1:].partition("]")
            port_text = remainder.lstrip(":")
            return host, int(port_text) if port_text else default_port
        if ":" in authority:
            host, _, port_text = authority.rpartition(":")
            if port_text.isdigit():
                return host, int(port_text)
        return authority, default_port

    @classmethod
    def _split_absolute_uri(cls, target: str) -> tuple[Optional[str], int, str]:
        lowered = target.lower()
        if not lowered.startswith("http://"):
            return None, 0, ""
        remainder = target[len("http://"):]
        slash = remainder.find("/")
        authority = remainder if slash < 0 else remainder[:slash]
        path = "/" if slash < 0 else remainder[slash:]
        host, port = cls._split_host_port(authority, 80)
        return host, port, path

    @staticmethod
    def _relay(client: socket.socket, upstream: socket.socket) -> None:
        forward = threading.Thread(target=_pump, args=(client, upstream), daemon=True)
        forward.start()
        _pump(upstream, client)
        forward.join(timeout=1)

    @staticmethod
    def _send_error(client: socket.socket, code: int, reason: str) -> None:
        try:
            body = "bridge error: {0} {1}\n".format(code, reason).encode("ascii")
            head = (
                "HTTP/1.1 {0} {1}\r\nContent-Type: text/plain\r\nContent-Length: {2}\r\n"
                "Connection: close\r\n\r\n".format(code, reason, len(body))
            ).encode("ascii")
            client.sendall(head + body)
        except OSError:
            pass


__all__ = ["LocalHttpProxyBridge", "Socks5Error", "StickyUpstreamPicker", "socks5_handshake"]
