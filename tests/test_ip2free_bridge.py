# -*- coding: utf-8 -*-
"""src/ip2free_bridge 单元测试（全离线）。

在 127.0.0.1 上起一个假的 socks5 服务端，验证：
* socks5 握手（无认证 / 用户名密码认证）与 CONNECT 目标解析；
* 本地 HTTP 代理把 CONNECT 与绝对 URI 请求正确转发；
* 代理池为空时返回 502，而不是静默直连。
"""

import importlib.util
import socket
import socketserver
import struct
import sys
import threading
import time
import unittest
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "src", filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bridge_mod = load_module("_ip2free_bridge_under_test", "ip2free_bridge.py")


class FakeSocks5Handler(socketserver.BaseRequestHandler):
    """最小 socks5 服务端：鉴权 -> 记录目标 -> 回显固定响应。"""

    def handle(self):
        try:
            self._handle()
        except (OSError, IndexError):
            return  # 客户端提前断开（例如握手被拒的用例）时静默退出

    def _handle(self):
        server = self.server
        sock = self.request
        sock.settimeout(5)
        greeting = sock.recv(2)
        methods = sock.recv(greeting[1])
        if server.require_auth:
            sock.sendall(b"\x05\x02")
            version = sock.recv(2)
            user = sock.recv(version[1]).decode()
            plen = sock.recv(1)[0]
            password = sock.recv(plen).decode()
            server.auth_seen.append((user, password))
            sock.sendall(b"\x01\x00")
        else:
            sock.sendall(b"\x05\x00")

        request = sock.recv(4)
        atyp = request[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(sock.recv(4))
        elif atyp == 0x03:
            length = sock.recv(1)[0]
            host = sock.recv(length).decode()
        else:
            host = str(sock.recv(16))
        port = struct.unpack("!H", sock.recv(2))[0]
        server.targets.append((host, port))
        sock.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
        server.chunks.append(sock.recv(4096))
        sock.sendall(server.reply)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class FakeSocks5Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, require_auth=False, reply=b"HTTP/1.1 200 OK\r\n\r\nhello"):
        self.require_auth = require_auth
        self.reply = reply
        self.targets = []
        self.chunks = []
        self.auth_seen = []
        super().__init__(("127.0.0.1", 0), FakeSocks5Handler)

    @property
    def port(self):
        return self.server_address[1]


class FakeProxy:
    def __init__(self, ip, port, username="", password=""):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password


class HandshakeTestCase(unittest.TestCase):
    def test_handshake_without_auth(self):
        server = FakeSocks5Server()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            sock = socket.create_connection(server.server_address, timeout=5)
            bridge_mod.socks5_handshake(sock, "example.com", 443)
            sock.sendall(b"ping")
            deadline = time.time() + 5
            while not server.chunks and time.time() < deadline:
                time.sleep(0.02)
            self.assertEqual(server.targets, [("example.com", 443)])
            self.assertEqual(server.chunks[0], b"ping")
            sock.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_handshake_with_auth_and_connect_reply(self):
        server = FakeSocks5Server(require_auth=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            sock = socket.create_connection(server.server_address, timeout=5)
            bridge_mod.socks5_handshake(sock, "1.2.3.4", 8443, username="u", password="p")
            self.assertEqual(server.auth_seen, [("u", "p")])
            self.assertEqual(server.targets, [("1.2.3.4", 8443)])
            sock.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_handshake_rejects_when_no_auth_but_required(self):
        server = FakeSocks5Server(require_auth=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            sock = socket.create_connection(server.server_address, timeout=5)
            with self.assertRaises(bridge_mod.Socks5Error):
                bridge_mod.socks5_handshake(sock, "example.com", 443)
            sock.close()
        finally:
            server.shutdown()
            server.server_close()


class AddressEncodingTestCase(unittest.TestCase):
    def test_ipv4_and_domain(self):
        self.assertEqual(bridge_mod._encode_address("1.2.3.4"), b"\x01\x01\x02\x03\x04")
        encoded = bridge_mod._encode_address("example.com")
        self.assertEqual(encoded[:2], b"\x03\x0b")
        self.assertEqual(encoded[2:], b"example.com")


class StickyPickerTestCase(unittest.TestCase):
    def test_same_target_keeps_same_proxy(self):
        pool = [FakeProxy("1.1.1.1", 1080), FakeProxy("2.2.2.2", 1080)]
        calls = []

        def pick():
            calls.append(1)
            return pool[len(calls) % 2]

        picker = bridge_mod.StickyUpstreamPicker(pick)
        first = picker("live.example.com", 443)
        for _ in range(5):
            self.assertIs(picker("LIVE.example.com", 443), first)
        self.assertEqual(len(calls), 1)

    def test_different_targets_pick_separately(self):
        pool = [FakeProxy("1.1.1.1", 1080), FakeProxy("2.2.2.2", 1080)]
        calls = []

        def pick():
            calls.append(1)
            return pool[len(calls) % 2]

        picker = bridge_mod.StickyUpstreamPicker(pick)
        picker("a.example.com", 443)
        picker("b.example.com", 443)
        self.assertEqual(len(calls), 2)

    def test_invalidate_forces_new_pick(self):
        pool = [FakeProxy("1.1.1.1", 1080), FakeProxy("2.2.2.2", 1080)]
        calls = []

        def pick():
            calls.append(1)
            return pool[len(calls) % 2]

        picker = bridge_mod.StickyUpstreamPicker(pick)
        first = picker("a.example.com", 443)
        picker.invalidate("a.example.com", 443)
        second = picker("a.example.com", 443)
        self.assertIsNot(first, second)

    def test_ttl_expiry_repicks(self):
        now = [0.0]
        calls = []

        def pick():
            calls.append(1)
            return FakeProxy("1.1.1.1", 1080)

        picker = bridge_mod.StickyUpstreamPicker(pick, ttl=10, clock=lambda: now[0])
        picker("a.example.com", 443)
        now[0] = 5
        picker("a.example.com", 443)
        self.assertEqual(len(calls), 1)
        now[0] = 11
        picker("a.example.com", 443)
        self.assertEqual(len(calls), 2)


class LocalBridgeTestCase(unittest.TestCase):
    def setUp(self):
        self.socks = FakeSocks5Server()
        self.thread = threading.Thread(target=self.socks.serve_forever, daemon=True)
        self.thread.start()
        self.proxy = FakeProxy("127.0.0.1", self.socks.port)
        self.bridge = bridge_mod.LocalHttpProxyBridge(lambda: self.proxy).start()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.bridge.stop()
        self.socks.shutdown()
        self.socks.server_close()

    def _send(self, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.bridge.port), timeout=5) as conn:
            conn.sendall(payload)
            buffer = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += chunk
        return buffer

    def test_connect_tunnel(self):
        response = self._send(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET / HTTP/1.1\r\n\r\n"
        )
        self.assertIn(b"200 Connection Established", response)
        self.assertEqual(self.socks.targets, [("example.com", 443)])

    def test_absolute_uri_is_rewritten(self):
        response = self._send(
            b"GET http://example.com/live.m3u8?x=1 HTTP/1.1\r\nHost: example.com\r\n"
            b"Proxy-Connection: keep-alive\r\nUser-Agent: test\r\n\r\n"
        )
        self.assertIn(b"hello", response)
        self.assertEqual(self.socks.targets, [("example.com", 80)])
        forwarded = self.socks.chunks[0]
        self.assertTrue(forwarded.startswith(b"GET /live.m3u8?x=1 HTTP/1.1"))
        self.assertIn(b"Connection: close", forwarded)
        self.assertNotIn(b"Proxy-Connection", forwarded)

    def test_missing_proxy_returns_502(self):
        self.bridge._upstream_provider = lambda: None
        response = self._send(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        self.assertIn(b"502 Bad Gateway", response)

    def test_bridge_url(self):
        self.assertTrue(self.bridge.url.startswith("http://127.0.0.1:"))
        self.assertTrue(self.bridge.running)


if __name__ == "__main__":
    unittest.main()
