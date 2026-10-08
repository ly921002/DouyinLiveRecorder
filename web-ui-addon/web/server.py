# -*- coding: utf-8 -*-
"""嵌入式 Web 管理界面的 HTTP 服务层。

仅使用 Python 标准库 http.server，默认只绑定 127.0.0.1。
所有响应均为 UTF-8 编码的 JSON，变更类接口只接受 application/json。
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

from .service import (
    MAX_BODY_BYTES,
    ConfigService,
    LogService,
    SystemService,
    UrlConfigService,
    WebServiceError,
    build_state_provider_wrapper,
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

STATIC_FILES: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")
WILDCARD_HOSTS = ("0.0.0.0", "::", "")


class WebContext:
    """Web 服务运行所需的依赖集合（由 main 注入，不反向依赖 main）。"""

    def __init__(
        self,
        url_service: UrlConfigService,
        config_service: ConfigService,
        log_service: LogService,
        system_service: SystemService,
        state_provider: Optional[Callable[[], dict[str, Any]]] = None,
        bind_host: str = "127.0.0.1",
        bind_port: int = 8080,
    ) -> None:
        self.url_service = url_service
        self.config_service = config_service
        self.log_service = log_service
        self.system_service = system_service
        self.state_provider = build_state_provider_wrapper(state_provider)
        self.bind_host = bind_host
        self.bind_port = bind_port


class WebAdminServer(ThreadingHTTPServer):
    """支持并发请求的 Web 管理服务。"""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler_cls: type) -> None:
        super().__init__(server_address, handler_cls)
        self.context: Optional[WebContext] = None
        self.bind_host: str = server_address[0]

    def shutdown(self) -> None:  # noqa: D102 - 标准库同名方法
        try:
            super().shutdown()
        finally:
            try:
                self.server_close()
            except OSError:
                pass


def _host_of(value: str) -> str:
    """从 URL 或 Host 头中提取 host[:port]。"""
    text = (value or "").strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0].lower()


def _host_name(host: str) -> str:
    """去掉端口，保留 IPv6 方括号。"""
    text = (host or "").strip().lower()
    if text.startswith("["):
        return text.split("]", 1)[0] + "]"
    if ":" in text:
        return text.rsplit(":", 1)[0]
    return text


class WebAdminHandler(BaseHTTPRequestHandler):
    """Web 管理界面的请求处理器。"""

    server_version = "DouyinLiveRecorderWeb"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ 基础工具

    def log_message(self, fmt: str, *args: Any) -> None:
        """静默默认访问日志，避免刷屏终端录制界面。"""

    def log_error(self, fmt: str, *args: Any) -> None:
        """静默默认错误日志。"""

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_error(self, error: WebServiceError) -> None:
        self._send_json(
            error.status,
            {"ok": False, "error": error.message, "code": error.code},
        )

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ------------------------------------------------------------ 安全校验

    def _check_same_origin(self) -> None:
        """校验 Origin 与 Host 同源，非回环绑定时只允许本机访问。"""
        server: WebAdminServer = self.server  # type: ignore[assignment]
        bind_host = getattr(server, "bind_host", "127.0.0.1") or "127.0.0.1"
        host = _host_of(self.headers.get("Host") or "")
        origin = self.headers.get("Origin")

        if origin and _host_of(origin) != host:
            raise WebServiceError("跨站请求已被拒绝：Origin 与 Host 不一致", 403, "origin_mismatch")

        if bind_host in WILDCARD_HOSTS:
            return
        allowed = {bind_host.lower(), *LOOPBACK_HOSTS}
        if _host_name(host) not in allowed and host not in allowed:
            raise WebServiceError("当前访问地址未被允许，请使用本机地址访问", 403, "host_forbidden")

    def _read_json_body(self) -> dict[str, Any]:
        """读取并解析 JSON 请求体，限制 1MB 且只接受 application/json。"""
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise WebServiceError("请求体必须是 application/json 格式", 415, "content_type_invalid")

        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise WebServiceError("缺少 Content-Length，无法读取请求体", 411, "length_required")
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as error:
            raise WebServiceError("Content-Length 不是合法数字", 400, "length_invalid") from error
        if length > MAX_BODY_BYTES:
            raise WebServiceError("请求体过大，最大支持 1MB", 413, "payload_too_large")
        if length <= 0:
            raise WebServiceError("请求体不能为空", 400, "payload_empty")

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise WebServiceError("请求体不是合法的 UTF-8 文本", 400, "payload_invalid") from error
        except json.JSONDecodeError as error:
            raise WebServiceError("请求体不是合法的 JSON：{0}".format(error.msg), 400, "payload_invalid") from error
        if not isinstance(payload, dict):
            raise WebServiceError("请求体必须是 JSON 对象", 400, "payload_invalid")
        return payload

    # ------------------------------------------------------------ 路由分发

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        try:
            self._check_same_origin()
            parts = urlsplit(self.path)
            path = parts.path.rstrip("/") or "/"
            query = parse_qs(parts.query or "")

            if path.startswith("/api/"):
                self._dispatch_api(method, path, query)
                return
            if method not in ("GET", "HEAD"):
                raise WebServiceError("静态资源只支持 GET 请求", 405, "method_not_allowed")
            self._dispatch_static(path)
        except WebServiceError as error:
            self._send_error(error)
        except Exception as error:  # noqa: BLE001 - 兜底，避免线程因异常退出
            self._send_json(500, {"ok": False, "error": "服务器内部错误：{0}".format(error), "code": "internal_error"})

    def _dispatch_static(self, path: str) -> None:
        matched = STATIC_FILES.get(path)
        if matched is None:
            raise WebServiceError("请求的资源不存在", 404, "not_found")
        file_name, content_type = matched
        file_path = os.path.join(STATIC_DIR, file_name)
        if not os.path.isfile(file_path):
            raise WebServiceError("静态资源缺失：{0}".format(file_name), 404, "static_missing")
        try:
            with open(file_path, "rb") as file_obj:
                body = file_obj.read()
        except OSError as error:
            raise WebServiceError("读取静态资源失败", 500, "static_read_failed") from error
        self._send_bytes(200, body, content_type)

    def _dispatch_api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        context: WebContext = self.server.context  # type: ignore[assignment]
        if context is None:
            raise WebServiceError("Web 服务尚未初始化", 503, "not_ready")

        if path == "/api/health":
            self._require(method, ("GET",))
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "DouyinLiveRecorder Web",
                    "status": "running",
                    "version": context.system_service.app_version,
                    "bind": "{0}:{1}".format(context.bind_host, context.bind_port),
                },
            )
            return

        if path == "/api/status":
            self._require(method, ("GET",))
            self._send_json(200, {"ok": True, "data": self._status_payload(context)})
            return

        if path == "/api/rooms":
            if method == "GET":
                rooms = context.url_service.list_rooms()
                self._send_json(200, {"ok": True, "data": rooms, "count": len(rooms)})
                return
            if method == "POST":
                payload = self._read_json_body()
                room = context.url_service.add_room(payload)
                self._send_json(201, {"ok": True, "data": room, "message": "直播间已添加"})
                return
            raise WebServiceError("不支持的请求方法", 405, "method_not_allowed")

        if path.startswith("/api/rooms/"):
            line_id = self._parse_line_id(path[len("/api/rooms/"):])
            if method == "PUT":
                payload = self._read_json_body()
                room = context.url_service.update_room(line_id, payload)
                self._send_json(200, {"ok": True, "data": room, "message": "直播间已更新"})
                return
            if method == "DELETE":
                room = context.url_service.delete_room(line_id)
                self._send_json(200, {"ok": True, "data": room, "message": "直播间已删除"})
                return
            raise WebServiceError("不支持的请求方法", 405, "method_not_allowed")

        if path == "/api/config":
            if method == "GET":
                fields = context.config_service.get_schema()
                self._send_json(200, {"ok": True, "data": {"section": "录制设置", "fields": fields}})
                return
            if method == "PUT":
                payload = self._read_json_body()
                values = payload.get("values") if isinstance(payload.get("values"), dict) else payload
                updated = context.config_service.update_values(values)
                self._send_json(200, {"ok": True, "data": updated, "message": "配置已保存，下一轮循环生效"})
                return
            raise WebServiceError("不支持的请求方法", 405, "method_not_allowed")

        if path == "/api/logs":
            self._require(method, ("GET",))
            raw_limit = (query.get("limit") or ["100"])[0]
            try:
                limit = int(str(raw_limit).strip())
            except (TypeError, ValueError):
                limit = 100
            self._send_json(200, {"ok": True, "data": context.log_service.read(limit)})
            return

        if path == "/api/system":
            self._require(method, ("GET",))
            self._send_json(200, {"ok": True, "data": context.system_service.info()})
            return

        raise WebServiceError("接口不存在：{0}".format(path), 404, "not_found")

    @staticmethod
    def _require(method: str, allowed: tuple[str, ...]) -> None:
        if method not in allowed:
            raise WebServiceError("不支持的请求方法：{0}".format(method), 405, "method_not_allowed")

    @staticmethod
    def _parse_line_id(raw: str) -> int:
        text = (raw or "").strip().strip("/")
        try:
            line_id = int(text)
        except (TypeError, ValueError) as error:
            raise WebServiceError("行号必须是数字", 400, "line_id_invalid") from error
        if line_id <= 0:
            raise WebServiceError("行号必须大于 0", 400, "line_id_invalid")
        return line_id

    def _status_payload(self, context: WebContext) -> dict[str, Any]:
        state = context.state_provider()
        try:
            rooms = context.url_service.list_rooms()
        except Exception:  # noqa: BLE001 - 配置读取失败不应影响状态接口
            rooms = []
        enabled = sum(1 for room in rooms if not room["disabled"])
        state["rooms_total"] = len(rooms)
        state["rooms_enabled"] = enabled
        state["rooms_disabled"] = len(rooms) - enabled
        state["web"] = {
            "host": context.bind_host,
            "port": context.bind_port,
            "version": context.system_service.app_version,
        }
        return state


def start_web_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    config_file: str = "config/config.ini",
    url_config_file: str = "config/URL_config.ini",
    backup_dir: str = "backup_config",
    log_file: str = "logs/streamget.log",
    file_update_lock: Optional[threading.Lock] = None,
    state_provider: Optional[Callable[[], dict[str, Any]]] = None,
    app_version: str = "",
    disk_path: Optional[str] = None,
) -> tuple[WebAdminServer, threading.Thread]:
    """启动 Web 管理服务（守护线程），返回 (server, thread)。"""
    bind_host = (host or "127.0.0.1").strip()
    try:
        bind_port = int(port)
    except (TypeError, ValueError):
        bind_port = 8080
    if not 1 <= bind_port <= 65535:
        raise WebServiceError("Web 服务端口必须在 1 到 65535 之间", 400, "port_invalid")

    lock: threading.Lock = file_update_lock if file_update_lock is not None else threading.RLock()
    context = WebContext(
        url_service=UrlConfigService(url_config_file, backup_dir, lock),
        config_service=ConfigService(config_file, backup_dir, lock),
        log_service=LogService(log_file),
        system_service=SystemService(app_version=app_version, disk_path=disk_path),
        state_provider=state_provider,
        bind_host=bind_host,
        bind_port=bind_port,
    )

    try:
        server = WebAdminServer((bind_host, bind_port), WebAdminHandler)
    except OSError as error:
        raise WebServiceError(
            "Web 服务启动失败，端口 {0} 可能已被占用：{1}".format(bind_port, error), 500, "bind_failed"
        ) from error

    server.context = context
    thread = threading.Thread(
        target=server.serve_forever,
        name="DouyinLiveRecorderWeb",
        daemon=True,
    )
    thread.start()
    return server, thread


def stop_web_server(server: Optional[WebAdminServer]) -> None:
    """停止 Web 管理服务。"""
    if server is None:
        return
    try:
        server.shutdown()
    except Exception:  # noqa: BLE001 - 关闭失败无需抛出
        pass
