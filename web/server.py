# -*- coding: utf-8 -*-
"""嵌入式 Web 管理界面的 HTTP 服务层。

仅使用 Python 标准库 http.server，默认只绑定 127.0.0.1。
所有响应均为 UTF-8 编码的 JSON，变更类接口只接受 application/json。
"""

from __future__ import annotations

import configparser
import email.utils
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

from .service import (
    MAX_BODY_BYTES,
    ConfigService,
    CookieService,
    LogService,
    RecordingsService,
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
    "/login": ("login.html", "text/html; charset=utf-8"),
    "/login.html": ("login.html", "text/html; charset=utf-8"),
    "/login.css": ("login.css", "text/css; charset=utf-8"),
    "/login.js": ("login.js", "application/javascript; charset=utf-8"),
    # 录制回放页面（独立页面，沿用既有的同源 / 鉴权 / CSP 约束）
    "/playback": ("playback.html", "text/html; charset=utf-8"),
    "/playback.html": ("playback.html", "text/html; charset=utf-8"),
    "/playback.css": ("playback.css", "text/css; charset=utf-8"),
    "/playback.js": ("playback.js", "application/javascript; charset=utf-8"),
}

# 安全响应头（静态资源与录制文件响应共用，禁止内联脚本/样式、禁止被嵌套）
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")
WILDCARD_HOSTS = ("0.0.0.0", "::", "")

# ---------------------------------------------------------------- 登录鉴权
SESSION_COOKIE = "dlr_session"
SESSION_TTL_SECONDS = 12 * 3600
LOGIN_MAX_FAILS = 5
LOGIN_FAIL_WINDOW_SECONDS = 300
# 这些路径在鉴权之前放行（登录页与其静态资源）
PUBLIC_PATHS = ("/login", "/login.html", "/login.css", "/login.js")


class LoginGuard:
    """按来源 IP 限制登录失败次数，缓解暴力破解。

    只以 TCP 对端地址计数，不信任 X-Forwarded-For（该头可伪造，会被绕过）。
    放在反向代理后面时同一代理的所有请求共用一个计数。
    """

    def __init__(self, max_fails: int = LOGIN_MAX_FAILS, window: int = LOGIN_FAIL_WINDOW_SECONDS) -> None:
        self._max_fails = max_fails
        self._window = window
        self._records: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str) -> list[float]:
        now = time.time()
        items = [moment for moment in self._records.get(key, []) if now - moment < self._window]
        if items:
            self._records[key] = items
        else:
            self._records.pop(key, None)
        return items

    def locked_seconds(self, key: str) -> int:
        with self._lock:
            items = self._prune(key)
            if len(items) < self._max_fails:
                return 0
            return max(int(self._window - (time.time() - items[-self._max_fails])), 1)

    def record_fail(self, key: str) -> None:
        with self._lock:
            self._prune(key)
            self._records.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._records.pop(key, None)


class AuthStore:
    """用户名/口令校验 + HMAC 签名的会话令牌。

    签名密钥每进程随机生成，因此重启后已发出的会话全部失效。
    未配置口令时 enabled 为 False，服务保持无鉴权（并打印告警）。
    """

    def __init__(self, username: str = "", password: str = "") -> None:
        self.username = (username or "admin").strip() or "admin"
        self._password = password or ""
        self.enabled = bool(self._password)
        self._secret = secrets.token_bytes(32)
        self._guard = LoginGuard()

    def locked_seconds(self, key: str) -> int:
        return self._guard.locked_seconds(key)

    def verify(self, username: str, password: str, key: str) -> tuple[bool, str, int]:
        """返回 (是否通过, 提示, HTTP 状态码)。"""
        if not self.enabled:
            return True, "", 200
        if self._guard.locked_seconds(key) > 0:
            return False, "登录尝试过于频繁，请稍后再试", 429
        if hmac.compare_digest(username or "", self.username) and hmac.compare_digest(password or "", self._password):
            self._guard.reset(key)
            return True, "", 200
        self._guard.record_fail(key)
        return False, "用户名或密码不正确", 401

    def issue_token(self) -> str:
        expire_at = str(int(time.time()) + SESSION_TTL_SECONDS)
        return "{0}.{1}".format(expire_at, self._sign(expire_at))

    def valid_token(self, token: str) -> bool:
        if not token or "." not in token:
            return False
        expire_at, _, signature = token.partition(".")
        if not hmac.compare_digest(signature, self._sign(expire_at)):
            return False
        try:
            return int(expire_at) > time.time()
        except (TypeError, ValueError):
            return False

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


class WebContext:
    """Web 服务运行所需的依赖集合（由 main 注入，不反向依赖 main）。"""

    def __init__(
        self,
        url_service: UrlConfigService,
        config_service: ConfigService,
        cookie_service: CookieService,
        log_service: LogService,
        system_service: SystemService,
        state_provider: Optional[Callable[[], dict[str, Any]]] = None,
        bind_host: str = "127.0.0.1",
        bind_port: int = 8080,
        auth: Optional[AuthStore] = None,
        cookie_check_file: Optional[str] = None,
        recordings_service: Optional[RecordingsService] = None,
    ) -> None:
        self.url_service = url_service
        self.config_service = config_service
        self.cookie_service = cookie_service
        self.log_service = log_service
        self.system_service = system_service
        self.state_provider = build_state_provider_wrapper(state_provider)
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.auth = auth if auth is not None else AuthStore()
        self.cookie_check_file = cookie_check_file
        self.recordings_service = recordings_service

    def read_cookie_check(self) -> dict[str, Any]:
        """读取 main.py 定时检测写出的结果文件；不存在时返回空结构。"""
        empty: dict[str, Any] = {
            "available": False,
            "updated_at": 0,
            "summary": {},
            "results": [],
        }
        path = self.cookie_check_file
        if not path or not os.path.isfile(path):
            return empty
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            return empty
        if not isinstance(data, dict):
            return empty
        results = data.get("results")
        data["results"] = results if isinstance(results, list) else []
        data["available"] = True
        return data

    def cookie_check_map(self) -> dict[str, dict[str, Any]]:
        """按配置键索引检测结果（同时兼容小写键，B站 在 config.ini 里有大小写两种写法）。"""
        mapping: dict[str, dict[str, Any]] = {}
        for item in self.read_cookie_check().get("results", []):
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or "")
            if not key:
                continue
            mapping[key] = item
            mapping.setdefault(key.lower(), item)
        return mapping


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

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: Optional[list[tuple[str, str]]] = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in extra_headers or ():
            self.send_header(name, value)
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

            if path in PUBLIC_PATHS:
                self._dispatch_public(method, path)
                return
            if not self._check_authenticated(path):
                return

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

    # ------------------------------------------------------------ 登录鉴权

    def _client_ip(self) -> str:
        try:
            return str(self.client_address[0])
        except (AttributeError, IndexError, TypeError):
            return "unknown"

    def _session_token(self) -> str:
        for item in (self.headers.get("Cookie") or "").split(";"):
            name, sep, value = item.partition("=")
            if sep and name.strip() == SESSION_COOKIE:
                return value.strip()
        return ""

    @staticmethod
    def _session_cookie(token: str, max_age: int = SESSION_TTL_SECONDS) -> str:
        # 不设 Secure：管理界面通常经 SSH 隧道以 http 访问，加了会导致 Cookie 无法写入
        return "{0}={1}; Path=/; HttpOnly; SameSite=Strict; Max-Age={2}".format(
            SESSION_COOKIE, token, max_age
        )

    def _check_authenticated(self, path: str) -> bool:
        context: Optional[WebContext] = getattr(self.server, "context", None)  # type: ignore[assignment]
        auth = getattr(context, "auth", None)
        if auth is None or not auth.enabled or auth.valid_token(self._session_token()):
            return True
        if path.startswith("/api/"):
            self._send_json(
                401,
                {"ok": False, "error": "未登录或登录已过期，请重新登录", "code": "unauthorized"},
            )
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        return False

    def _dispatch_public(self, method: str, path: str) -> None:
        """登录页与其静态资源，以及 POST /login 登录提交。"""
        if path not in PUBLIC_PATHS:
            raise WebServiceError("请求的资源不存在", 404, "not_found")
        if method == "POST":
            self._handle_login()
            return
        if method not in ("GET", "HEAD"):
            raise WebServiceError("不支持的请求方法", 405, "method_not_allowed")
        self._dispatch_static(path)

    def _handle_login(self) -> None:
        context: WebContext = self.server.context  # type: ignore[assignment]
        if context is None:
            raise WebServiceError("Web 服务尚未初始化", 503, "not_ready")
        auth = context.auth
        client_ip = self._client_ip()

        if not auth.enabled:
            self._send_json(200, {"ok": True, "message": "未启用登录鉴权", "redirect": "/"})
            return

        locked = auth.locked_seconds(client_ip)
        if locked > 0:
            self._send_json(
                429,
                {
                    "ok": False,
                    "error": "登录尝试过于频繁，请 {0} 秒后重试".format(locked),
                    "code": "too_many_attempts",
                },
            )
            return

        payload = self._read_json_body()
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        passed, message, status = auth.verify(username, password, client_ip)
        if not passed:
            self._send_json(status, {"ok": False, "error": message, "code": "login_failed"})
            return
        self._send_json(
            200,
            {"ok": True, "message": "登录成功", "redirect": "/"},
            [("Set-Cookie", self._session_cookie(auth.issue_token()))],
        )

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

        if path == "/api/cookies":
            if method == "GET":
                reveal = (query.get("reveal") or ["0"])[0]
                show_raw = str(reveal).strip().lower() in ("1", "true", "yes", "on")
                fields = context.cookie_service.list_cookies(reveal=show_raw)
                # 附上最近一次在线检测的状态（失效/有效/未知/检测失败）
                check_map = context.cookie_check_map()
                for field in fields:
                    key = str(field.get("key") or "")
                    result = check_map.get(key) or check_map.get(key.lower())
                    if result:
                        field["check_status"] = result.get("status", "")
                        field["check_status_text"] = result.get("status_text", "")
                        field["check_detail"] = result.get("detail", "")
                        field["check_at"] = result.get("checked_at", 0)
                    else:
                        field["check_status"] = ""
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "data": {
                            "section": "Cookie",
                            "reveal": show_raw,
                            "fields": fields,
                            "check": context.read_cookie_check(),
                        },
                    },
                )
                return
            if method == "PUT":
                payload = self._read_json_body()
                values = payload.get("values") if isinstance(payload.get("values"), dict) else payload
                fields = context.cookie_service.update_values(values)
                self._send_json(
                    200,
                    {"ok": True, "data": {"section": "Cookie", "fields": fields}, "message": "Cookie 已保存"},
                )
                return
            raise WebServiceError("不支持的请求方法", 405, "method_not_allowed")

        if path == "/api/cookie-check":
            self._require(method, ("GET",))
            self._send_json(200, {"ok": True, "data": context.read_cookie_check()})
            return

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

        if path == "/api/logout":
            self._require(method, ("POST",))
            self._send_json(
                200,
                {"ok": True, "message": "已退出登录", "redirect": "/login"},
                [("Set-Cookie", self._session_cookie("", 0))],
            )
            return

        # ---------------------------------------------------------- 录制回放
        if path == "/api/recordings":
            self._require(method, ("GET",))
            self._send_json(200, {"ok": True, "data": self._recordings_list(context, query)})
            return

        if path == "/api/recordings/file":
            if method == "DELETE":
                self._delete_recording(context, query)
                return
            self._require(method, ("GET", "HEAD"))
            self._send_recording_file(context, query)
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

    # ------------------------------------------------------------ 录制回放

    def _recordings_list(
        self, context: WebContext, query: Optional[dict[str, list[str]]] = None
    ) -> list[dict[str, Any]]:
        service = getattr(context, "recordings_service", None)
        if service is None:
            return []
        # 默认走 TTL 缓存；用户主动点刷新时带 refresh=1 绕过缓存，立即看到新录制的文件
        force = False
        if query:
            force = (query.get("refresh") or [""])[0].strip().lower() in ("1", "true", "yes")
        return service.list_recordings(force=force)

    def _send_recording_file(self, context: WebContext, query: dict[str, list[str]]) -> None:
        service = getattr(context, "recordings_service", None)
        if service is None:
            raise WebServiceError("录制回放功能未启用", 503, "not_ready")
        rel = (query.get("path") or [""])[0]
        file_path = service.resolve(rel)
        try:
            self._send_file_range(file_path, "video/mp4")
        except WebServiceError:
            raise
        except OSError as error:
            raise WebServiceError("读取录制文件失败：{0}".format(error), 500, "file_read_failed") from error

    def _delete_recording(self, context: WebContext, query: dict[str, list[str]]) -> None:
        """删除单个录制文件（DELETE /api/recordings/file?path=...）。

        鉴权由 _dispatch 统一把关：非 PUBLIC_PATHS 的 /api/ 请求必须持有有效会话
        Cookie（DLR_WEB_USER/PASSWORD 启用时），同源校验也已前置，天然防 CSRF。
        路径合法性交由 service.resolve 校验，杜绝目录穿越。
        """
        service = getattr(context, "recordings_service", None)
        if service is None:
            raise WebServiceError("录制回放功能未启用", 503, "not_ready")
        rel = (query.get("path") or [""])[0]
        result = service.delete_recording(rel)
        self._send_json(200, {"ok": True, "data": result, "message": "文件已删除"})

    def _send_file_range(self, file_path: str, content_type: str) -> None:
        """支持 HTTP Range 的静态文件流式响应，便于 <video> 拖拽与分段加载。"""
        try:
            # 单次 stat 同时取大小与修改时间，避免重复系统调用
            stat_result = os.stat(file_path)
        except OSError as error:
            raise WebServiceError("读取录制文件失败：{0}".format(error), 500, "file_read_failed") from error
        file_size = stat_result.st_size
        file_mtime = stat_result.st_mtime
        # size + mtime 构成弱校验器：录制中的文件持续增长，仅凭 mtime 不足以标识版本
        etag = '"{0:x}-{1:x}"'.format(int(file_mtime), file_size)

        range_header = (self.headers.get("Range") or "").strip()
        start, end = 0, file_size - 1
        partial = False
        if range_header:
            matched = re.match(r"bytes=(\d*)-(\d*)$", range_header)
            if matched:
                # If-Range 校验器不匹配时按 RFC 7233 忽略本次 Range，回退为整体 200，
                # 否则客户端会拿着针对旧版本文件的偏移在新文件上取到错位数据
                if_range = (self.headers.get("If-Range") or "").strip()
                range_valid = True
                if if_range and if_range.strip('"') != etag.strip('"'):
                    range_valid = False
                if range_valid:
                    begin, finish = matched.group(1), matched.group(2)
                    start = int(begin) if begin else 0
                    end = int(finish) if finish else file_size - 1
                    if start < 0 or end >= file_size or start > end:
                        self.send_response(416)
                        self.send_header("Content-Range", "bytes */{0}".format(file_size))
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    partial = True
        length = end - start + 1
        if partial:
            self.send_response(206)
            self.send_header("Content-Range", "bytes {0}-{1}/{2}".format(start, end, file_size))
        else:
            self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", email.utils.formatdate(file_mtime, usegmt=True))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        if self.command == "HEAD":
            return
        self._write_file_range(file_path, start, length)

    def _write_file_range(self, file_path: str, start: int, length: int) -> None:
        chunk_size = 256 * 1024
        sent = 0
        try:
            with open(file_path, "rb") as handle:
                handle.seek(start)
                while sent < length:
                    data = handle.read(min(chunk_size, length - sent))
                    if not data:
                        break
                    self.wfile.write(data)
                    sent += len(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


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
    auth_user: str = "",
    auth_password: str = "",
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
    downloads_dir = _resolve_downloads_dir(config_file, disk_path)
    context = WebContext(
        url_service=UrlConfigService(url_config_file, backup_dir, lock),
        config_service=ConfigService(config_file, backup_dir, lock),
        cookie_service=CookieService(config_file, backup_dir, lock),
        log_service=LogService(log_file),
        system_service=SystemService(app_version=app_version, disk_path=disk_path),
        state_provider=state_provider,
        bind_host=bind_host,
        bind_port=bind_port,
        auth=AuthStore(auth_user, auth_password),
        cookie_check_file=os.path.join(os.path.dirname(os.path.abspath(config_file)), "cookie_check.json"),
        recordings_service=RecordingsService(downloads_dir, lock),
    )

    if not context.auth.enabled:
        print("[Web] 警告：未配置登录口令，管理界面处于无鉴权状态，请勿暴露到公网或不可信网络")
        print("[Web] 启用方式：环境变量 DLR_WEB_PASSWORD（可选 DLR_WEB_USER），"
              "或 config.ini [Web] 段填写 web登录用户名 / web登录密码")
    else:
        print("[Web] 登录鉴权已启用，访问管理界面需要先登录（连续 {0} 次失败将锁定 {1} 秒）".format(
            LOGIN_MAX_FAILS, LOGIN_FAIL_WINDOW_SECONDS))

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


def _read_config_value(config_file: str, section: str, option: str, default: str) -> str:
    """只读读取 config.ini 中单个配置值（标准库实现，不破坏原文件）。"""
    try:
        parser = configparser.ConfigParser()
        parser.read(config_file, encoding="utf-8-sig")
        if parser.has_option(section, option):
            return (parser.get(section, option) or "").strip()
    except Exception:
        pass
    return default


def _resolve_downloads_dir(config_file: str, disk_path: Optional[str]) -> str:
    """解析录制文件根目录。

    优先级：config.ini [录制设置] 直播保存路径(不填则默认) > 调用方注入的 disk_path
    （即默认 downloads）> <程序根目录>/downloads。相对路径按程序根目录解析。
    """
    # STATIC_DIR 形如 <程序根目录>/web/static，需连剥两层才是程序根目录：
    # 第一层剥到 web 包本身，第二层才到根目录。只剥一层会导致 config.ini 中
    # 的相对保存路径被解析成 <根目录>/web/downloads，与 Docker 挂载的
    # /app/downloads 不符，回放列表将出现空白。
    app_root = os.path.dirname(os.path.dirname(STATIC_DIR))
    save_path = _read_config_value(config_file, "录制设置", "直播保存路径(不填则默认)", "")
    if save_path:
        if not os.path.isabs(save_path):
            save_path = os.path.join(app_root, save_path)
        return os.path.abspath(save_path)
    if disk_path:
        return os.path.abspath(disk_path)
    return os.path.abspath(os.path.join(app_root, "downloads"))


def stop_web_server(server: Optional[WebAdminServer]) -> None:
    """停止 Web 管理服务。"""
    if server is None:
        return
    try:
        server.shutdown()
    except Exception:  # noqa: BLE001 - 关闭失败无需抛出
        pass
