# -*- coding: utf-8 -*-
"""ip2free 免费 SOCKS5 代理自动挑选。

模块职责
--------
1. ``Ip2FreeClient``     登录 api.ip2free.com，翻页抓取「免费代理列表」(/ip/freeList)。
2. ``probe_proxy``       用 httpx(socks5h) 实测外网连通性与延迟。
3. ``select_working``    并发测速，按延迟从快到慢返回可用代理。
4. ``Ip2FreeProxyPool``  组合以上流程：本地缓存、按需刷新、故障轮换、导出 proxychains。
5. ``read_proxychains_conf`` / ``write_proxychains_conf``
   与 claim_daily_proxy.py 生成的 proxychains.conf 互通，接口不可用时可用本地文件兜底。

约定
----
* 账号密码优先取环境变量 ``IP2FREE_EMAIL`` / ``IP2FREE_PASSWORD``，其次 config.ini。
* 配置项从 config.ini 的 ``[录制设置]`` 读取，见 ``CONFIG_KEYS``。
* 状态文件（token / 代理缓存 / proxychains 导出）默认放在工程根目录的 ``.ip2free`` 目录。
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence
from urllib.parse import quote, unquote, urlsplit

import httpx

try:  # requests 是项目已有依赖，缺失时只在登录抓取阶段报错，不影响离线读取
    import requests
except ImportError:  # pragma: no cover - requirements 中已声明
    requests = None  # type: ignore[assignment]

try:
    from .logger import logger
except ImportError:  # 以单文件方式加载（离线单测）时回退到标准 logging
    import logging

    logger = logging.getLogger("ip2free")


API_BASE = "https://api.ip2free.com"
WEB_BASE = "https://www.ip2free.com"
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULT_STATE_DIR = ".ip2free"
CONFIG_SECTION = "录制设置"
UA = os.getenv(
    "UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
)

#: 代理挑选方式：随机（默认，避免所有线程挤同一条） / 最快（固定用延迟最低的一条）
PICK_MODE_RANDOM = "随机"
PICK_MODE_FASTEST = "最快"
PICK_MODES = (PICK_MODE_RANDOM, PICK_MODE_FASTEST)

#: config.ini 中与 ip2free 相关的配置项及其默认值
CONFIG_KEYS: dict[str, str] = {
    "enabled": "是否使用ip2free动态socks5代理(是/否)",
    "email": "ip2free账号",
    "password": "ip2free密码",
    "countries": "ip2free代理国家代码",
    "max_pick": "ip2free最多挑选代理数",
    "max_candidates": "ip2free最多测速数量",
    "max_workers": "ip2free测速并发数",
    "probe_timeout": "ip2free测速超时(秒)",
    "refresh_minutes": "ip2free代理刷新间隔(分钟)",
    "test_url": "ip2free测速地址",
    "pick_mode": "ip2free代理选择方式",
    "recheck_minutes": "ip2free代理复检间隔(分钟)",
}

#: config.ini 缺失这些项时的默认值（会被 main.read_config_value 自动补写进配置文件）
CONFIG_DEFAULTS: dict[str, str] = {
    "enabled": "否",
    "email": "",
    "password": "",
    "countries": "",
    "max_pick": "5",
    "max_candidates": "40",
    "max_workers": "12",
    "probe_timeout": "8",
    "refresh_minutes": "60",
    "test_url": DEFAULT_TEST_URL,
    "pick_mode": PICK_MODE_RANDOM,
    "recheck_minutes": "5",
}

_TRUE_VALUES = {"是", "yes", "y", "true", "1", "on", "enable", "enabled"}
_FALSE_VALUES = {"否", "no", "n", "false", "0", "off", "disable", "disabled"}


class Ip2FreeError(RuntimeError):
    """ip2free 接口或代理流程异常。"""


# ---------------------------------------------------------------- 数据模型


@dataclass(frozen=True)
class ProxyEntry:
    """一条可用的 SOCKS5 代理。"""

    ip: str
    port: int
    username: str = ""
    password: str = ""
    protocol: str = "socks5"
    country: str = ""
    city: str = ""
    latency_ms: int = 0
    last_checked_at: str = ""

    def __post_init__(self) -> None:
        if not self.ip or not self.port:
            raise ValueError("代理 ip / port 不能为空")
        if not 0 < int(self.port) <= 65535:
            raise ValueError("代理端口必须在 1-65535 之间")

    # ---------------- 序列化

    @property
    def key(self) -> str:
        return "{0}:{1}".format(self.ip, self.port)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyEntry":
        return cls(
            ip=str(data.get("ip") or "").strip(),
            port=int(data.get("port") or 0),
            username=str(data.get("username") or ""),
            password=str(data.get("password") or ""),
            protocol=str(data.get("protocol") or "socks5").lower(),
            country=str(data.get("country") or ""),
            city=str(data.get("city") or ""),
            latency_ms=int(data.get("latency_ms") or 0),
            last_checked_at=str(data.get("last_checked_at") or ""),
        )

    # ---------------- 展示 / 连接串

    @property
    def url(self) -> str:
        """httpx 可用的 socks5h 连接串（远端解析域名）。"""
        auth = ""
        if self.username:
            auth = "{0}:{1}@".format(quote(self.username, safe=""), quote(self.password, safe=""))
        return "socks5h://{0}{1}:{2}".format(auth, self.ip, self.port)

    @property
    def has_auth(self) -> bool:
        return bool(self.username)

    def masked(self) -> str:
        return "{0}:{1}".format(self.ip, self.port)

    def __str__(self) -> str:  # pragma: no cover - 仅用于日志展示
        return self.masked()


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    latency_ms: int = 0
    detail: str = ""


@dataclass
class Ip2FreeSettings:
    """ip2free 代理池配置（从 config.ini / 环境变量解析而来）。"""

    enabled: bool = False
    email: str = ""
    password: str = ""
    countries: tuple[str, ...] = ()
    max_pick: int = 5
    max_candidates: int = 40
    max_workers: int = 12
    probe_timeout: float = 8.0
    refresh_minutes: int = 60
    test_url: str = DEFAULT_TEST_URL
    page_size: int = 50
    pick_mode: str = PICK_MODE_RANDOM
    recheck_minutes: int = 5

    @property
    def has_credentials(self) -> bool:
        return bool(self.email and self.password)

    def signature(self) -> tuple:
        """配置指纹，用于判断是否需要重建代理池。"""
        return (
            self.email,
            self.password,
            self.countries,
            self.max_pick,
            self.max_candidates,
            self.max_workers,
            self.probe_timeout,
            self.test_url,
            self.pick_mode,
        )

    @classmethod
    def from_reader(
        cls,
        reader: Callable[[str, str, str], str],
        environ: Optional[dict[str, str]] = None,
    ) -> "Ip2FreeSettings":
        """从 config.ini 读取配置；``reader(section, option, default) -> str``。"""
        env = os.environ if environ is None else environ

        def raw(name: str) -> str:
            option = CONFIG_KEYS[name]
            default = CONFIG_DEFAULTS.get(name, "")
            try:
                value = reader(CONFIG_SECTION, option, default)
            except Exception:  # 配置读取异常时退回默认值，不影响主流程
                value = default
            if value is None:
                value = ""
            if isinstance(value, bool):
                return "是" if value else "否"
            return str(value).strip()

        enabled = _to_bool(raw("enabled"), False)
        email = (env.get("IP2FREE_EMAIL") or raw("email")).strip()
        password = (env.get("IP2FREE_PASSWORD") or raw("password")).strip()
        countries = tuple(
            code.strip().upper()
            for code in raw("countries").replace("，", ",").split(",")
            if code.strip()
        )
        pick_mode_raw = raw("pick_mode").lower()
        if pick_mode_raw in ("最快", "fastest", "fast", "latency"):
            pick_mode = PICK_MODE_FASTEST
        elif pick_mode_raw in ("随机", "random", "rand"):
            pick_mode = PICK_MODE_RANDOM
        else:
            pick_mode = PICK_MODE_RANDOM
        return cls(
            enabled=enabled,
            email=email,
            password=password,
            countries=countries,
            max_pick=_to_int(raw("max_pick"), 5, 1, 50),
            max_candidates=_to_int(raw("max_candidates"), 40, 1, 200),
            max_workers=_to_int(raw("max_workers"), 12, 1, 64),
            probe_timeout=_to_float(raw("probe_timeout"), 8.0, 1.0, 60.0),
            refresh_minutes=_to_int(raw("refresh_minutes"), 60, 1, 1440),
            test_url=raw("test_url") or DEFAULT_TEST_URL,
            pick_mode=pick_mode,
            recheck_minutes=_to_int(raw("recheck_minutes"), 5, 1, 720),
        )


# ---------------------------------------------------------------- 小工具


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    return default


def _to_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def _to_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def normalize_proxies(
    items: Iterable[dict[str, Any]],
    countries: Sequence[str] = (),
    protocol: str = "socks5",
) -> list[ProxyEntry]:
    """把 ip2free 接口返回的原始字典归一化为 ``ProxyEntry`` 列表（去重、过滤协议/国家）。"""
    wanted = {code.upper() for code in countries if code}
    seen: set[str] = set()
    entries: list[ProxyEntry] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        proto = str(item.get("protocol") or "socks5").lower()
        if protocol and proto != protocol:
            continue
        country = str(item.get("country_code") or "").upper()
        if wanted and country not in wanted:
            continue
        try:
            entry = ProxyEntry(
                ip=str(item.get("ip") or "").strip(),
                port=int(str(item.get("port") or 0).strip()),
                username=str(item.get("username") or ""),
                password=str(item.get("password") or ""),
                protocol=proto,
                country=country,
                city=str(item.get("city") or ""),
                last_checked_at=str(item.get("last_checked_at") or ""),
            )
        except (TypeError, ValueError):
            continue
        if not _is_ip(entry.ip):
            continue
        if entry.key in seen:
            continue
        seen.add(entry.key)
        entries.append(entry)
    return entries


def _normalize_proxy_key(proxy: "ProxyEntry | str") -> str:
    """把代理标识统一归一成 ``ip:port``。

    程序里同时存在三种写法：``ProxyEntry``、``ip:port``、以及
    ``socks5h://user:pass@ip:port``（main.py 传给 mark_failed / exclude 的就是连接串）。
    不归一化的话失效代理永远匹配不上、也就永远不会被舍弃。
    """
    if isinstance(proxy, ProxyEntry):
        return proxy.key
    text = str(proxy or "").strip()
    if not text:
        return ""
    if "://" in text:
        try:
            parts = urlsplit(text)
            hostname = parts.hostname or ""
            port = parts.port
            if hostname and port:
                return "{0}:{1}".format(hostname, port)
        except ValueError:
            pass
        return text
    # 裸的 user:pass@ip:port
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    return text


def _credentials_changed(old: ProxyEntry, new: ProxyEntry) -> bool:
    """同一 ip:port 上，接口返回的账号密码是否与当前生效的凭证不同。"""
    return (old.username, old.password) != (new.username, new.password)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def parse_proxychains_line(line: str) -> Optional[ProxyEntry]:
    """解析一行 proxychains 代理配置：``socks5 host port [user pass]``。"""
    text = (line or "").strip()
    if not text or text.startswith("#") or text.startswith("["):
        return None
    parts = text.split()
    if len(parts) < 3:
        return None
    proto = parts[0].lower()
    if proto not in ("socks5", "socks5h", "socks4", "http", "https"):
        return None
    host, port = parts[1], parts[2]
    username = parts[3] if len(parts) > 3 else ""
    password = parts[4] if len(parts) > 4 else ""
    try:
        return ProxyEntry(
            ip=host,
            port=int(port),
            username=unquote(username),
            password=unquote(password),
            protocol="socks5" if proto.startswith("socks5") else proto,
        )
    except (TypeError, ValueError):
        return None


def read_proxychains_conf(path: str | Path) -> list[ProxyEntry]:
    """读取 proxychains.conf（兼容 claim_daily_proxy.py 的输出），返回 socks5 代理列表。"""
    file_path = Path(path)
    if not file_path.is_file():
        return []
    entries: list[ProxyEntry] = []
    seen: set[str] = set()
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    for line in content.splitlines():
        entry = parse_proxychains_line(line)
        if entry is None or entry.protocol != "socks5" or not _is_ip(entry.ip):
            continue
        if entry.key in seen:
            continue
        seen.add(entry.key)
        entries.append(entry)
    return entries


def write_proxychains_conf(
    path: str | Path,
    entries: Sequence[ProxyEntry],
    title: str = "ip2free 免费 socks5 代理",
) -> Path:
    """把代理列表写成 proxychains.conf，返回写入路径。"""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[ProxyList]"]
    if entries:
        lines.append("# ===== {0} {1} 条（按延迟升序，{2}）=====".format(
            title, len(entries), time.strftime("%Y-%m-%d %H:%M:%S")
        ))
    for entry in entries:
        if entry.username:
            lines.append("socks5 {0} {1} {2} {3}".format(
                entry.ip, entry.port,
                quote(entry.username, safe=""), quote(entry.password, safe=""),
            ))
        else:
            lines.append("socks5 {0} {1}".format(entry.ip, entry.port))
    file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return file_path


# ---------------------------------------------------------------- 接口客户端


class Ip2FreeClient:
    """ip2free 账号 API 客户端：登录 + 免费代理列表抓取。"""

    def __init__(
        self,
        email: str,
        password: str,
        *,
        timeout: float = 20.0,
        token_path: str | Path | None = None,
        session: Any = None,
        api_base: str = API_BASE,
        web_base: str = WEB_BASE,
        page_size: int = 50,
    ) -> None:
        self.email = email
        self.password = password
        self.timeout = timeout
        self.token_path = Path(token_path) if token_path else None
        self.api_base = api_base.rstrip("/")
        self.web_base = web_base.rstrip("/")
        self.page_size = page_size
        self._session = session
        self._token = ""
        self._lock = threading.Lock()

    # ---------------- session / token

    def _session_obj(self) -> Any:
        if self._session is not None:
            return self._session
        if requests is None:  # pragma: no cover - 依赖缺失
            raise Ip2FreeError("缺少 requests 依赖，无法调用 ip2free 接口")
        session = requests.Session()
        session.headers.update(self._headers())
        self._session = session
        return session

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": UA,
            "Origin": self.web_base,
            "Referer": self.web_base + "/",
            "webname": "IP2FREE",
            "lang": "cn",
            "content-type": "text/plain;charset=UTF-8",
        }
        if self._token:
            headers["x-token"] = self._token
        return headers

    def _load_token(self) -> str:
        if self.token_path is None or not self.token_path.is_file():
            return ""
        try:
            return self.token_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def _save_token(self, token: str) -> None:
        if self.token_path is None or not token:
            return
        try:
            self.token_path.parent.mkdir(parents=True, exist_ok=True)
            self.token_path.write_text(token, encoding="utf-8")
        except OSError:
            pass

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        session = self._session_obj()
        session.headers.update(self._headers())
        try:
            response = session.post(self.api_base + path, json=payload, timeout=self.timeout)
        except Exception as exc:
            raise Ip2FreeError("请求 {0} 失败：{1}: {2}".format(path, type(exc).__name__, exc)) from exc
        if response.status_code != 200:
            raise Ip2FreeError("请求 {0} 返回 HTTP {1}".format(path, response.status_code))
        try:
            data = response.json()
        except ValueError as exc:
            raise Ip2FreeError("请求 {0} 返回内容不是 JSON".format(path)) from exc
        if not isinstance(data, dict):
            raise Ip2FreeError("请求 {0} 返回结构异常".format(path))
        return data

    def login(self, force: bool = False) -> bool:
        """登录并缓存 token；force=True 时忽略本地缓存。"""
        with self._lock:
            if self._token and not force:
                return True
            if not self.has_credentials:
                raise Ip2FreeError("未配置 ip2free 账号或密码")

            if not force:
                cached = self._load_token()
                if cached:
                    self._token = cached
                    return True

            payload = self._post("/api/account/login?", {"email": self.email, "password": self.password})
            if payload.get("code") != 0:
                self._token = ""
                raise Ip2FreeError("ip2free 登录失败：{0}".format(payload.get("msg") or payload.get("code")))
            token = str((payload.get("data") or {}).get("token") or "")
            if not token:
                raise Ip2FreeError("ip2free 登录返回缺少 token")
            self._token = token
            self._save_token(token)
            logger.debug("ip2free 登录成功，token 已缓存")
            return True

    @property
    def has_credentials(self) -> bool:
        return bool(self.email and self.password)

    # ---------------- 免费代理列表

    def _api(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """带 token 失效自动重登的接口调用，返回 data 字段。"""
        if not self._token:
            self.login()
        for attempt in range(2):
            result = self._post(path, payload)
            if result.get("code") == 0:
                data = result.get("data")
                return data if isinstance(data, dict) else {}
            message = str(result.get("msg") or "")
            lowered = message.lower()
            token_words = ("token", "login", "auth", "expire", "登录", "失效", "过期")
            expired = attempt == 0 and (
                result.get("code") in (-1, 401, 403)
                or any(word in lowered for word in token_words)
            )
            if expired:
                logger.debug("ip2free token 失效，重新登录后重试")
                self.login(force=True)
                continue
            raise Ip2FreeError("{0} 返回错误：{1}".format(path, message or result.get("code")))
        raise Ip2FreeError("{0} 调用失败".format(path))

    def fetch_free_proxies(self, countries: Sequence[str] = ()) -> list[ProxyEntry]:
        """翻页抓取全部免费代理并过滤为 socks5。"""
        raw: list[dict[str, Any]] = []
        page = 1
        total_pages = 1
        while page <= total_pages and page <= 100:
            data = self._api("/api/ip/freeList", {"page": page, "page_size": self.page_size})
            items = data.get("free_ip_list") or []
            if not isinstance(items, list) or not items:
                break
            raw.extend(item for item in items if isinstance(item, dict))
            page_info = data.get("page") or {}
            try:
                total_pages = int(page_info.get("totalPage") or page)
            except (TypeError, ValueError):
                total_pages = page
            page += 1
        return normalize_proxies(raw, countries=countries)


# ---------------------------------------------------------------- 测速挑选

def _default_client_factory(proxy_url: str, timeout: float) -> httpx.Client:
    return httpx.Client(
        proxy=proxy_url,
        timeout=timeout,
        verify=False,
        http2=False,
        follow_redirects=False,
        trust_env=False,
    )


def probe_proxy(
    proxy: ProxyEntry | str,
    test_url: str = DEFAULT_TEST_URL,
    timeout: float = 8.0,
    client_factory: Optional[Callable[[str, float], Any]] = None,
) -> ProbeResult:
    """实测一条 socks5 代理的连通性与延迟。"""
    url = proxy.url if isinstance(proxy, ProxyEntry) else str(proxy)
    factory = client_factory or _default_client_factory
    started = time.perf_counter()
    try:
        with factory(url, timeout) as client:
            response = client.get(test_url)
        latency = int((time.perf_counter() - started) * 1000)
        ok = response.status_code < 500
        return ProbeResult(ok=ok, latency_ms=latency, detail="HTTP {0}".format(response.status_code))
    except Exception as exc:
        latency = int((time.perf_counter() - started) * 1000)
        return ProbeResult(ok=False, latency_ms=latency, detail="{0}: {1}".format(type(exc).__name__, exc))


def select_working(
    proxies: Sequence[ProxyEntry],
    *,
    max_pick: int = 5,
    max_workers: int = 12,
    timeout: float = 8.0,
    test_url: str = DEFAULT_TEST_URL,
    max_candidates: int = 40,
    probe: Optional[Callable[..., ProbeResult]] = None,
    pick_mode: str = PICK_MODE_RANDOM,
    rng: Any = None,
) -> list[ProxyEntry]:
    """并发测速，只保留实测可用的代理，并按 ``pick_mode`` 从可用集合里挑选。

    * ``PICK_MODE_RANDOM``（默认）：在全部可用代理里随机取 ``max_pick`` 条，
      避免每次都固定那几条、也避免多个线程挤在同一条代理上；
    * ``PICK_MODE_FASTEST``：按实测延迟取最快的 ``max_pick`` 条。

    返回结果按延迟升序排列，便于日志阅读。
    """
    candidates = list(proxies)[: max(0, max_candidates)]
    if not candidates or max_pick <= 0:
        return []
    probe_func = probe or probe_proxy
    workers = max(1, min(max_workers, len(candidates)))
    working: list[ProxyEntry] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ip2free-probe") as executor:
        futures = {
            executor.submit(probe_func, entry, test_url, timeout): entry for entry in candidates
        }
        for future in as_completed(futures):
            entry = futures[future]
            try:
                result = future.result()
            except Exception:
                continue
            if result.ok:
                working.append(replace(entry, latency_ms=result.latency_ms))
    working.sort(key=lambda item: (item.latency_ms, item.ip))
    if pick_mode == PICK_MODE_FASTEST or len(working) <= max_pick:
        return working[:max_pick]
    random_source = rng or random
    chosen = random_source.sample(working, max_pick)
    chosen.sort(key=lambda item: (item.latency_ms, item.ip))
    return chosen


# ---------------------------------------------------------------- 代理池


class Ip2FreeProxyPool:
    """ip2free 免费 socks5 代理池：缓存 / 刷新 / 轮换。"""

    def __init__(
        self,
        settings: Ip2FreeSettings,
        *,
        state_dir: str | Path | None = None,
        offline_conf: str | Path | None = None,
        client_factory: Optional[Callable[..., Ip2FreeClient]] = None,
        probe: Optional[Callable[..., ProbeResult]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.state_dir = Path(state_dir or DEFAULT_STATE_DIR)
        self.offline_conf = Path(offline_conf) if offline_conf else None
        self._client_factory = client_factory or (lambda **kwargs: Ip2FreeClient(**kwargs))
        self._probe = probe
        self._clock = clock
        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._refresh_thread: Optional[threading.Thread] = None
        self._proxies: list[ProxyEntry] = []
        self._index = 0
        self._updated_at = 0.0
        self.last_error = ""
        self._client: Optional[Ip2FreeClient] = None
        self._last_pick: Optional[ProxyEntry] = None
        self._checked_at = 0.0
        self._checked_keys: set[str] = set()
        self._rechecking = False
        self._background_threads: list[threading.Thread] = []

    # ---------------- 路径

    @property
    def cache_path(self) -> Path:
        return self.state_dir / "proxy_cache.json"

    @property
    def token_path(self) -> Path:
        return self.state_dir / "token.txt"

    @property
    def proxychains_path(self) -> Path:
        return self.state_dir / "proxychains.conf"

    # ---------------- 状态

    @property
    def proxies(self) -> list[ProxyEntry]:
        with self._lock:
            return list(self._proxies)

    @property
    def current(self) -> Optional[ProxyEntry]:
        """最近一次挑中的代理（仅用于展示 / 桥接兜底）。"""
        with self._lock:
            if self._last_pick is not None and self._last_pick.key in self._checked_keys:
                return self._last_pick
            if not self._proxies:
                return None
            return self._proxies[min(self._index, len(self._proxies) - 1)]

    @property
    def updated_at(self) -> float:
        return self._updated_at

    @property
    def refreshing(self) -> bool:
        return self._refresh_thread is not None and self._refresh_thread.is_alive()

    def is_stale(self) -> bool:
        with self._lock:
            if not self._proxies:
                return True
            return (self._clock() - self._updated_at) >= self.settings.refresh_minutes * 60

    def needs_recheck(self) -> bool:
        """代理池是否到了复检时间（ip2free 的免费代理随时可能失效）。"""
        with self._lock:
            if not self._proxies:
                return False
            return (self._clock() - self._checked_at) >= self.settings.recheck_minutes * 60

    def status_line(self) -> str:
        entry = self.current
        if entry is None:
            return "ip2free 代理池为空"
        return "ip2free 可用代理 {0} 条，本次使用 {1}（{2}ms）".format(
            len(self.proxies), entry.masked(), entry.latency_ms
        )

    # ---------------- 客户端

    def _get_client(self) -> Ip2FreeClient:
        if self._client is None:
            self._client = self._client_factory(
                email=self.settings.email,
                password=self.settings.password,
                timeout=max(10.0, self.settings.probe_timeout),
                token_path=self.token_path,
                page_size=self.settings.page_size,
            )
        return self._client

    # ---------------- 缓存

    def _load_cache(self) -> None:
        path = self.cache_path
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        entries: list[ProxyEntry] = []
        for item in payload.get("proxies") or []:
            try:
                entries.append(ProxyEntry.from_dict(item))
            except (TypeError, ValueError):
                continue
        if not entries:
            return
        updated_at = float(payload.get("updated_at") or 0)
        checked_at = float(payload.get("checked_at") or updated_at)
        with self._lock:
            self._proxies = entries
            self._updated_at = updated_at
            self._checked_at = checked_at
            self._checked_keys = {entry.key for entry in entries}
            self._index = 0
        logger.debug("ip2free 读取本地代理缓存 {0} 条：{1}".format(len(entries), path))

    def _save_cache(self, last_pick: Optional[ProxyEntry] = None) -> None:
        with self._lock:
            payload = {
                "updated_at": self._updated_at,
                "checked_at": self._checked_at,
                "updated_text": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._updated_at or self._clock())),
                "pick_mode": self.settings.pick_mode,
                "proxies": [entry.to_dict() for entry in self._proxies],
                "last_pick": last_pick.to_dict() if last_pick is not None else None,
            }
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.warning("写入 ip2free 代理缓存失败：{0}".format(exc))

    def _write_proxychains(self, last_pick: Optional[ProxyEntry] = None) -> None:
        entries = self.proxies
        if last_pick is not None:
            # 置顶本次使用的代理，方便人工核对
            entries = [last_pick] + [entry for entry in entries if entry.key != last_pick.key]
        try:
            write_proxychains_conf(self.proxychains_path, entries)
        except OSError as exc:
            logger.debug("写入 proxychains.conf 失败：{0}".format(exc))

    def _commit(self, entries: list[ProxyEntry], checked_at: float) -> None:
        with self._lock:
            self._proxies = list(entries)
            self._checked_at = checked_at
            self._checked_keys = {entry.key for entry in entries}
            self._index = 0

    # ---------------- 刷新

    def _probe_many(self, entries: Sequence[ProxyEntry], label: str) -> list[ProxyEntry]:
        """并发实测一组代理，返回仍可用（带实测延迟）的条目。"""
        if not entries:
            return []
        probe_func = self._probe or probe_proxy
        workers = max(1, min(self.settings.max_workers, len(entries)))
        alive: list[ProxyEntry] = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=label) as executor:
            futures = {
                executor.submit(
                    probe_func, entry, self.settings.test_url, self.settings.probe_timeout
                ): entry
                for entry in entries
            }
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    result = future.result()
                except Exception:
                    continue
                if result.ok:
                    alive.append(replace(entry, latency_ms=result.latency_ms))
        return alive

    def _merge_with_sticky_credentials(
        self, fetched: list[ProxyEntry]
    ) -> tuple[list[ProxyEntry], int, int]:
        """刷新时保留「实测仍可用」的旧凭证，只在必要时接纳接口的新凭证。

        ip2free 会轮换同一 ``ip:port`` 上的账号密码，而新凭证常常还没生效、
        旧凭证却仍然可用。直接拿接口列表覆盖会把能用的旧凭证丢掉。策略：

        1. 对每个已缓存节点，用**它当前那套凭证**实测；仍可用则原样保留（不采纳新凭证）；
        2. 缓存节点实测失败的，才拿接口里同节点的新凭证再测一次，能通才替换；
        3. 接口里全新、缓存里没有的节点，按正常流程测速后加入；
        4. 接口已下线的旧节点，只要复检仍可用就继续保留。

        Returns:
            (合并后的可用代理列表, 保留旧凭证条数, 采纳新凭证条数)
        """
        with self._lock:
            cached = list(self._proxies)
        fetched_by_key: dict[str, ProxyEntry] = {}
        for entry in fetched:
            # 接口同一节点若返回多条，保留 last_checked_at 最新的那条
            existing = fetched_by_key.get(entry.key)
            if existing is None or entry.last_checked_at > existing.last_checked_at:
                fetched_by_key[entry.key] = entry

        # 1) 缓存里的旧凭证全部实测一遍（含接口已下线的节点，给它们继续存活的机会）
        still_alive = self._probe_many(cached, "ip2free-oldcred")
        alive_by_key = {entry.key: entry for entry in still_alive}

        kept = 0
        accepted_new = 0
        merged: dict[str, ProxyEntry] = dict(alive_by_key)

        # 2) 旧凭证失效的同名节点 + 3) 接口里的全新节点，才测试新凭证
        fresh_to_probe: list[ProxyEntry] = []
        for key, new_entry in fetched_by_key.items():
            if key in merged:
                # 节点已有可用的旧凭证 -> 不采纳新凭证
                if _credentials_changed(merged[key], new_entry):
                    kept += 1
                continue
            fresh_to_probe.append(new_entry)

        # 新节点按「最近校验过」优先，避免把测速次数浪费在陈旧的条目上
        fresh_to_probe.sort(key=lambda item: item.last_checked_at, reverse=True)
        fresh_to_probe = fresh_to_probe[: max(0, self.settings.max_candidates)]
        for entry in self._probe_many(fresh_to_probe, "ip2free-newcred"):
            merged[entry.key] = entry
            accepted_new += 1

        # 按延迟升序，并限制池子规模；保留下来的旧凭证同样参与后续随机/最快挑选
        result = sorted(merged.values(), key=lambda item: (item.latency_ms, item.ip))
        return result[: max(1, self.settings.max_pick)], kept, accepted_new

    def refresh(self) -> list[ProxyEntry]:
        """抓取 + 测速 + 落盘，返回本轮测出的可用代理（空表示失败，旧池保留）。

        凭证粘性：已缓存且实测仍可用的旧凭证会继续生效，不会被接口返回的新凭证覆盖；
        只有旧凭证实测失效、或接口出现全新节点时，才会实测并接纳新凭证。
        """
        if not self._refresh_lock.acquire(blocking=False):
            return self.proxies
        self.last_error = ""
        cached_count = 0
        merged: list[ProxyEntry] = []
        source = "ip2free"
        kept = accepted_new = 0
        try:
            try:
                fetched, source = self._refresh_once()
                # 即使接口没抓到任何东西（挂了 / 列表为空），也走同一套合并逻辑：
                # 它会实测缓存里的旧凭证，仍可用的继续保留，不可用的才舍弃。
                merged, kept, accepted_new = self._merge_with_sticky_credentials(fetched)
                with self._lock:
                    cached_count = len(self._proxies)
            except Exception as exc:
                self.last_error = "{0}: {1}".format(type(exc).__name__, exc)
                logger.warning("ip2free 刷新异常：{0}".format(self.last_error))
                return self.proxies

            if merged:
                now = self._clock()
                self._commit(merged, now)
                with self._lock:
                    self._updated_at = now
                self._save_cache()
                self._write_proxychains()
                logger.info(
                    "ip2free 测速完成：{0} 条可用（来源：{1}，保留旧凭证 {2} 条，"
                    "采纳新凭证 {3} 条，最快 {4}ms）".format(
                        len(merged), source, kept, accepted_new, merged[0].latency_ms
                    )
                )
            elif cached_count:
                # 旧凭证也全部实测失效 -> 明确舍弃，避免死凭证残留在池里被 pick 选中
                logger.warning("ip2free 缓存里的旧凭证已全部失效，清空代理池等待下次重新抓取")
                now = self._clock()
                self._commit([], now)
                self._save_cache()
                self._write_proxychains()
            else:
                suffix = "：" + self.last_error if self.last_error else ""
                logger.warning("ip2free 本轮未测出可用 socks5 代理{0}".format(suffix))
            return merged
        finally:
            self._refresh_lock.release()

    def recheck(self) -> list[ProxyEntry]:
        """复检当前代理池：每条都带「它自己那套凭证」实测，剔除失效的，保留仍可用的。"""
        snapshot = self.proxies
        if not snapshot:
            return []
        alive = self._probe_many(snapshot, "ip2free-recheck")
        if alive:
            now = self._clock()
            self._commit(alive, now)
            self._save_cache()
            self._write_proxychains()
            dropped = len(snapshot) - len(alive)
            logger.info(
                "ip2free 复检完成：{0} 条仍然可用{1}".format(
                    len(alive), "，剔除 {0} 条失效代理".format(dropped) if dropped else ""
                )
            )
        else:
            logger.warning("ip2free 复检：代理池内所有代理均已失效，稍后重新抓取")
            now = self._clock()
            self._commit([], now)
        return alive

    def _refresh_once(self) -> tuple[list[ProxyEntry], str]:
        """抓取接口候选列表（不做测速/截断），交给 refresh 做凭证粘性合并。"""
        raw: list[ProxyEntry] = []
        source = "ip2free"
        self.last_error = ""
        if self.settings.has_credentials:
            try:
                raw = self._get_client().fetch_free_proxies(self.settings.countries)
            except Exception as exc:
                self.last_error = "{0}: {1}".format(type(exc).__name__, exc)
                logger.warning("ip2free 代理列表获取失败：{0}".format(self.last_error))
        else:
            self.last_error = "未配置 ip2free 账号或密码"
            logger.warning("ip2free 未配置账号密码，改从本地 proxychains.conf 读取代理")

        if not raw and self.offline_conf is not None:
            raw = read_proxychains_conf(self.offline_conf)
            if raw:
                source = "本地 proxychains.conf"
                logger.info("从 {0} 读取到 {1} 条 socks5 代理".format(self.offline_conf, len(raw)))

        if not raw:
            return [], source

        # 最近被 ip2free 校验过的优先测速，避免浪费探测次数。
        # 这里不做 select_working：新凭证往往不可用，若先按新凭证筛一遍，
        # 那些「旧凭证仍可用」的节点可能被提前淘汰，凭证粘性就无从谈起。
        raw.sort(key=lambda item: item.last_checked_at, reverse=True)
        return raw, source

    def pick(self, exclude: Optional[Iterable[str]] = None) -> Optional[ProxyEntry]:
        """从「实测可用」的代理里挑选一条用作本次连接。

        * 刷新 / 复检都在后台进行，不会阻塞正在录制的线程；
        * 默认在可用池里随机挑，``ip2free代理选择方式 = 最快`` 时固定取延迟最低的一条；
        * ``exclude`` 里的 key（通常是刚失败的代理）会被排除，避免立刻又走回同一条；
        * 池子为空时退化为同步抓取一次（此时本来也没法录制）。
        """
        self.ensure_fresh(background=True)
        self._maybe_recheck_async()
        banned = {_normalize_proxy_key(item) for item in (exclude or ())}
        banned.discard("")
        entry = self._choose(banned)
        if entry is None:
            # 池子空（首次启动或代理全部失效）：同步抓一次，别让录制线程拿不到代理
            self.refresh()
            entry = self._choose(banned)
        return entry

    def _choose(self, banned: set[str]) -> Optional[ProxyEntry]:
        with self._lock:
            candidates = [entry for entry in self._proxies if entry.key not in banned]
            if not candidates:
                candidates = list(self._proxies)
            if not candidates:
                return None
            # 池里还有别的代理时，尽量不和上一次重复，避免多线程都挤在同一条上
            # （「最快」模式下不做去重，否则就不是「固定用延迟最低的那条」了）
            if self.settings.pick_mode != PICK_MODE_FASTEST and len(candidates) > 1 \
                    and self._last_pick is not None:
                without_last = [item for item in candidates if item.key != self._last_pick.key]
                if without_last:
                    candidates = without_last
            if self.settings.pick_mode == PICK_MODE_FASTEST:
                entry = candidates[0]
            else:
                entry = random.choice(candidates)
            self._last_pick = entry
            self._index = self._proxies.index(entry)
            return entry

    def _maybe_recheck_async(self) -> None:
        """到了复检时间就在后台复检一遍，剔除已被墙掉的代理。"""
        if not self.needs_recheck():
            return
        with self._lock:
            if self._rechecking:
                return
            self._rechecking = True
        thread = threading.Thread(target=self._safe_recheck, name="ip2free-recheck", daemon=True)
        self._track(thread)
        thread.start()

    def _safe_recheck(self) -> None:
        try:
            self.recheck()
        except Exception as exc:  # pragma: no cover - recheck 内部已兜底
            logger.warning("ip2free 后台复检异常：{0}: {1}".format(type(exc).__name__, exc))
        finally:
            with self._lock:
                self._rechecking = False

    def pick_fast(self, exclude: Optional[Iterable[str]] = None) -> Optional[ProxyEntry]:
        """只从「当前已验证可用」的池子里挑一条，不做复检/刷新（供本地桥接每连接调用）。"""
        banned = {_normalize_proxy_key(item) for item in (exclude or ())}
        banned.discard("")
        return self._choose(banned) or self._last_pick

    def bootstrap(self) -> Optional[ProxyEntry]:
        """启动时调用：优先用未过期缓存，否则（或缓存为空时）刷新一次，然后随机挑一条。"""
        self._load_cache()
        if self.proxies and not self.is_stale():
            logger.debug("ip2free 使用本地缓存代理池：{0} 条可用".format(len(self.proxies)))
        else:
            self.refresh()
        # 缓存可能过期很久，首次使用前再复检一次，避免直接拿失效代理开录
        return self.pick()

    def wait_idle(self, timeout: float = 10.0) -> bool:
        """等待后台刷新/复检线程结束（供测试与退出前收尾使用）。"""
        deadline = time.time() + timeout
        for thread in list(self._background_threads):
            remaining = deadline - time.time()
            if remaining <= 0 or not thread.is_alive():
                continue
            thread.join(timeout=remaining)
        self._background_threads = [item for item in self._background_threads if item.is_alive()]
        return not self._background_threads

    def _track(self, thread: threading.Thread) -> None:
        with self._lock:
            self._background_threads = [
                item for item in self._background_threads if item.is_alive()
            ] + [thread]

    def ensure_fresh(self, background: bool = True) -> bool:
        """缓存过期时触发抓取刷新；background=True 时在后台线程执行，不阻塞录制主循环。"""
        if not self.is_stale():
            return False
        if background:
            if self.refreshing:
                return False
            thread = threading.Thread(
                target=self._safe_refresh, name="ip2free-refresh", daemon=True
            )
            with self._lock:
                self._refresh_thread = thread
            self._track(thread)
            thread.start()
            return True
        self.refresh()
        return True

    def _safe_refresh(self) -> None:
        try:
            self.refresh()
        except Exception as exc:  # pragma: no cover - refresh 内部已兜底
            logger.warning("ip2free 后台刷新异常：{0}: {1}".format(type(exc).__name__, exc))

    # ---------------- 轮换

    def rotate(self) -> Optional[ProxyEntry]:
        """换一条代理（排除刚用过的那条）；没有别的可用代理时返回当前条目。"""
        current = self.current
        exclude = [current.key] if current is not None else []
        picked = self.pick(exclude=exclude)
        return picked if picked is not None else current

    def mark_failed(self, proxy: ProxyEntry | str) -> None:
        """标记某条代理失效：从可用集合中移除，下次 pick 不会再选中它。

        只有实测确认不可用才调用本方法；保留下来的旧凭证会一直用到这里为止。
        参数可以是 ProxyEntry、``ip:port`` 或完整的 socks5h 连接串。
        """
        key = _normalize_proxy_key(proxy)
        if not key:
            return
        with self._lock:
            remaining = [entry for entry in self._proxies if entry.key != key]
            self._proxies = remaining
            self._checked_keys.discard(key)
            if self._last_pick is not None and self._last_pick.key == key:
                self._last_pick = None
            self._index = 0
            # 同步刷新缓存文件，避免重启后又把已失效的凭证读回来
            self._save_cache()
            self._write_proxychains()

    def close(self) -> None:
        self.wait_idle(timeout=5.0)
        with self._lock:
            self._proxies = []
            self._index = 0
            self._updated_at = 0.0
            self._checked_at = 0.0
            self._checked_keys = set()
            self._last_pick = None
        self._client = None


__all__ = [
    "CONFIG_DEFAULTS",
    "CONFIG_KEYS",
    "CONFIG_SECTION",
    "DEFAULT_TEST_URL",
    "PICK_MODES",
    "PICK_MODE_FASTEST",
    "PICK_MODE_RANDOM",
    "Ip2FreeClient",
    "Ip2FreeError",
    "Ip2FreeProxyPool",
    "Ip2FreeSettings",
    "ProbeResult",
    "ProxyEntry",
    "normalize_proxies",
    "parse_proxychains_line",
    "probe_proxy",
    "read_proxychains_conf",
    "select_working",
    "write_proxychains_conf",
]
