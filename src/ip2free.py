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
import re
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

#: 平台封禁探测：代理本身能出网，但目标平台按出口 IP 封禁时也要舍弃
DEFAULT_BLOCK_PROBES = "pandatv"
BLOCK_PROBE_PANDA = "pandatv"
BLOCK_PROBES = (BLOCK_PROBE_PANDA,)

#: 平台封禁判定关键词（结构化字段优先，文本兜底；对韩文/英文字样都覆盖）
PANDA_BLOCK_MARKERS = (
    '"code": "block"',
    '"code":"block"',
    "제재된 아이피",          # 该 IP 已被制裁
    "blocked ip",
    "banned ip",
)

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
    "block_probes": "ip2free平台封禁探测",
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
    "block_probes": DEFAULT_BLOCK_PROBES,
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
    #: 最近一次测速结果：True=能出网，False=测过但不通，None=还没测过（新加入的候选）
    healthy: Optional[bool] = None
    #: 最近一次测速时间（秒级时间戳），用于判断候选是否需要复测
    probed_at: float = 0.0

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
        healthy = data.get("healthy")
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
            healthy=None if healthy is None else bool(healthy),
            probed_at=float(data.get("probed_at") or 0),
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
    block_probes: tuple[str, ...] = (DEFAULT_BLOCK_PROBES,)

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
            self.block_probes,
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
            block_probes=_parse_block_probes(raw("block_probes")),
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


def _parse_block_probes(value: Any) -> tuple[str, ...]:
    """解析「平台封禁探测」配置：逗号分隔，支持 pandatv / 熊猫 / 空值关闭。"""
    text = str(value or "").strip()
    if not text:
        return ()
    aliases = {
        "pandatv": BLOCK_PROBE_PANDA,
        "panda": BLOCK_PROBE_PANDA,
        "熊猫": BLOCK_PROBE_PANDA,
        "熊猫tv": BLOCK_PROBE_PANDA,
    }
    probes: list[str] = []
    for item in text.replace("，", ",").split(","):
        key = item.strip().lower()
        if not key:
            continue
        mapped = aliases.get(key, key)
        if mapped in BLOCK_PROBES and mapped not in probes:
            probes.append(mapped)
    return tuple(probes)


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


@dataclass(frozen=True)
class BlockResult:
    """平台封禁探测结果。``blocked`` 只在**确认**被该平台封禁时为 True。"""

    blocked: bool
    platform: str = ""
    detail: str = ""


def probe_pandatv_block(
    proxy: "ProxyEntry | str",
    timeout: float = 10.0,
    client_factory: Optional[Callable[[str, float], Any]] = None,
) -> BlockResult:
    """探测该出口 IP 是否被 PandaTV 封禁。

    PandaTV 对封禁 IP 返回 HTTP 403 且响应体带 ``errorData.code = "block"``：

        {"result":false,"message":"제재된 아이피입니다...","errorData":{"code":"block"}}

    因此优先匹配结构化字段，文本关键词只作兜底。网络异常/超时一律**不判定为封禁**
    （避免把平台抖动误判成封禁，白白丢掉可用代理）。
    """
    url = proxy.url if isinstance(proxy, ProxyEntry) else str(proxy)
    factory = client_factory or _default_client_factory
    headers = {
        "origin": "https://www.pandalive.co.kr",
        "referer": "https://www.pandalive.co.kr/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
                      "Gecko/20100101 Firefox/124.0",
    }
    try:
        with factory(url, timeout) as client:
            response = client.post(
                "https://api.pandalive.co.kr/v1/live/play",
                headers=headers,
                data={"action": "watch", "userId": "probe", "password": "", "shareLinkType": ""},
            )
    except Exception as exc:
        return BlockResult(False, BLOCK_PROBE_PANDA, "{0}: {1}".format(type(exc).__name__, exc))

    body = (getattr(response, "text", "") or "").lower()
    code = getattr(response, "status_code", 0)
    blocked = False
    detail = "HTTP {0}".format(code)
    # 结构化判定优先：PandaTV 封禁时固定返回 errorData.code = "block"
    compact = re.sub(r"\s+", "", body)
    if '"errordata"' in compact and '"code":"block"' in compact:
        blocked = True
        detail = "HTTP {0} errorData.code=block".format(code)
    else:
        for marker in PANDA_BLOCK_MARKERS:
            if marker.lower() in body:
                blocked = True
                detail = "HTTP {0} 命中封禁关键字".format(code)
                break
    return BlockResult(blocked, BLOCK_PROBE_PANDA, detail)


#: 平台 -> 封禁探测函数
BLOCK_PROBE_FUNCS: dict[str, Callable[..., BlockResult]] = {
    BLOCK_PROBE_PANDA: probe_pandatv_block,
}


def probe_platform_blocks(
    proxy: "ProxyEntry | str",
    platforms: Sequence[str] = (),
    timeout: float = 10.0,
    probe_funcs: Optional[dict[str, Callable[..., BlockResult]]] = None,
) -> dict[str, BlockResult]:
    """对一条代理依次做各平台的封禁探测，返回 平台->结果。"""
    funcs = probe_funcs or BLOCK_PROBE_FUNCS
    results: dict[str, BlockResult] = {}
    for platform in platforms:
        func = funcs.get(platform)
        if func is None:
            continue
        try:
            results[platform] = func(proxy, timeout)
        except Exception as exc:
            results[platform] = BlockResult(
                False, platform, "{0}: {1}".format(type(exc).__name__, exc)
            )
    return results


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
        block_probe: Optional[Callable[..., dict[str, "BlockResult"]]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.state_dir = Path(state_dir or DEFAULT_STATE_DIR)
        self.offline_conf = Path(offline_conf) if offline_conf else None
        self._client_factory = client_factory or (lambda **kwargs: Ip2FreeClient(**kwargs))
        self._probe = probe
        self._block_probe = block_probe
        self._clock = clock
        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._refresh_thread: Optional[threading.Thread] = None
        self._proxies: list[ProxyEntry] = []
        # 候选池：保存全部已知代理（含当前不通的），key -> ProxyEntry
        self._candidates: dict[str, ProxyEntry] = {}
        self._index = 0
        self._updated_at = 0.0
        self.last_error = ""
        self._client: Optional[Ip2FreeClient] = None
        self._last_pick: Optional[ProxyEntry] = None
        self._checked_at = 0.0
        self._checked_keys: set[str] = set()
        self._rechecking = False
        self._background_threads: list[threading.Thread] = []
        # 已淘汰名单：ip:port -> 说明。命中即永久不再使用（平台封禁的 IP 不会自己恢复）
        self._retired: dict[str, str] = {}

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
        """是否该重新抓取候选列表（按刷新间隔）。"""
        with self._lock:
            if not self._candidates:
                return True
            return (self._clock() - self._updated_at) >= self.settings.refresh_minutes * 60

    def needs_recheck(self) -> bool:
        """是否有候选到了该复测的时间（按复检间隔）。"""
        return bool(self._candidates_due())

    def status_line(self) -> str:
        entry = self.current
        with self._lock:
            total = len(self._candidates)
            healthy = len(self._proxies)
            retired = len(self._retired)
        if entry is None:
            return "ip2free 无可用代理（候选 {0} 条，已淘汰 {1} 条）".format(total, retired)
        return "ip2free 可用 {0}/{1} 条（已淘汰 {2}），本次使用 {3}（{4}ms）".format(
            healthy, total, retired, entry.masked(), entry.latency_ms
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
            # 候选池保存全部历史代理；可用集合只保留上次测得通的
            self._candidates = {entry.key: entry for entry in entries}
            healthy = [entry for entry in entries if entry.healthy]
            healthy.sort(key=lambda item: (item.latency_ms, item.ip))
            self._proxies = healthy
            self._updated_at = updated_at
            self._checked_at = checked_at
            self._checked_keys = {entry.key for entry in healthy}
            self._index = 0
        logger.debug(
            "ip2free 读取本地缓存：候选 {0} 条，其中可用 {1} 条：{2}".format(
                len(entries), len(healthy), path
            )
        )

    def _save_cache(self, last_pick: Optional[ProxyEntry] = None) -> None:
        with self._lock:
            payload = {
                "updated_at": self._updated_at,
                "checked_at": self._checked_at,
                "updated_text": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._updated_at or self._clock())),
                "pick_mode": self.settings.pick_mode,
                # 落盘的是整个候选池（含当前不通的），这样重启后仍能继续复检
                "proxies": [entry.to_dict() for entry in self._candidates.values()],
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

    def _drop_retired(self, entries: Sequence[ProxyEntry]) -> list[ProxyEntry]:
        """剔除已淘汰（平台封禁）的代理，一次探测都不做。

        平台封禁是按出口 IP 判定的，不会自己恢复，因此命中即**永久**不再使用，
        既不测速也不重复探测，自然也不会重复刷同样的 WARNING。
        """
        with self._lock:
            retired = self._retired
            if not retired:
                return list(entries)
            kept = [entry for entry in entries if entry.key not in retired]
        skipped = len(entries) - len(kept)
        if skipped:
            logger.debug("ip2free 跳过 {0} 条已淘汰代理（平台封禁），不再复用".format(skipped))
        return kept

    def _retire(self, entry: ProxyEntry, reason: str) -> None:
        """把代理加入淘汰名单（永久），并落盘。"""
        with self._lock:
            if entry.key in self._retired:
                return
            self._retired[entry.key] = reason
        logger.warning(
            "ip2free 代理 {0} 已淘汰（{1}），后续不再复用".format(entry.key, reason)
        )

    def _filter_blocked(self, entries: Sequence[ProxyEntry]) -> list[ProxyEntry]:
        """按平台探测结果淘汰被封禁的代理。

        代理能出网不代表目标平台肯收（PandaTV 会按出口 IP 直接 403 block）。
        一旦确认封禁，就**永久淘汰**该代理：不再参与挑选、不再复测、不再重复告警。
        """
        platforms = self.settings.block_probes
        fresh = self._drop_retired(entries)
        if not platforms or not fresh:
            return fresh

        probe_func = self._block_probe or probe_platform_blocks
        workers = max(1, min(self.settings.max_workers, len(fresh)))
        kept: list[ProxyEntry] = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ip2free-block") as executor:
            futures = {executor.submit(probe_func, entry, platforms, self.settings.probe_timeout): entry
                       for entry in fresh}
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    results = future.result()
                except Exception:
                    # 探测本身异常：按"未封禁"处理，避免误杀可用代理
                    kept.append(entry)
                    continue
                blocked_here = {p: r.detail for p, r in (results or {}).items() if r.blocked}
                if not blocked_here:
                    kept.append(entry)
                    continue
                self._retire(
                    entry,
                    "、".join("{0}: {1}".format(p, d) for p, d in blocked_here.items()),
                )
        if kept != fresh:
            self._save_retired()

        order = {entry.key: index for index, entry in enumerate(entries)}
        kept.sort(key=lambda item: order.get(item.key, 0))
        return kept

    def retired_info(self) -> dict[str, str]:
        """已淘汰代理（ip:port -> 原因），供状态展示。"""
        with self._lock:
            return dict(self._retired)

    @property
    def retired_path(self) -> Path:
        return self.state_dir / "retired.json"

    def _load_retired(self) -> None:
        """读取淘汰名单：重启后同样不再复用被封禁的代理。"""
        path = self.retired_path
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        raw = payload.get("retired") if isinstance(payload, dict) else None
        if not isinstance(raw, dict):
            return
        cleaned: dict[str, str] = {}
        for key, value in raw.items():
            if isinstance(value, dict):
                # 兼容旧的 blocked.json 结构
                detail = value.get("platforms") or {}
                text = "、".join("{0}: {1}".format(k, v) for k, v in detail.items()) or "platform block"
            else:
                text = str(value or "platform block")
            cleaned[str(key)] = text
        with self._lock:
            self._retired.update(cleaned)
        if cleaned:
            logger.debug("ip2free 载入淘汰名单 {0} 条：{1}".format(len(cleaned), path))

    def _save_retired(self) -> None:
        with self._lock:
            payload = {
                "updated_at": self._clock(),
                "updated_text": time.strftime("%Y-%m-%d %H:%M:%S"),
                "retired": dict(self._retired),
            }
        try:
            self.retired_path.parent.mkdir(parents=True, exist_ok=True)
            self.retired_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.debug("写入淘汰名单失败：{0}".format(exc))

    def _probe_many(self, entries: Sequence[ProxyEntry], label: str) -> list[ProxyEntry]:
        """并发实测一组代理，返回仍可用（带实测延迟）的条目。"""
        if not entries:
            return []
        # 已知被封禁的直接跳过，连测速都不做（避免每小时重复请求同几条死代理）
        entries = self._drop_retired(entries)
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
        # 能出网但被目标平台封禁的，等同于不可用：一并舍弃并记日志
        return self._filter_blocked(alive)

    def _merge_candidates(self, fetched: list[ProxyEntry]) -> tuple[int, int]:
        """把接口返回的代理并入「候选池」，保持凭证粘性。

        ip2free 会轮换同一 ``ip:port`` 上的账号密码，而新凭证常常还没生效、
        旧凭证却仍然可用。因此：
        * 候选池里已有该节点 -> 保留原有凭证，不采纳接口的新凭证；
        * 新节点 -> 加入候选池，标记为「未测」，等本轮/下轮测速决定可用性；
        * 接口已下线的旧节点同样留在候选池（它可能仍能出网，要不要用由测速决定）。

        Returns:
            (新增候选数, 因凭证不同而保持旧凭证的条数)
        """
        added = 0
        kept_old_cred = 0
        with self._lock:
            for entry in fetched:
                existing = self._candidates.get(entry.key)
                if existing is not None:
                    if _credentials_changed(existing, entry):
                        kept_old_cred += 1
                    continue
                self._candidates[entry.key] = replace(
                    entry, healthy=None, probed_at=0.0, latency_ms=0
                )
                added += 1
        return added, kept_old_cred

    def _candidates_due(self, force: bool = False) -> list[ProxyEntry]:
        """挑出需要测速的候选：未测过的、上次不通的、或已过复检间隔的。"""
        now = self._clock()
        interval = self.settings.recheck_minutes * 60
        with self._lock:
            pool = list(self._candidates.values())
            retired = self._retired
        due: list[ProxyEntry] = []
        for entry in pool:
            if entry.key in retired:
                continue
            if force or entry.healthy is not True:
                due.append(entry)
            elif (now - entry.probed_at) >= interval:
                due.append(entry)
        return due

    def _apply_probe_results(
        self, probed: Sequence[ProxyEntry], living: Sequence[ProxyEntry]
    ) -> None:
        """把测速结果写回候选池，并重算「当前可用集合」。"""
        now = self._clock()
        alive_keys = {entry.key for entry in living}
        alive_by_key = {entry.key: entry for entry in living}
        with self._lock:
            for entry in probed:
                current = self._candidates.get(entry.key)
                if current is None:
                    continue
                if entry.key in alive_keys:
                    fresh = alive_by_key[entry.key]
                    self._candidates[entry.key] = replace(
                        current,
                        healthy=True,
                        latency_ms=fresh.latency_ms,
                        probed_at=now,
                    )
                else:
                    self._candidates[entry.key] = replace(
                        current, healthy=False, latency_ms=0, probed_at=now
                    )
            healthy = [
                entry for entry in self._candidates.values()
                if entry.healthy and entry.key not in self._retired
            ]
            healthy.sort(key=lambda item: (item.latency_ms, item.ip))
            self._proxies = healthy
            self._checked_keys = {entry.key for entry in healthy}
            self._checked_at = now
            self._index = 0

    def refresh(self) -> list[ProxyEntry]:
        """抓取候选并入池，然后测速，返回当前可用代理列表。

        * 候选池保存**全部**已知代理（含当前不通的），每轮只测「到期该测」的那些；
        * 被测出不通的代理留在候选池，等下一轮复检再试，不会一次性丢弃；
        * 平台封禁的代理进入淘汰名单，永久不再测也不再用。
        """
        if not self._refresh_lock.acquire(blocking=False):
            return self.proxies
        self.last_error = ""
        source = "ip2free"
        try:
            try:
                fetched, source = self._refresh_once()
                added, kept_old_cred = self._merge_candidates(fetched)
            except Exception as exc:
                self.last_error = "{0}: {1}".format(type(exc).__name__, exc)
                logger.warning("ip2free 刷新异常：{0}".format(self.last_error))
                return self.proxies

            due = self._candidates_due()
            probed: list[ProxyEntry] = []
            living: list[ProxyEntry] = []
            if due:
                due.sort(key=lambda item: (item.healthy is not None, item.probed_at))
                due = due[: max(1, self.settings.max_candidates)]
                probed = due
                living = self._probe_many(due, "ip2free-refresh")
                self._apply_probe_results(probed, living)
                with self._lock:
                    self._updated_at = self._clock()
                self._save_cache()
                self._write_proxychains()

            with self._lock:
                total = len(self._candidates)
            logger.info(
                "ip2free 刷新完成：候选 {0} 条（新增 {1}，沿用旧凭证 {2}），"
                "本轮测速 {3} 条，可用 {4} 条".format(
                    total, added, kept_old_cred, len(probed), len(living)
                )
            )
            # 返回当前可用集（而不是仅本轮测通的），调用方拿到的是真实可用状态
            return self.proxies
        finally:
            self._refresh_lock.release()

    def recheck(self) -> list[ProxyEntry]:
        """复检：把到期该测的候选全部测一遍，更新可用集合。"""
        with self._lock:
            if not self._candidates:
                return []
        due = self._candidates_due()
        if not due:
            return self.proxies
        due = due[: max(1, self.settings.max_candidates)]
        living = self._probe_many(due, "ip2free-recheck")
        self._apply_probe_results(due, living)
        self._save_cache()
        self._write_proxychains()
        logger.info(
            "ip2free 复检完成：测速 {0} 条，可用 {1} 条".format(len(due), len(living))
        )
        return living

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
        """启动时调用：载入候选池与淘汰名单，按需刷新，然后挑一条可用代理。"""
        self._load_cache()
        self._load_retired()
        if not self.proxies or self.is_stale():
            self.refresh()
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
        """标记某条代理**本次**失败：从可用集合移除，但保留在候选池等下次复检。

        与平台封禁不同，这类失败（连不上、超时、凭证暂未生效）可能只是暂时的，
        因此不淘汰，只标记为不健康，让下一轮复检重新验证。
        参数可以是 ProxyEntry、``ip:port`` 或完整的 socks5h 连接串。
        """
        key = _normalize_proxy_key(proxy)
        if not key:
            return
        now = self._clock()
        with self._lock:
            self._proxies = [entry for entry in self._proxies if entry.key != key]
            self._checked_keys.discard(key)
            current = self._candidates.get(key)
            if current is not None:
                self._candidates[key] = replace(
                    current, healthy=False, latency_ms=0, probed_at=now
                )
            if self._last_pick is not None and self._last_pick.key == key:
                self._last_pick = None
            self._index = 0
            # 同步刷新缓存文件，避免重启后又把已失效的凭证读回来
            self._save_cache()
            self._write_proxychains()

    def retire(self, proxy: ProxyEntry | str, reason: str = "platform block") -> None:
        """永久淘汰一条代理（平台按 IP 封禁，不会自行恢复）。"""
        key = _normalize_proxy_key(proxy)
        if not key:
            return
        entry = self._candidates.get(key)
        with self._lock:
            if entry is not None:
                self._retire(entry, reason)
            else:
                if key in self._retired:
                    return
                self._retired[key] = reason
                logger.warning("ip2free 代理 {0} 已淘汰（{1}），后续不再复用".format(key, reason))
            self._proxies = [item for item in self._proxies if item.key != key]
            self._checked_keys.discard(key)
            if self._last_pick is not None and self._last_pick.key == key:
                self._last_pick = None
            self._index = 0
        self._save_retired()
        self._save_cache()
        self._write_proxychains()

    def close(self) -> None:
        self.wait_idle(timeout=5.0)
        with self._lock:
            self._proxies = []
            self._candidates = {}
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
