# -*- coding: utf-8 -*-
"""Cookie 在线有效性检测。

设计要点
--------
1. **只检测已填写的 Cookie**：config.ini 的 [Cookie] 段里值为空的条目直接跳过，不做任何请求。
2. **在线检测**：真的带着 Cookie 去请求平台，按响应判定登录态，不做本地过期时间猜测。
3. **判定分级**：
   - ``valid``   平台返回了正常的登录态
   - ``invalid`` 平台明确表示未登录 / 被踢下线（401/403、跳转到登录页、接口返回未登录码）
   - ``unknown`` 平台没有适配规则且通用探测也无法判断（**不会**当成失效去告警）
   - ``error``   网络异常 / 超时 / 被风控拦截（**不会**当成失效，避免误报）
4. **可扩展**：``PLATFORM_PROBES`` 里给平台配专用接口即可变成精确判定；
   没有配规则的平台走通用首页探测（启发式，结果可能是 unknown）。

判定顺序
--------
1. 请求异常            -> error
2. HTTP 401 / 403      -> invalid
3. 跳转后的 URL 命中登录页特征 -> invalid
4. 配了专用接口规则     -> 按 ``json_ok_codes`` / ``json_true_path`` 精确判定
5. 未配规则但响应体命中登录特征 -> invalid
6. 其余                -> valid（有专用规则）或 unknown（通用探测，无法排除误判）
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

try:  # httpx 是项目已有依赖（requests 之外的主力 http 库）
    import httpx
except ImportError:  # pragma: no cover - 理论不会走到，requirements 里已声明
    httpx = None  # type: ignore[assignment]

DEFAULT_TIMEOUT = 15
DEFAULT_CONCURRENCY = 5
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# 结果状态
STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_UNKNOWN = "unknown"
STATUS_ERROR = "error"

STATUS_TEXT = {
    STATUS_VALID: "有效",
    STATUS_INVALID: "失效",
    STATUS_UNKNOWN: "未知",
    STATUS_ERROR: "检测失败",
}


# --------------------------------------------------------------------- 规则表

@dataclass(frozen=True)
class ProbeRule:
    """单个平台的探测规则。

    url             探测地址（一般是平台首页或登录态接口）
    json_ok_codes   响应 JSON 里 ``code`` 字段落在这些值内视为有效（如 B站/斗鱼的 0）
    json_true_path  响应 JSON 里该路径为真值才视为有效（如 B站 data.isLogin）
    body_markers    响应体命中这些子串视为**未登录**（小写比较）
    precise         是否为精确规则；False 时判定为 valid 会降级成 unknown
    """

    url: str
    json_ok_codes: frozenset[int] = frozenset()
    json_true_path: str | None = None
    body_markers: tuple[str, ...] = ()
    precise: bool = True
    method: str = "GET"
    extra_headers: dict[str, str] = field(default_factory=dict)


# 跳转后的 URL 命中这些关键字 -> 未登录
LOGIN_URL_MARKERS = (
    "/login",
    "/signin",
    "/sign_in",
    "/passport",
    "/sso",
    "/auth",
    "/account/login",
    "login.html",
)

# 响应体命中这些关键字 -> 未登录（小写比较，仅在无精确规则时参与判定）
LOGIN_BODY_MARKERS = (
    '"islogin":false',
    '"is_login":false',
    '"islogin": false',
    '"is_login": false',
    "'islogin':false",
    '"loginstatus":false',
    '"haslogin":false',
    "window.location.href='/login",
    "请重新登录",
    "请先登录",
    "登录已失效",
    "登录状态已失效",
    "login_required",
    "not_logged_in",
)

# 未登录的通用业务码
NOT_LOGIN_CODES = frozenset({-101, -352, -401, -403, 401, 403, 100013, 21001})


def _platform_home() -> dict[str, tuple[str, str]]:
    """config.ini 的 cookie 键 -> (平台名, 探测地址)。

    只列项目实际支持的平台；键名与 config.ini [Cookie] 段保持一致。
    """
    return {
        "抖音cookie": ("抖音", "https://www.douyin.com/"),
        "快手cookie": ("快手", "https://live.kuaishou.com/"),
        "tiktok_cookie": ("TikTok", "https://www.tiktok.com/"),
        "虎牙cookie": ("虎牙", "https://www.huya.com/"),
        "斗鱼cookie": ("斗鱼", "https://www.douyu.com/"),
        "yy_cookie": ("YY", "https://www.yy.com/"),
        "b站cookie": ("B站", "https://api.bilibili.com/x/web-interface/nav"),
        "B站cookie": ("B站", "https://api.bilibili.com/x/web-interface/nav"),
        "小红书cookie": ("小红书", "https://www.xiaohongshu.com/"),
        "bigo_cookie": ("Bigo", "https://www.bigo.tv/"),
        "blued_cookie": ("Blued", "https://app.blued.cn/"),
        "sooplive_cookie": ("SOOP", "https://play.sooplive.co.kr/"),
        "netease_cookie": ("网易CC", "https://cc.163.com/"),
        "千度热播_cookie": ("千度热播", "https://qiandurebo.com/"),
        "pandatv_cookie": ("PandaTV", "https://www.pandalive.co.kr/"),
        "猫耳fm_cookie": ("猫耳FM", "https://fm.missevan.com/"),
        "winktv_cookie": ("WinkTV", "https://www.winktv.co.kr/"),
        "flextv_cookie": ("FlexTV", "https://www.flextv.co.kr/"),
        "look_cookie": ("Look", "https://look.163.com/"),
        "twitcasting_cookie": ("TwitCasting", "https://twitcasting.tv/"),
        "baidu_cookie": ("百度", "https://live.baidu.com/"),
        "weibo_cookie": ("微博", "https://weibo.com/"),
        "kugou_cookie": ("酷狗", "https://fanxing.kugou.com/"),
        "twitch_cookie": ("Twitch", "https://www.twitch.tv/"),
        "liveme_cookie": ("LiveMe", "https://www.liveme.com/"),
        "huajiao_cookie": ("花椒", "https://www.huajiao.com/"),
        "liuxing_cookie": ("流星", "https://www.7u66.com/"),
        "showroom_cookie": ("ShowRoom", "https://www.showroom-live.com/"),
        "acfun_cookie": ("AcFun", "https://live.acfun.cn/"),
        "changliao_cookie": ("畅聊", "https://live.tlclw.com/"),
        "yinbo_cookie": ("音播", "https://live.ybw1666.com/"),
        "yingke_cookie": ("映客", "https://www.inke.cn/"),
        "zhihu_cookie": ("知乎", "https://www.zhihu.com/"),
        "chzzk_cookie": ("CHZZK", "https://chzzk.naver.com/"),
        "haixiu_cookie": ("嗨秀", "https://www.haixiutv.com/"),
        "vvxqiu_cookie": ("VV星球", "https://h5webcdnp.vvxqiu.com/"),
        "17live_cookie": ("17Live", "https://17.live/"),
        "langlive_cookie": ("浪Live", "https://www.lang.live/"),
        "pplive_cookie": ("漂漂", "https://m.pp.weimipopo.com/"),
        "6room_cookie": ("六间房", "https://v.6.cn/"),
        "lehaitv_cookie": ("乐嗨", "https://www.lehaitv.com/"),
        "huamao_cookie": ("花猫", "https://h.catshow168.com/"),
        "shopee_cookie": ("Shopee", "https://live.shopee.com/"),
        "youtube_cookie": ("YouTube", "https://www.youtube.com/"),
        "taobao_cookie": ("淘宝", "https://huodong.m.taobao.com/"),
        "jd_cookie": ("京东", "https://eco.m.jd.com/"),
        "faceit_cookie": ("Faceit", "https://www.faceit.com/"),
        "migu_cookie": ("咪咕", "https://www.miguvideo.com/"),
        "lianjie_cookie": ("连接", "https://www.lianjie.com/"),
        "laixiu_cookie": ("来秀", "https://www.laixiu.com/"),
        "picarto_cookie": ("Picarto", "https://picarto.tv/"),
    }


def _precise_probes() -> dict[str, ProbeRule]:
    """已验证过的精确判定规则。没有配的平台走通用首页探测。"""
    return {
        # B站：未登录时 data.isLogin=false 且 code=-101
        "b站cookie": ProbeRule(
            url="https://api.bilibili.com/x/web-interface/nav",
            json_true_path="data.isLogin",
            json_ok_codes=frozenset({0}),
        ),
        "B站cookie": ProbeRule(
            url="https://api.bilibili.com/x/web-interface/nav",
            json_true_path="data.isLogin",
            json_ok_codes=frozenset({0}),
        ),
        # 知乎：未登录时 /api/v4/me 返回 401
        "zhihu_cookie": ProbeRule(
            url="https://www.zhihu.com/api/v4/me",
            json_ok_codes=frozenset({0}),
        ),
    }


PLATFORM_HOME = _platform_home()
PLATFORM_PROBES = _precise_probes()


# --------------------------------------------------------------------- 结果

@dataclass
class CookieCheckResult:
    key: str                 # config.ini 里的键，如 抖音cookie
    platform: str            # 平台显示名
    status: str              # valid / invalid / unknown / error
    detail: str = ""         # 人类可读的说明
    checked_at: float = 0.0  # unix 时间戳
    http_status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status_text"] = STATUS_TEXT.get(self.status, self.status)
        return data


# --------------------------------------------------------------------- 工具

def _normalize_proxy(proxy_addr: str | None) -> str | None:
    if not proxy_addr:
        return None
    proxy_addr = proxy_addr.strip()
    if not proxy_addr:
        return None
    if not proxy_addr.startswith("http"):
        proxy_addr = "http://" + proxy_addr
    return proxy_addr


def _dig(data: Any, path: str) -> Any:
    """按 a.b.c 取嵌套字段，取不到返回 None。"""
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _parse_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except Exception:
        return None


def classify_response(
    status_code: int,
    final_url: str,
    body: str,
    rule: ProbeRule | None = None,
) -> tuple[str, str]:
    """根据响应判定登录态，返回 (status, detail)。纯函数，方便单测。"""
    if status_code in (401, 403):
        return STATUS_INVALID, f"HTTP {status_code}（平台拒绝，通常表示未登录）"

    lowered_url = (final_url or "").lower()
    for marker in LOGIN_URL_MARKERS:
        if marker in lowered_url:
            return STATUS_INVALID, f"被重定向到登录页（{marker}）"

    lowered_body = (body or "").lower()
    payload = _parse_json(body or "")

    if rule is not None:
        if payload is not None:
            code = _dig(payload, "code")
            if isinstance(code, bool):
                code = int(code)
            code_hint = f"（code={code}）" if isinstance(code, int) else ""

            # 有显式登录标识时优先看它：code=0 但 isLogin=false 仍然是未登录
            if rule.json_true_path is not None:
                flag = _dig(payload, rule.json_true_path)
                if isinstance(flag, bool):
                    return (STATUS_VALID, "已登录" + code_hint) if flag \
                        else (STATUS_INVALID, "未登录" + code_hint)
                if flag is not None:
                    return (STATUS_VALID, "已登录" + code_hint) if flag \
                        else (STATUS_INVALID, "未登录" + code_hint)

            if isinstance(code, int):
                if rule.json_ok_codes:
                    if code in rule.json_ok_codes:
                        return STATUS_VALID, f"接口返回 code={code}"
                    if code in NOT_LOGIN_CODES:
                        return STATUS_INVALID, f"接口返回未登录码 code={code}"
                    return STATUS_INVALID, f"接口返回异常码 code={code}"
                if code in NOT_LOGIN_CODES:
                    return STATUS_INVALID, f"接口返回未登录码 code={code}"
                if code == 0:
                    return STATUS_VALID, f"接口返回 code={code}"

            if rule.json_true_path is not None:
                return STATUS_INVALID, f"响应缺少 {rule.json_true_path} 字段"
        for marker in rule.body_markers:
            if marker.lower() in lowered_body:
                return STATUS_INVALID, f"响应命中未登录特征（{marker}）"
        if status_code >= 400:
            return STATUS_ERROR, f"HTTP {status_code}"
        # 有精确规则但响应不是 JSON：只能说明请求通了，不能确认登录态
        return STATUS_UNKNOWN, "专用接口未返回可判定的 JSON"

    # 通用探测
    for marker in LOGIN_BODY_MARKERS:
        if marker in lowered_body:
            return STATUS_INVALID, f"响应命中未登录特征（{marker}）"
    if status_code >= 400:
        return STATUS_ERROR, f"HTTP {status_code}"
    if not body:
        return STATUS_UNKNOWN, "响应为空，无法判定"
    # 首页探测到 200 只能说明网络通，不能证明 Cookie 仍被认可
    return STATUS_UNKNOWN, "该平台未配置专用检测接口，仅确认可访问"


# --------------------------------------------------------------------- 探测

async def probe_one(
    key: str,
    cookie: str,
    proxy_addr: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    semaphore: asyncio.Semaphore | None = None,
) -> CookieCheckResult:
    """检测单个 Cookie。"""
    platform, fallback_url = PLATFORM_HOME.get(key, (key, ""))
    rule = PLATFORM_PROBES.get(key)
    url = rule.url if rule else fallback_url

    result = CookieCheckResult(key=key, platform=platform, status=STATUS_UNKNOWN)

    if httpx is None:
        result.status = STATUS_ERROR
        result.detail = "缺少 httpx 依赖"
        result.checked_at = time.time()
        return result
    if not url:
        result.status = STATUS_UNKNOWN
        result.detail = "该平台未配置探测地址"
        result.checked_at = time.time()
        return result

    headers = {"User-Agent": DEFAULT_USER_AGENT, "Cookie": cookie}
    if rule and rule.extra_headers:
        headers.update(rule.extra_headers)

    async def _do() -> None:
        async with httpx.AsyncClient(
            proxy=_normalize_proxy(proxy_addr),
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            if (rule and rule.method.upper() == "POST") if rule else False:
                response = await client.post(url, headers=headers)
            else:
                response = await client.get(url, headers=headers)
            result.http_status = response.status_code
            body = response.text or ""
            status, detail = classify_response(
                response.status_code, str(response.url), body, rule
            )
            result.status = status
            result.detail = detail

    try:
        if semaphore is not None:
            async with semaphore:
                await _do()
        else:
            await _do()
    except asyncio.TimeoutError:
        result.status = STATUS_ERROR
        result.detail = f"请求超时（{timeout}s）"
    except Exception as exc:  # noqa: BLE001 - 网络类异常一律归为 error，不误判为失效
        result.status = STATUS_ERROR
        result.detail = f"请求异常：{type(exc).__name__}: {exc}"

    result.checked_at = time.time()
    return result


async def check_cookies(
    cookies: dict[str, str],
    proxy_addr: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[CookieCheckResult]:
    """并发检测一批 Cookie。**值为空的键会被直接跳过**。"""
    items = [(key, value) for key, value in cookies.items() if (value or "").strip()]
    if not items:
        return []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    tasks = [
        probe_one(key, value, proxy_addr=proxy_addr, timeout=timeout, semaphore=semaphore)
        for key, value in items
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    collected: list[CookieCheckResult] = []
    for (key, _value), item in zip(items, results):
        if isinstance(item, BaseException):
            collected.append(
                CookieCheckResult(
                    key=key,
                    platform=PLATFORM_HOME.get(key, (key, ""))[0],
                    status=STATUS_ERROR,
                    detail=f"检测异常：{item}",
                    checked_at=time.time(),
                )
            )
        else:
            collected.append(item)
    return collected


def run_check(
    cookies: dict[str, str],
    proxy_addr: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[CookieCheckResult]:
    """同步入口，供线程直接调用。"""
    return asyncio.run(
        check_cookies(cookies, proxy_addr=proxy_addr, timeout=timeout, concurrency=concurrency)
    )


def summarize(results: Iterable[CookieCheckResult]) -> dict[str, int]:
    counter = {STATUS_VALID: 0, STATUS_INVALID: 0, STATUS_UNKNOWN: 0, STATUS_ERROR: 0}
    for item in results:
        counter[item.status] = counter.get(item.status, 0) + 1
    return counter
