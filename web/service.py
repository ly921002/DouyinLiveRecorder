# -*- coding: utf-8 -*-
"""Web 管理界面服务层。

提供四类能力:
    1. UrlConfigService: URL_config.ini 的解析与增删改（原子写 + 备份 + 外部锁）
    2. ConfigService   : config.ini 的安全白名单字段读取与行级定点写入
    3. LogService      : 运行日志读取与脱敏
    4. SystemService   : 运行环境的非敏感信息

约束:
    - 只使用 Python 标准库
    - 不得 import main，运行时数据一律由调用方注入
    - 绝不读取、输出或写入 Cookie / 账号密码 / token 等敏感字段
"""

from __future__ import annotations

import datetime
import os
import platform
import re
import shutil
import tempfile
import threading
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------- 常量定义

DEFAULT_ENCODING = "utf-8-sig"
FALLBACK_ENCODING = "utf-8"
BOM_BYTES = b"\xef\xbb\xbf"

MAX_BODY_BYTES = 1024 * 1024
MAX_LOG_LINES = 300
MAX_BACKUP_FILES = 6

QUALITY_OPTIONS: tuple[str, ...] = ("原画", "蓝光", "超清", "高清", "标清", "流畅")
SAVE_FORMAT_OPTIONS: tuple[str, ...] = ("ts", "mkv", "flv", "mp4", "mp3音频", "m4a音频")
RECORD_QUALITY_OPTIONS: tuple[str, ...] = ("原画", "超清", "高清", "标清", "流畅")

PLATFORM_HOST_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("douyin.com", "抖音"),
    ("kuaishou.com", "快手"),
    ("huya.com", "虎牙"),
    ("douyu.com", "斗鱼"),
    ("yy.com", "YY"),
    ("bilibili.com", "B站"),
    ("xiaohongshu.com", "小红书"),
    ("xhslink.com", "小红书"),
    ("tiktok.com", "TikTok"),
    ("twitch.tv", "Twitch"),
    ("youtube.com", "YouTube"),
    ("youtu.be", "YouTube"),
    ("sooplive.co.kr", "SOOP"),
    ("twitcasting.tv", "TwitCasting"),
    ("acfun.cn", "AcFun"),
    ("weibo.com", "微博"),
    ("zhihu.com", "知乎"),
    ("17.live", "17Live"),
    ("picarto.tv", "Picarto"),
)

CONFIG_SECTION = "录制设置"
COOKIE_SECTION = "Cookie"

TRUE_VALUES = ("是", "yes", "true", "1", "on", "y", "t")
FALSE_VALUES = ("否", "no", "false", "0", "off", "n", "f")

_URL_PATTERN = re.compile(
    r"^(?:https?://)?"
    r"(?:[A-Za-z0-9\-_.~%$]+(?::[^@/\s]+)?@)?"
    r"(?:[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+)+|localhost|\[[0-9A-Fa-f:]+\])"
    r"(?::\d+)?"
    r"(?:/[^\s,]*)?$"
)

_SECTION_PATTERN = re.compile(r"^[ \t]*\[(?P<name>[^\]]+)\][ \t]*$")
_OPTION_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)(?P<mark>#?[ \t]*)"
    r"(?P<option>[^=:\s][^=:]*?)(?P<sep>[ \t]*[=:][ \t]*)(?P<value>.*)$"
)
_COMMENT_PATTERN = re.compile(r"^[ \t]*[#;]")


class WebServiceError(Exception):
    """面向 Web 层的业务异常，携带 HTTP 状态码与中文提示。"""

    def __init__(self, message: str, status: int = 400, code: str = "bad_request") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


# ---------------------------------------------------------------- 通用文件工具


def detect_encoding(file_path: str, default: str = DEFAULT_ENCODING) -> str:
    """判断文件编码，带 BOM 的文件使用 utf-8-sig，否则使用 utf-8。"""
    try:
        with open(file_path, "rb") as file_obj:
            head = file_obj.read(3)
    except OSError:
        return default
    if head.startswith(BOM_BYTES):
        return DEFAULT_ENCODING
    return FALLBACK_ENCODING


def read_text_lines(file_path: str, encoding: Optional[str] = None) -> tuple[list[str], str, str]:
    """读取文本文件。

    :return: (不含换行符的行列表, 换行符, 实际使用的编码)
    """
    used_encoding = encoding or detect_encoding(file_path)
    if not os.path.isfile(file_path):
        return [], "\n", used_encoding
    with open(file_path, "r", encoding=used_encoding, errors="ignore", newline="") as file_obj:
        content = file_obj.read()
    newline = "\r\n" if "\r\n" in content else "\n"
    return content.splitlines(), newline, used_encoding


def atomic_write_text(file_path: str, text: str, encoding: str = DEFAULT_ENCODING) -> None:
    """同目录临时文件 + os.replace 原子写，Windows 兼容。"""
    directory = os.path.dirname(os.path.abspath(file_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".dlr_tmp_", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as file_obj:
            file_obj.write(text)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(tmp_path, file_path)
    except BaseException:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise


def backup_file(file_path: str, backup_dir: str, limit_counts: int = MAX_BACKUP_FILES) -> None:
    """写前备份，最多保留 limit_counts 份历史。"""
    try:
        if not os.path.isfile(file_path):
            return
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_name = os.path.basename(file_path)
        target = os.path.join(backup_dir, base_name + "_" + timestamp).replace("\\", "/")
        shutil.copy2(file_path, target)

        history = sorted(
            (name for name in os.listdir(backup_dir) if name.startswith(base_name)),
            key=lambda name: os.path.getmtime(os.path.join(backup_dir, name)),
        )
        while len(history) > limit_counts:
            os.remove(os.path.join(backup_dir, history[0]))
            history = history[1:]
    except OSError:
        # 备份失败不应阻断主流程
        pass


def apply_ini_option(lines: list[str], section: str, option: str, value: str) -> list[str]:
    """在行列表中定点更新指定小节的 option，缺失时插入到该小节末尾。"""
    target_section = section.strip()
    new_line = "{0} = {1}".format(option, value)

    section_index = -1
    section_end = len(lines)
    for index, line in enumerate(lines):
        matched = _SECTION_PATTERN.match(line)
        if not matched:
            continue
        if matched.group("name").strip() == target_section:
            section_index = index
            for inner in range(index + 1, len(lines)):
                if _SECTION_PATTERN.match(lines[inner]):
                    section_end = inner
                    break
            break

    if section_index >= 0:
        for index in range(section_index + 1, section_end):
            matched = _OPTION_PATTERN.match(lines[index])
            if matched and matched.group("option").strip() == option:
                lines[index] = new_line
                return lines
        insert_at = section_end
        while insert_at - 1 > section_index and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines.insert(insert_at, new_line)
        return lines

    if lines and lines[-1].strip():
        lines.append("")
    lines.append("[{0}]".format(target_section))
    lines.append(new_line)
    return lines


def upsert_ini_option(
    file_path: str,
    section: str,
    option: str,
    value: str,
    encoding: Optional[str] = None,
) -> None:
    """行级定点更新 ini 配置项，保留注释、顺序与其他字段。

    不使用 configparser.write 重写全文，避免破坏注释与敏感段落。
    """
    lines, newline, used_encoding = read_text_lines(file_path, encoding)
    target_section = section.strip()
    option_name = option.strip()
    new_line = "{0} = {1}".format(option_name, value)

    section_index = -1
    section_end = len(lines)
    for index, line in enumerate(lines):
        matched = _SECTION_PATTERN.match(line)
        if not matched:
            continue
        if matched.group("name").strip() == target_section:
            section_index = index
            for inner in range(index + 1, len(lines)):
                if _SECTION_PATTERN.match(lines[inner]):
                    section_end = inner
                    break
            break

    if section_index >= 0:
        for index in range(section_index + 1, section_end):
            matched = _OPTION_PATTERN.match(lines[index])
            if matched and matched.group("option").strip() == option_name:
                lines[index] = new_line
                break
        else:
            insert_at = section_end
            while insert_at - 1 > section_index and not lines[insert_at - 1].strip():
                insert_at -= 1
            lines.insert(insert_at, new_line)
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("[{0}]".format(target_section))
        lines.append(new_line)

    text = newline.join(lines)
    if lines:
        text += newline
    atomic_write_text(file_path, text, used_encoding)


def parse_boolean(value: Any, default: bool = False) -> bool:
    """把 是/否、yes/no、1/0、布尔值统一转换为 bool。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    return default


def format_boolean(value: bool) -> str:
    """把 bool 序列化为配置文件使用的 是/否。"""
    return "是" if value else "否"


def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    """把输入转换为限制在区间内的整数。"""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def clamp_float(value: Any, minimum: float, maximum: float, default: float) -> float:
    """把输入转换为限制在区间内的浮点数。"""
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def infer_platform(url: str) -> str:
    """根据直播间 URL 推断平台名称，未知平台回退为主机名。"""
    text = (url or "").strip()
    if not text:
        return "未知平台"
    candidate = text if "://" in text else "https://" + text
    try:
        host = (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        host = ""
    for suffix, label in PLATFORM_HOST_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return label
    return host.removeprefix("www.") or "未知平台"


# ---------------------------------------------------------------- URL 配置服务


class UrlConfigService:
    """URL_config.ini 读写服务。

    行格式兼容:
        - 质量,URL,主播名
        - 质量,URL,主播: 主播名
        - 行首 # 表示禁用该直播间
    """

    def __init__(
        self,
        url_config_file: str,
        backup_dir: str,
        lock: Optional[threading.Lock] = None,
        encoding: Optional[str] = None,
    ) -> None:
        self.url_config_file = url_config_file
        self.backup_dir = backup_dir
        self._lock: threading.Lock = lock if lock is not None else threading.RLock()
        self._encoding = encoding

    # ---------------- 内部方法

    def _write_lines(self, lines: list[str], newline: str, encoding: str) -> None:
        backup_file(self.url_config_file, self.backup_dir)
        text = newline.join(lines)
        if lines:
            text += newline
        atomic_write_text(self.url_config_file, text, encoding)

    @staticmethod
    def _normalize_url(url: str) -> str:
        """用于重复判定的归一化：忽略协议与大小写，去掉末尾斜杠。"""
        text = (url or "").strip()
        if not text:
            return ""
        if "://" in text:
            text = text.split("://", 1)[1]
        return text.rstrip("/").lower()

    @staticmethod
    def _clean_name(name: str) -> str:
        text = (name or "").strip()
        text = re.sub(r"^主播\s*[:：]\s*", "", text)
        return text.strip().strip(",，").strip()

    @classmethod
    def _validate_name(cls, name: Any) -> str:
        text = cls._clean_name(str(name or ""))
        if len(text) > 100:
            raise WebServiceError("主播名不能超过 100 个字符", 400, "name_too_long")
        if any(mark in text for mark in (",", "，", "\r", "\n")):
            raise WebServiceError("主播名不能包含逗号或换行符", 400, "name_invalid")
        return text

    @classmethod
    def _validate_url(cls, url: Any) -> str:
        text = str(url or "").strip()
        if not text:
            raise WebServiceError("直播间地址不能为空", 400, "url_required")
        if len(text) > 2048:
            raise WebServiceError("直播间地址过长", 400, "url_too_long")
        if not _URL_PATTERN.match(text):
            raise WebServiceError("直播间地址格式不正确，请填写以 http(s):// 开头的完整链接", 400, "url_invalid")
        if "://" not in text:
            text = "https://" + text
        return text

    @staticmethod
    def _validate_quality(quality: Any) -> str:
        text = str(quality or "").strip()
        if not text:
            return "原画"
        if text not in QUALITY_OPTIONS:
            raise WebServiceError(
                "录制画质只能是：{0}".format("、".join(QUALITY_OPTIONS)), 400, "quality_invalid"
            )
        return text

    def _parse(self, raw_line: str, line_id: int) -> Optional[dict[str, Any]]:
        stripped = raw_line.strip()
        if not stripped:
            return None
        disabled = stripped.startswith("#")
        content = stripped[1:].strip() if disabled else stripped
        parts = [part.strip() for part in re.split(r"[,，]", content)]

        if len(parts) == 1:
            quality, url, name = "原画", parts[0], ""
        elif len(parts) == 2:
            if _URL_PATTERN.match(parts[0]) or "://" in parts[0]:
                quality, url, name = "原画", parts[0], parts[1]
            else:
                quality, url, name = parts[0], parts[1], ""
        else:
            quality, url = parts[0], parts[1]
            name = ",".join(parts[2:])

        if quality not in QUALITY_OPTIONS:
            quality = "原画"
        name = self._clean_name(name)
        return {
            "line_id": line_id,
            "quality": quality,
            "url": url.strip(),
            "name": name,
            "platform": infer_platform(url.strip()),
            "disabled": disabled,
            "raw": stripped,
        }

    def _load(self) -> tuple[list[str], str, str]:
        return read_text_lines(self.url_config_file, self._encoding)

    def _all_rooms(self, lines: Iterable[str]) -> list[dict[str, Any]]:
        rooms: list[dict[str, Any]] = []
        for index, raw_line in enumerate(lines):
            room = self._parse(raw_line, index + 1)
            if room is not None:
                rooms.append(room)
        return rooms

    def _find(self, rooms: list[dict[str, Any]], line_id: int) -> dict[str, Any]:
        for room in rooms:
            if room["line_id"] == line_id:
                return room
        raise WebServiceError("未找到行号为 {0} 的直播间配置".format(line_id), 404, "room_not_found")

    def _check_duplicate(
        self, rooms: list[dict[str, Any]], url: str, exclude_line_id: Optional[int] = None
    ) -> None:
        target = self._normalize_url(url)
        for room in rooms:
            if exclude_line_id is not None and room["line_id"] == exclude_line_id:
                continue
            if self._normalize_url(room["url"]) == target:
                raise WebServiceError("该直播间地址已存在，不能重复添加", 409, "room_duplicate")

    @staticmethod
    def _render(quality: str, url: str, name: str, disabled: bool) -> str:
        text = "{0},{1}".format(quality, url)
        if name:
            text += "," + name
        return ("#" + text) if disabled else text

    # ---------------- 对外接口

    def list_rooms(self) -> list[dict[str, Any]]:
        """返回全部直播间配置，line_id 为文件中的真实行号。"""
        with self._lock:
            lines, _newline, _encoding = self._load()
            return self._all_rooms(lines)

    def get_room(self, line_id: int) -> dict[str, Any]:
        with self._lock:
            lines, _newline, _encoding = self._load()
            return self._find(self._all_rooms(lines), line_id)

    def add_room(self, payload: dict[str, Any]) -> dict[str, Any]:
        """新增一行直播间配置，重复地址返回 409。"""
        if not isinstance(payload, dict):
            raise WebServiceError("请求体必须是 JSON 对象", 400, "payload_invalid")
        url = self._validate_url(payload.get("url"))
        quality = self._validate_quality(payload.get("quality"))
        name = self._validate_name(payload.get("name"))
        disabled = parse_boolean(payload.get("disabled"), False)

        with self._lock:
            lines, newline, encoding = self._load()
            rooms = self._all_rooms(lines)
            self._check_duplicate(rooms, url)
            lines.append(self._render(quality, url, name, disabled))
            self._write_lines(lines, newline, encoding)
            return self._parse(lines[-1], len(lines))

    def update_room(self, line_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """局部更新直播间配置，未提供的字段保持原值。"""
        if not isinstance(payload, dict):
            raise WebServiceError("请求体必须是 JSON 对象", 400, "payload_invalid")

        with self._lock:
            lines, newline, encoding = self._load()
            rooms = self._all_rooms(lines)
            current = self._find(rooms, line_id)

            url = current["url"]
            if "url" in payload and payload.get("url") is not None:
                url = self._validate_url(payload.get("url"))
            quality = current["quality"]
            if "quality" in payload and payload.get("quality") is not None:
                quality = self._validate_quality(payload.get("quality"))
            name = current["name"]
            if "name" in payload and payload.get("name") is not None:
                name = self._validate_name(payload.get("name"))
            disabled = current["disabled"]
            if "disabled" in payload and payload.get("disabled") is not None:
                disabled = parse_boolean(payload.get("disabled"), disabled)

            self._check_duplicate(rooms, url, exclude_line_id=line_id)
            lines[line_id - 1] = self._render(quality, url, name, disabled)
            self._write_lines(lines, newline, encoding)
            return self._parse(lines[line_id - 1], line_id)

    def set_room_enabled(self, line_id: int, enabled: bool) -> dict[str, Any]:
        """启用或禁用某一行直播间配置。"""
        return self.update_room(line_id, {"disabled": not bool(enabled)})

    def delete_room(self, line_id: int) -> dict[str, Any]:
        """删除某一行直播间配置。"""
        with self._lock:
            lines, newline, encoding = self._load()
            room = self._find(self._all_rooms(lines), line_id)
            del lines[line_id - 1]
            self._write_lines(lines, newline, encoding)
            return room


# ---------------------------------------------------------------- config.ini 白名单


def _field(
    option: str,
    label: str,
    field_type: str,
    description: str,
    default: Any = "",
    options: Optional[tuple[str, ...]] = None,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    danger: bool = False,
) -> dict[str, Any]:
    return {
        "section": CONFIG_SECTION,
        "option": option,
        "label": label,
        "type": field_type,
        "description": description,
        "default": default,
        "options": list(options) if options else None,
        "min": minimum,
        "max": maximum,
        "danger": danger,
    }


CONFIG_FIELD_SCHEMA: tuple[dict[str, Any], ...] = (
    _field("直播保存路径(不填则默认)", "直播保存路径", "string",
           "留空则使用程序目录下的 downloads 文件夹", ""),
    _field("保存文件夹是否以作者区分", "保存文件夹以作者区分", "boolean",
           "开启后按主播名建立子文件夹", "是"),
    _field("保存文件夹是否以时间区分", "保存文件夹以时间区分", "boolean",
           "开启后按录制日期建立子文件夹", "否"),
    _field("保存文件夹是否以标题区分", "保存文件夹以标题区分", "boolean",
           "开启后按直播标题建立子文件夹", "否"),
    _field("保存文件名是否包含标题", "保存文件名包含标题", "boolean",
           "开启后文件名附带直播标题", "否"),
    _field("是否去除名称中的表情符号", "去除名称中的表情符号", "boolean",
           "避免部分系统因表情符号导致保存失败", "是"),
    _field("视频保存格式ts|mkv|flv|mp4|mp3音频|m4a音频", "视频保存格式", "select",
           "推荐使用 ts 格式，中断录制不易损坏文件", "ts", SAVE_FORMAT_OPTIONS, danger=True),
    _field("原画|超清|高清|标清|流畅", "默认录制画质", "select",
           "单个直播间可在 URL_config.ini 中单独指定画质", "原画", RECORD_QUALITY_OPTIONS),
    _field("同一时间访问网络的线程数", "同一时间访问网络的线程数", "integer",
           "数值过大易被平台限制，建议 1 到 10", 3, None, 1, 50, danger=True),
    _field("循环时间(秒)", "循环检测时间(秒)", "integer",
           "每轮检测直播间状态的间隔时间", 300, None, 10, 3600, danger=True),
    _field("排队读取网址时间(秒)", "排队读取网址时间(秒)", "integer",
           "多个直播间逐个启动的间隔时间", 0, None, 0, 600),
    _field("是否显示循环秒数", "显示循环秒数", "boolean",
           "终端中显示每轮检测的倒计时", "否"),
    _field("是否显示直播源地址", "显示直播源地址", "boolean",
           "终端中打印真实推流地址", "否"),
    _field("分段录制是否开启", "分段录制", "boolean",
           "开启后按分段时间切割视频文件", "否"),
    _field("是否强制启用https录制", "强制启用 https 录制", "boolean",
           "部分平台仅提供 http 源时开启此项可能失败", "否"),
    _field("录制空间剩余阈值(gb)", "录制空间剩余阈值(GB)", "number",
           "磁盘剩余空间低于该值时停止录制", 1.0, None, 0.1, 1000.0, danger=True),
    _field("视频分段时间(秒)", "视频分段时间(秒)", "integer",
           "分段录制开启时单个视频的时长", 1800, None, 60, 86400),
    _field("录制完成后自动转为mp4格式", "录制完成后自动转为 mp4", "boolean",
           "转换需要额外时间并占用磁盘", "否", danger=True),
    _field("mp4格式重新编码为h264", "mp4 重新编码为 h264", "boolean",
           "重新编码会消耗大量 CPU", "否", danger=True),
    _field("追加格式后删除原文件", "转换后删除原文件", "boolean",
           "开启后源文件将被删除，请谨慎操作", "否", danger=True),
    _field("生成时间字幕文件", "生成时间字幕文件", "boolean",
           "录制时同时生成时间轴字幕", "否"),
    _field("是否使用代理ip(是/否)", "使用代理 IP", "boolean",
           "录制海外平台时需要开启", "是"),
    _field("使用代理录制的平台(逗号分隔)", "使用代理录制的平台", "string",
           "平台英文关键字，逗号分隔，如 tiktok, twitch", ""),
    _field("额外使用代理录制的平台(逗号分隔)", "额外使用代理录制的平台", "string",
           "在默认列表之外追加需要代理的平台", ""),
)

CONFIG_WHITELIST: dict[str, dict[str, Any]] = {
    item["option"]: item for item in CONFIG_FIELD_SCHEMA
}


class ConfigService:
    """config.ini 白名单读写服务。

    只暴露 CONFIG_FIELD_SCHEMA 中声明的字段，写入使用行级定点更新，
    绝不使用 configparser.write 重写全文，以保留注释、顺序和未暴露字段。
    """

    def __init__(
        self,
        config_file: str,
        backup_dir: str,
        lock: Optional[threading.Lock] = None,
        encoding: Optional[str] = None,
    ) -> None:
        self.config_file = config_file
        self.backup_dir = backup_dir
        self._lock: threading.Lock = lock if lock is not None else threading.RLock()
        self._encoding = encoding

    # ---------------- 读取

    def _raw_values(self) -> dict[str, str]:
        """行级读取白名单字段的原始字符串值。"""
        values: dict[str, str] = {}
        if not os.path.isfile(self.config_file):
            return values
        lines, _newline, _encoding = read_text_lines(self.config_file, self._encoding)
        current_section = ""
        for line in lines:
            section = _SECTION_PATTERN.match(line)
            if section:
                current_section = section.group("name").strip()
                continue
            if current_section != CONFIG_SECTION:
                continue
            if _COMMENT_PATTERN.match(line):
                continue
            matched = _OPTION_PATTERN.match(line)
            if not matched:
                continue
            option = matched.group("option").strip()
            if option in CONFIG_WHITELIST:
                values[option] = matched.group("value").strip()
        return values

    def _coerce_read(self, meta: dict[str, Any], raw: Optional[str]) -> Any:
        default = meta["default"]
        if raw is None or raw == "":
            raw_value: Any = default
        else:
            raw_value = raw
        if meta["type"] == "boolean":
            return parse_boolean(raw_value, parse_boolean(default, False))
        if meta["type"] == "integer":
            return clamp_int(raw_value, int(meta["min"] or 0), int(meta["max"] or 1 << 30), int(default))
        if meta["type"] == "number":
            return clamp_float(
                raw_value, float(meta["min"] or 0.0), float(meta["max"] or 1.0e9), float(default)
            )
        if meta["type"] == "select":
            text = str(raw_value).strip()
            lowered = {item.lower(): item for item in meta["options"]}
            return lowered.get(text.lower(), default)
        return str(raw_value)

    def _schema_unlocked(self) -> list[dict[str, Any]]:
        """在已持有锁的情况下生成字段 schema。"""
        raw_values = self._raw_values()
        fields: list[dict[str, Any]] = []
        for meta in CONFIG_FIELD_SCHEMA:
            value = self._coerce_read(meta, raw_values.get(meta["option"]))
            fields.append(
                {
                    "section": meta["section"],
                    "option": meta["option"],
                    "label": meta["label"],
                    "type": meta["type"],
                    "options": meta["options"],
                    "min": meta["min"],
                    "max": meta["max"],
                    "description": meta["description"],
                    "danger": meta["danger"],
                    "value": value,
                }
            )
        return fields

    def get_schema(self) -> list[dict[str, Any]]:
        """返回字段 schema（含当前值）。"""
        with self._lock:
            return self._schema_unlocked()

    def get_values(self) -> dict[str, Any]:
        """返回白名单字段的当前值。"""
        with self._lock:
            return {item["option"]: item["value"] for item in self._schema_unlocked()}

    # ---------------- 写入

    def _serialize(self, meta: dict[str, Any], value: Any) -> str:
        if meta["type"] == "boolean":
            return format_boolean(parse_boolean(value, parse_boolean(meta["default"], False)))
        if meta["type"] == "integer":
            return str(
                clamp_int(
                    value,
                    int(meta["min"] or 0),
                    int(meta["max"] or 1 << 30),
                    int(meta["default"]),
                )
            )
        if meta["type"] == "number":
            text_value = clamp_float(
                value,
                float(meta["min"] or 0.0),
                float(meta["max"] or 1.0e9),
                float(meta["default"]),
            )
            return ("%g" % text_value)
        if meta["type"] == "select":
            text = str(value).strip()
            lowered = {item.lower(): item for item in meta["options"]}
            if text.lower() not in lowered:
                raise WebServiceError(
                    "字段“{0}”的取值不合法，可选值：{1}".format(meta["label"], "、".join(meta["options"])),
                    400,
                    "value_invalid",
                )
            return lowered[text.lower()]
        text = str(value if value is not None else "").strip()
        if len(text) > 500:
            raise WebServiceError("字段“{0}”的内容过长".format(meta["label"]), 400, "value_too_long")
        if "\n" in text or "\r" in text:
            raise WebServiceError("字段“{0}”不能包含换行符".format(meta["label"]), 400, "value_invalid")
        return text

    def update_values(self, values: dict[str, Any]) -> dict[str, Any]:
        """校验并写回白名单字段，返回更新后的值。"""
        if not isinstance(values, dict):
            raise WebServiceError("请求体必须是 JSON 对象", 400, "payload_invalid")
        if not values:
            raise WebServiceError("没有需要保存的配置项", 400, "payload_empty")

        unknown = [key for key in values if key not in CONFIG_WHITELIST]
        if unknown:
            raise WebServiceError(
                "以下配置项不允许通过 Web 修改：{0}".format("、".join(sorted(map(str, unknown)))),
                400,
                "field_forbidden",
            )

        with self._lock:
            lines, newline, encoding = read_text_lines(self.config_file, self._encoding)
            for option, value in values.items():
                meta = CONFIG_WHITELIST[option]
                serialized = self._serialize(meta, value)
                lines = self._apply(lines, option, serialized)
            backup_file(self.config_file, self.backup_dir)
            text = newline.join(lines)
            if lines:
                text += newline
            atomic_write_text(self.config_file, text, encoding)
            # 已在锁内，复用无锁实现避免重复获取不可重入锁
            return {item["option"]: item["value"] for item in self._schema_unlocked()}

    @staticmethod
    def _apply(lines: list[str], option: str, value: str) -> list[str]:
        """在行列表中定点更新 option，缺失时插入到所属小节末尾。"""
        return apply_ini_option(lines, CONFIG_SECTION, option, value)


# ---------------------------------------------------------------- Cookie 服务

COOKIE_LABELS: dict[str, str] = {
    "抖音cookie": "抖音",
    "快手cookie": "快手",
    "tiktok_cookie": "TikTok",
    "虎牙cookie": "虎牙",
    "斗鱼cookie": "斗鱼",
    "yy_cookie": "YY",
    "b站cookie": "B站",
    "B站cookie": "B站",
    "小红书cookie": "小红书",
    "bigo_cookie": "Bigo",
    "blued_cookie": "Blued",
    "sooplive_cookie": "SOOP",
    "netease_cookie": "网易CC",
    "千度热播_cookie": "千度热播",
    "pandatv_cookie": "PandaTV",
    "猫耳fm_cookie": "猫耳FM",
    "winktv_cookie": "WinkTV",
    "flextv_cookie": "FlexTV",
    "look_cookie": "Look",
    "twitcasting_cookie": "TwitCasting",
    "baidu_cookie": "百度",
    "weibo_cookie": "微博",
    "kugou_cookie": "酷狗",
    "twitch_cookie": "Twitch",
    "liveme_cookie": "LiveMe",
    "huajiao_cookie": "花椒",
    "liuxing_cookie": "流星",
    "showroom_cookie": "ShowRoom",
    "acfun_cookie": "AcFun",
    "changliao_cookie": "畅聊",
    "yinbo_cookie": "音播",
    "yingke_cookie": "映客",
    "zhihu_cookie": "知乎",
    "chzzk_cookie": "CHZZK",
    "haixiu_cookie": "嗨秀",
    "vvxqiu_cookie": "VV星球",
    "17live_cookie": "17Live",
    "langlive_cookie": "浪Live",
    "pplive_cookie": "漂漂",
    "6room_cookie": "六间房",
    "lehaitv_cookie": "乐嗨",
    "huamao_cookie": "花猫",
    "shopee_cookie": "Shopee",
    "youtube_cookie": "YouTube",
    "taobao_cookie": "淘宝",
    "jd_cookie": "京东",
    "faceit_cookie": "Faceit",
    "migu_cookie": "咪咕",
    "lianjie_cookie": "连接",
    "laixiu_cookie": "来秀",
    "picarto_cookie": "Picarto",
}


def mask_secret(value: str) -> str:
    """对敏感值做掩码预览，只保留首尾少量字符。"""
    text = (value or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return "*" * len(text)
    return "{0}{1}{2}".format(text[:4], "*" * 8, text[-2:])


def cookie_label(key: str) -> str:
    """把配置键转换为平台显示名。"""
    if key in COOKIE_LABELS:
        return COOKIE_LABELS[key]
    name = re.sub(r"(?i)_?cookie$", "", key).strip(" _-")
    if not name:
        return key
    if name.isascii():
        return name.upper() if len(name) <= 5 else name.capitalize()
    return name


class CookieService:
    """config.ini 中 [Cookie] 小节的读写服务。

    - 默认只返回掩码预览，明文需要显式请求
    - 写入使用行级定点更新，绝不做 % → %% 转义，避免破坏 Cookie 中的百分号编码
    """

    MAX_VALUE_LENGTH = 8000

    def __init__(
        self,
        config_file: str,
        backup_dir: str,
        lock: Optional[threading.Lock] = None,
        encoding: Optional[str] = None,
    ) -> None:
        self.config_file = config_file
        self.backup_dir = backup_dir
        self._lock: threading.Lock = lock if lock is not None else threading.RLock()
        self._encoding = encoding

    # ---------------- 读取

    def _raw_pairs_unlocked(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if not os.path.isfile(self.config_file):
            return pairs
        lines, _newline, _encoding = read_text_lines(self.config_file, self._encoding)
        current_section = ""
        for line in lines:
            section = _SECTION_PATTERN.match(line)
            if section:
                current_section = section.group("name").strip()
                continue
            if current_section != COOKIE_SECTION:
                continue
            if _COMMENT_PATTERN.match(line):
                continue
            matched = _OPTION_PATTERN.match(line)
            if not matched:
                continue
            pairs.append((matched.group("option").strip(), matched.group("value").strip()))
        return pairs

    def _list_unlocked(self, reveal: bool = False) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        for key, value in self._raw_pairs_unlocked():
            item: dict[str, Any] = {
                "key": key,
                "label": cookie_label(key),
                "masked": mask_secret(value),
                "length": len(value),
                "has_value": bool(value),
            }
            if reveal:
                item["value"] = value
            fields.append(item)
        return fields

    def list_cookies(self, reveal: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            return self._list_unlocked(reveal)

    # ---------------- 写入

    def update_values(self, values: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(values, dict):
            raise WebServiceError("请求体必须是 JSON 对象", 400, "payload_invalid")
        if not values:
            raise WebServiceError("没有需要保存的 Cookie 项", 400, "payload_empty")

        with self._lock:
            known = {key for key, _value in self._raw_pairs_unlocked()}
            unknown = [key for key in values if key not in known]
            if unknown:
                raise WebServiceError(
                    "以下键不属于 Cookie 小节，不能通过此接口修改：{0}".format("、".join(sorted(map(str, unknown)))),
                    400,
                    "field_forbidden",
                )

            cleaned: dict[str, str] = {}
            for key, value in values.items():
                if value is None:
                    text = ""
                else:
                    text = str(value).strip()
                if "\n" in text or "\r" in text:
                    raise WebServiceError(
                        "Cookie“{0}”不能包含换行符".format(cookie_label(str(key))), 400, "value_invalid"
                    )
                if len(text) > self.MAX_VALUE_LENGTH:
                    raise WebServiceError(
                        "Cookie“{0}”内容过长，上限 {1} 个字符".format(cookie_label(str(key)), self.MAX_VALUE_LENGTH),
                        400,
                        "value_too_long",
                    )
                cleaned[str(key)] = text

            lines, newline, encoding = read_text_lines(self.config_file, self._encoding)
            for key, value in cleaned.items():
                lines = apply_ini_option(lines, COOKIE_SECTION, key, value)
            backup_file(self.config_file, self.backup_dir)
            text = newline.join(lines)
            if lines:
                text += newline
            atomic_write_text(self.config_file, text, encoding)
            return self._list_unlocked()


# ---------------------------------------------------------------- 日志服务

_SECRET_KV_PATTERN = re.compile(
    r"(?i)\b(cookie|token|password|passwd|pwd|secret|authorization|auth"
    r"|api[_-]?key|access[_-]?key|signature|mstoken|ttwid|odin_tt"
    r"|csrf[_-]?token|sessionid|session)\b"
    r"(\s*[:=]\s*)(\"?)([^\"\s,;&]+)\3"
)
_URL_QUERY_PATTERN = re.compile(r"(https?://[^\s\"'<>)\]]+)\?[^\s\"'<>)\]]+")
_AUTH_HEADER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9\-._~+/=]{6,})")
_MASK = "***"


def sanitize_text(text: str) -> str:
    """对日志文本脱敏：URL 查询参数、授权头与常见凭据字段。"""
    if not text:
        return text
    result = _URL_QUERY_PATTERN.sub(lambda m: m.group(1) + "?" + _MASK, text)
    result = _AUTH_HEADER_PATTERN.sub(lambda m: m.group(1) + " " + _MASK, result)
    result = _SECRET_KV_PATTERN.sub(lambda m: m.group(1) + "=" + _MASK, result)
    return result


class LogService:
    """运行日志读取服务，最多返回 300 行并做脱敏处理。"""

    def __init__(self, log_file: str, max_lines: int = MAX_LOG_LINES) -> None:
        self.log_file = log_file
        self.max_lines = max_lines

    def read(self, limit: int = 100) -> dict[str, Any]:
        limit = clamp_int(limit, 1, self.max_lines, min(100, self.max_lines))
        if not os.path.isfile(self.log_file):
            return {"lines": [], "count": 0, "limit": limit, "max": self.max_lines, "exists": False}
        try:
            lines, _newline, _encoding = read_text_lines(self.log_file)
        except OSError as error:
            raise WebServiceError("读取日志文件失败：{0}".format(error), 500, "log_read_failed") from error
        selected = lines[-limit:]
        return {
            "lines": [sanitize_text(line) for line in selected],
            "count": len(selected),
            "limit": limit,
            "max": self.max_lines,
            "exists": True,
        }


# ---------------------------------------------------------------- 系统信息


class SystemService:
    """运行环境信息（不含任何敏感绝对路径）。"""

    def __init__(self, app_version: str = "", disk_path: Optional[str] = None) -> None:
        self.app_version = app_version
        self.disk_path = disk_path

    @staticmethod
    def _ffmpeg_available() -> bool:
        return shutil.which("ffmpeg") is not None or shutil.which("ffmpeg.exe") is not None

    def info(self) -> dict[str, Any]:
        total = used = free = 0
        try:
            usage = shutil.disk_usage(self.disk_path or os.getcwd())
            total, used, free = usage.total, usage.used, usage.free
        except OSError:
            pass
        return {
            "app_version": self.app_version,
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "os_name": platform.system(),
            "os_release": platform.release(),
            "cpu_arch": platform.machine() or platform.processor(),
            "cpu_count": os.cpu_count() or 0,
            "ffmpeg_available": self._ffmpeg_available(),
            "disk_total_bytes": total,
            "disk_used_bytes": used,
            "disk_free_bytes": free,
            "disk_total_gb": round(total / (1024 ** 3), 2),
            "disk_free_gb": round(free / (1024 ** 3), 2),
            "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }


# ---------------------------------------------------------------- 运行时快照


def normalize_state_snapshot(state: Any) -> dict[str, Any]:
    """把外部注入的运行时状态整理为安全的展示数据。"""
    if not isinstance(state, dict):
        return {}

    recording = state.get("recording")
    if isinstance(recording, (list, tuple, set)):
        recording = {str(item): {} for item in recording}
    elif not isinstance(recording, dict):
        recording = {}

    time_list = state.get("recording_time_list")
    normalized_time: dict[str, Any] = {}
    if isinstance(time_list, dict):
        for key, value in time_list.items():
            if isinstance(value, (list, tuple)) and value:
                started = value[0]
                started_text = (
                    started.strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(started, datetime.datetime)
                    else str(started)
                )
                normalized_time[str(key)] = {
                    "start_time": started_text,
                    "quality": str(value[1]) if len(value) > 1 else "",
                }
            else:
                normalized_time[str(key)] = {"start_time": str(value), "quality": ""}

    running_list = state.get("running_list")
    if isinstance(running_list, (list, tuple, set)):
        running_list = [str(item) for item in running_list]
    else:
        running_list = []

    return {
        "version": str(state.get("version") or ""),
        "uptime_seconds": clamp_int(state.get("uptime_seconds"), 0, 1 << 40, 0),
        "uptime_text": str(state.get("uptime_text") or ""),
        "monitoring": clamp_int(state.get("monitoring"), 0, 1 << 30, 0),
        "recording": recording,
        "recording_count": clamp_int(state.get("recording_count"), 0, 1 << 30, len(recording)),
        "recording_time_list": normalized_time,
        "running_list": running_list,
        "max_request": clamp_int(state.get("max_request"), 0, 1 << 30, 0),
        "error_count": clamp_int(state.get("error_count"), 0, 1 << 30, 0),
        "exit_recording": bool(state.get("exit_recording", False)),
        "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_state_provider_wrapper(provider: Optional[Callable[[], dict[str, Any]]]) -> Callable[[], dict[str, Any]]:
    """包装状态回调，保证异常不会穿透到 HTTP 层。"""

    def _provider() -> dict[str, Any]:
        if provider is None:
            return normalize_state_snapshot({})
        try:
            return normalize_state_snapshot(provider())
        except Exception as error:  # noqa: BLE001 - 状态回调来自外部，必须兜底
            return normalize_state_snapshot({"version": "", "error": str(error)})

    return _provider
