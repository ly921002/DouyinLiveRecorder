# -*- coding: utf-8 -*-
"""web.service 单元测试。

只使用 unittest 与 tempfile，不 import main，不启动录制、代理探测或网络访问。
"""

import http.client
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web import server as web_server  # noqa: E402
from web import service  # noqa: E402


class UrlConfigServiceTestCase(unittest.TestCase):
    """URL_config.ini 解析与增删改。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.url_file = os.path.join(self.tmp.name, "URL_config.ini")
        self.backup_dir = os.path.join(self.tmp.name, "backup_config")
        self.service = service.UrlConfigService(self.url_file, self.backup_dir, threading.Lock())

    def write(self, text: str) -> None:
        with open(self.url_file, "w", encoding="utf-8") as file_obj:
            file_obj.write(text)

    def read(self) -> str:
        with open(self.url_file, "r", encoding="utf-8") as file_obj:
            return file_obj.read()

    def test_parse_quality_url_name(self) -> None:
        self.write("原画,https://live.douyin.com/745964462470,张三\n")
        rooms = self.service.list_rooms()
        self.assertEqual(len(rooms), 1)
        self.assertEqual(rooms[0]["line_id"], 1)
        self.assertEqual(rooms[0]["quality"], "原画")
        self.assertEqual(rooms[0]["url"], "https://live.douyin.com/745964462470")
        self.assertEqual(rooms[0]["name"], "张三")
        self.assertFalse(rooms[0]["disabled"])

    def test_parse_anchor_prefix_and_disabled(self) -> None:
        self.write("#超清,https://live.douyin.com/123,主播: 李四\n高清,https://www.huya.com/52333,王五\n")
        rooms = self.service.list_rooms()
        self.assertEqual(len(rooms), 2)
        self.assertEqual(rooms[0]["name"], "李四")
        self.assertTrue(rooms[0]["disabled"])
        self.assertEqual(rooms[0]["quality"], "超清")
        self.assertEqual(rooms[1]["name"], "王五")
        self.assertFalse(rooms[1]["disabled"])

    def test_parse_unknown_quality_fallback(self) -> None:
        self.write("火星画质,https://live.bilibili.com/320,赵六\n")
        rooms = self.service.list_rooms()
        self.assertEqual(rooms[0]["quality"], "原画")

    def test_line_id_uses_real_file_line(self) -> None:
        self.write("\n\n蓝光,https://www.douyu.com/3637778,孙七\n")
        rooms = self.service.list_rooms()
        self.assertEqual(rooms[0]["line_id"], 3)

    def test_add_room(self) -> None:
        room = self.service.add_room(
            {"url": "https://live.douyin.com/8888", "quality": "高清", "name": "新主播"}
        )
        self.assertEqual(room["line_id"], 1)
        self.assertEqual(room["quality"], "高清")
        self.assertIn("高清,https://live.douyin.com/8888,新主播", self.read())
        self.assertEqual(len(self.service.list_rooms()), 1)

    def test_add_room_duplicate_returns_409(self) -> None:
        self.service.add_room({"url": "https://live.douyin.com/8888", "name": "甲"})
        with self.assertRaises(service.WebServiceError) as ctx:
            self.service.add_room({"url": "http://live.douyin.com/8888/", "name": "乙"})
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "room_duplicate")

    def test_add_room_invalid_url_quality_and_name(self) -> None:
        with self.assertRaises(service.WebServiceError) as ctx:
            self.service.add_room({"url": "不是一个链接"})
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(service.WebServiceError):
            self.service.add_room({"url": "https://live.douyin.com/1", "quality": "8K"})
        with self.assertRaises(service.WebServiceError) as ctx:
            self.service.add_room({"url": "https://live.douyin.com/1", "name": "主播,名称"})
        self.assertEqual(ctx.exception.code, "name_invalid")

    def test_platform_is_inferred_from_url(self) -> None:
        room = self.service.add_room({"url": "https://live.douyin.com/8888", "name": "测试主播"})
        self.assertEqual(room["platform"], "抖音")

    def test_update_room_partial(self) -> None:
        self.write("原画,https://live.douyin.com/1,甲\n")
        room = self.service.update_room(1, {"quality": "流畅"})
        self.assertEqual(room["quality"], "流畅")
        self.assertEqual(room["name"], "甲")
        self.assertEqual(room["url"], "https://live.douyin.com/1")

    def test_enable_and_disable_room(self) -> None:
        self.write("原画,https://live.douyin.com/1,甲\n原画,https://live.douyin.com/2,乙\n")
        disabled = self.service.set_room_enabled(1, False)
        self.assertTrue(disabled["disabled"])
        self.assertIn("#原画,https://live.douyin.com/1,甲", self.read())

        enabled = self.service.set_room_enabled(1, True)
        self.assertFalse(enabled["disabled"])
        self.assertNotIn("#原画", self.read())

        rooms = self.service.list_rooms()
        self.assertEqual(rooms[0]["name"], "甲")
        self.assertEqual(rooms[1]["name"], "乙")

    def test_update_missing_room_returns_404(self) -> None:
        self.write("原画,https://live.douyin.com/1,甲\n")
        with self.assertRaises(service.WebServiceError) as ctx:
            self.service.update_room(99, {"name": "不存在"})
        self.assertEqual(ctx.exception.status, 404)

    def test_delete_room(self) -> None:
        self.write("原画,https://live.douyin.com/1,甲\n原画,https://live.douyin.com/2,乙\n")
        removed = self.service.delete_room(1)
        self.assertEqual(removed["name"], "甲")
        rooms = self.service.list_rooms()
        self.assertEqual(len(rooms), 1)
        self.assertEqual(rooms[0]["line_id"], 1)
        self.assertEqual(rooms[0]["name"], "乙")

    def test_write_creates_backup(self) -> None:
        self.write("原画,https://live.douyin.com/1,甲\n")
        self.service.add_room({"url": "https://live.douyin.com/2", "name": "乙"})
        backups = os.listdir(self.backup_dir)
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].startswith("URL_config.ini_"))


class ConfigServiceTestCase(unittest.TestCase):
    """config.ini 白名单读取与行级定点写入。"""

    SAMPLE = (
        "[录制设置]\n"
        "language(zh_cn/en) = zh_cn\n"
        "# 这是一条需要保留的注释\n"
        "循环时间(秒) = 120\n"
        "视频保存格式ts|mkv|flv|mp4|mp3音频|m4a音频 = ts\n"
        "是否使用代理ip(是/否) = 是\n"
        "代理地址 = 127.0.0.1:7890\n"
        "自定义脚本执行命令 = rm -rf /\n"
        "\n"
        "[推送配置]\n"
        "pushplus推送token = SECRET-TOKEN\n"
        "\n"
        "[Cookie]\n"
        "抖音cookie = ttwid=SECRET-COOKIE-VALUE\n"
        "\n"
        "[Web]\n"
        "web服务端口 = 8080\n"
    )

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_file = os.path.join(self.tmp.name, "config.ini")
        self.backup_dir = os.path.join(self.tmp.name, "backup_config")
        with open(self.config_file, "w", encoding="utf-8") as file_obj:
            file_obj.write(self.SAMPLE)
        self.service = service.ConfigService(self.config_file, self.backup_dir, threading.Lock())

    def test_schema_only_exposes_whitelist(self) -> None:
        fields = self.service.get_schema()
        options = [item["option"] for item in fields]
        self.assertIn("循环时间(秒)", options)
        self.assertIn("视频保存格式ts|mkv|flv|mp4|mp3音频|m4a音频", options)
        for forbidden in ("抖音cookie", "pushplus推送token", "代理地址", "自定义脚本执行命令"):
            self.assertNotIn(forbidden, options)

        values = self.service.get_values()
        self.assertNotIn("抖音cookie", values)
        self.assertEqual(values["循环时间(秒)"], 120)
        self.assertEqual(values["是否使用代理ip(是/否)"], True)

    def test_schema_meta(self) -> None:
        fields = {item["option"]: item for item in self.service.get_schema()}
        quality = fields["原画|超清|高清|标清|流畅"]
        self.assertEqual(quality["type"], "select")
        self.assertEqual(quality["options"], list(service.RECORD_QUALITY_OPTIONS))
        loop = fields["循环时间(秒)"]
        self.assertEqual(loop["type"], "integer")
        self.assertEqual(loop["min"], 10)
        self.assertEqual(loop["max"], 3600)
        self.assertTrue(loop["description"])
        self.assertTrue(fields["追加格式后删除原文件"]["danger"])

    def test_update_keeps_comments_and_sensitive_fields(self) -> None:
        self.service.update_values({"循环时间(秒)": 300})
        with open(self.config_file, "r", encoding="utf-8") as file_obj:
            content = file_obj.read()

        self.assertIn("循环时间(秒) = 300", content)
        self.assertIn("# 这是一条需要保留的注释", content)
        self.assertIn("抖音cookie = ttwid=SECRET-COOKIE-VALUE", content)
        self.assertIn("pushplus推送token = SECRET-TOKEN", content)
        self.assertIn("代理地址 = 127.0.0.1:7890", content)
        self.assertIn("自定义脚本执行命令 = rm -rf /", content)
        self.assertIn("[Web]", content)
        self.assertEqual(content.index("# 这是一条需要保留的注释"),
                         content.index("# 这是一条需要保留的注释"))
        self.assertLess(content.index("language(zh_cn/en)"), content.index("循环时间(秒)"))
        self.assertLess(content.index("[录制设置]"), content.index("[推送配置]"))
        self.assertLess(content.index("[推送配置]"), content.index("[Cookie]"))

    def test_update_boolean_and_select(self) -> None:
        self.service.update_values(
            {"是否使用代理ip(是/否)": "否", "原画|超清|高清|标清|流畅": "超清"}
        )
        with open(self.config_file, "r", encoding="utf-8") as file_obj:
            content = file_obj.read()
        self.assertIn("是否使用代理ip(是/否) = 否", content)
        self.assertIn("原画|超清|高清|标清|流畅 = 超清", content)
        self.assertEqual(self.service.get_values()["原画|超清|高清|标清|流畅"], "超清")

    def test_update_clamps_out_of_range(self) -> None:
        self.service.update_values({"循环时间(秒)": 999999})
        self.assertEqual(self.service.get_values()["循环时间(秒)"], 3600)

    def test_update_rejects_forbidden_field(self) -> None:
        for forbidden in ("抖音cookie", "pushplus推送token", "代理地址", "自定义脚本执行命令"):
            with self.assertRaises(service.WebServiceError) as ctx:
                self.service.update_values({forbidden: "x"})
            self.assertEqual(ctx.exception.status, 400)
            self.assertEqual(ctx.exception.code, "field_forbidden")

    def test_update_rejects_invalid_select(self) -> None:
        with self.assertRaises(service.WebServiceError) as ctx:
            self.service.update_values({"视频保存格式ts|mkv|flv|mp4|mp3音频|m4a音频": "rmvb"})
        self.assertEqual(ctx.exception.status, 400)

    def test_update_empty_payload(self) -> None:
        with self.assertRaises(service.WebServiceError):
            self.service.update_values({})

    def test_update_creates_backup_and_appends_missing_option(self) -> None:
        self.service.update_values({"生成时间字幕文件": "是"})
        self.assertEqual(len(os.listdir(self.backup_dir)), 1)
        with open(self.config_file, "r", encoding="utf-8") as file_obj:
            content = file_obj.read()
        self.assertIn("生成时间字幕文件 = 是", content)
        self.assertLess(content.index("生成时间字幕文件"), content.index("[推送配置]"))

    def test_upsert_ini_option_creates_section(self) -> None:
        service.upsert_ini_option(self.config_file, "Web", "是否启用web管理(是/否)", "是")
        with open(self.config_file, "r", encoding="utf-8") as file_obj:
            content = file_obj.read()
        self.assertIn("是否启用web管理(是/否) = 是", content)
        self.assertIn("抖音cookie", content)


class CookieServiceTestCase(unittest.TestCase):
    """Cookie 小节的掩码读取与行级写入。"""

    SAMPLE = (
        "[录制设置]\n"
        "循环时间(秒) = 120\n"
        "\n"
        "[推送配置]\n"
        "pushplus推送token = SECRET-TOKEN\n"
        "\n"
        "[Cookie]\n"
        "# 录制抖音必填\n"
        "抖音cookie = ttwid=1%7CB1qls3GdnZhUov9o%7C16805\n"
        "快手cookie =\n"
        "b站cookie = SESSION=abc123\n"
        "\n"
        "[账号密码]\n"
        "sooplive账号 = user\n"
    )

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_file = os.path.join(self.tmp.name, "config.ini")
        self.backup_dir = os.path.join(self.tmp.name, "backup")
        with open(self.config_file, "w", encoding="utf-8") as file_obj:
            file_obj.write(self.SAMPLE)
        self.service = service.CookieService(self.config_file, self.backup_dir, threading.Lock())

    def test_list_masks_values_by_default(self) -> None:
        fields = self.service.list_cookies()
        keys = [item["key"] for item in fields]
        self.assertEqual(keys, ["抖音cookie", "快手cookie", "b站cookie"])
        self.assertEqual(fields[0]["label"], "抖音")
        self.assertEqual(fields[0]["length"], len("ttwid=1%7CB1qls3GdnZhUov9o%7C16805"))
        self.assertTrue(fields[0]["has_value"])
        self.assertFalse(fields[1]["has_value"])
        for item in fields:
            self.assertNotIn("value", item)
        self.assertNotIn("B1qls3GdnZhUov9o", fields[0]["masked"])

    def test_reveal_returns_raw_value(self) -> None:
        fields = self.service.list_cookies(reveal=True)
        self.assertEqual(fields[0]["value"], "ttwid=1%7CB1qls3GdnZhUov9o%7C16805")

    def test_update_keeps_percent_encoding(self) -> None:
        raw = "ttwid=1%7Cnew%7Cvalue; msToken=a%3Db"
        self.service.update_values({"抖音cookie": raw})
        with open(self.config_file, "r", encoding="utf-8") as file_obj:
            content = file_obj.read()
        self.assertIn("抖音cookie = " + raw, content)
        self.assertNotIn("%%7C", content)
        self.assertEqual(self.service.list_cookies(reveal=True)[0]["value"], raw)

    def test_update_preserves_other_sections_and_comments(self) -> None:
        self.service.update_values({"b站cookie": "NEW=1"})
        with open(self.config_file, "r", encoding="utf-8") as file_obj:
            content = file_obj.read()
        self.assertIn("b站cookie = NEW=1", content)
        self.assertIn("# 录制抖音必填", content)
        self.assertIn("pushplus推送token = SECRET-TOKEN", content)
        self.assertIn("sooplive账号 = user", content)
        self.assertIn("循环时间(秒) = 120", content)
        self.assertLess(content.index("[Cookie]"), content.index("[账号密码]"))

    def test_update_creates_backup(self) -> None:
        self.service.update_values({"快手cookie": "kuaishou=1"})
        self.assertEqual(len(os.listdir(self.backup_dir)), 1)

    def test_update_rejects_unknown_key(self) -> None:
        for forbidden in ("pushplus推送token", "sooplive账号", "循环时间(秒)", "不存在cookie"):
            with self.assertRaises(service.WebServiceError) as ctx:
                self.service.update_values({forbidden: "x"})
            self.assertEqual(ctx.exception.status, 400)
            self.assertEqual(ctx.exception.code, "field_forbidden")

    def test_update_rejects_newline_and_empty_payload(self) -> None:
        with self.assertRaises(service.WebServiceError) as ctx:
            self.service.update_values({"快手cookie": "a\nb"})
        self.assertEqual(ctx.exception.code, "value_invalid")
        with self.assertRaises(service.WebServiceError):
            self.service.update_values({})
        with self.assertRaises(service.WebServiceError):
            self.service.update_values("not-a-dict")

    def test_mask_secret(self) -> None:
        self.assertEqual(service.mask_secret(""), "")
        self.assertEqual(service.mask_secret("abc"), "***")
        masked = service.mask_secret("ttwid=1%7Cabcdefg")
        self.assertTrue(masked.startswith("ttwi"))
        self.assertTrue(masked.endswith("fg"))
        self.assertIn("*", masked)


class LogServiceTestCase(unittest.TestCase):
    """日志读取与脱敏。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log_file = os.path.join(self.tmp.name, "streamget.log")

    def test_missing_file_returns_empty(self) -> None:
        result = service.LogService(self.log_file).read(100)
        self.assertEqual(result["lines"], [])
        self.assertFalse(result["exists"])

    def test_limit_is_capped(self) -> None:
        with open(self.log_file, "w", encoding="utf-8") as file_obj:
            for index in range(400):
                file_obj.write("line {0}\n".format(index))
        result = service.LogService(self.log_file).read(1000)
        self.assertEqual(result["count"], 300)
        self.assertEqual(result["lines"][-1], "line 399")
        self.assertEqual(result["max"], 300)

    def test_sanitize_query_and_secret(self) -> None:
        with open(self.log_file, "w", encoding="utf-8") as file_obj:
            file_obj.write("请求 https://live.douyin.com/x?msToken=abc&room=1 完成\n")
            file_obj.write("cookie: ttwid=1%7Cabcdef; other=1\n")
            file_obj.write("Authorization: Bearer secret-token-value\n")
            file_obj.write("password=123456 secret=abcdef\n")
        lines = service.LogService(self.log_file).read(10)["lines"]
        joined = "\n".join(lines)
        self.assertNotIn("msToken=abc", joined)
        self.assertNotIn("ttwid=1%7Cabcdef", joined)
        self.assertNotIn("secret-token-value", joined)
        self.assertNotIn("123456", joined)
        self.assertIn(service._MASK, joined)
        self.assertIn("https://live.douyin.com/x", joined)


class SystemServiceTestCase(unittest.TestCase):
    """系统信息接口不含敏感路径。"""

    def test_info_fields(self) -> None:
        info = service.SystemService(app_version="v4.0.7").info()
        self.assertEqual(info["app_version"], "v4.0.7")
        self.assertTrue(info["python_version"])
        self.assertTrue(info["os_name"])
        self.assertIn("ffmpeg_available", info)
        self.assertGreaterEqual(info["disk_total_bytes"], 0)
        for key in ("config_file", "script_path", "executable", "cwd"):
            self.assertNotIn(key, info)


class StateSnapshotTestCase(unittest.TestCase):
    """运行时快照归一化。"""

    def test_normalize_snapshot(self) -> None:
        provider = service.build_state_provider_wrapper(
            lambda: {
                "version": "v4.0.7",
                "uptime_seconds": 3661,
                "monitoring": 3,
                "recording": {"甲": {"start_time": "2026-01-01 00:00:00", "quality": "原画"}},
                "recording_time_list": {"甲": ["2026-01-01 00:00:00", "原画"]},
                "running_list": ["https://live.douyin.com/1"],
                "max_request": 3,
                "error_count": 2,
                "exit_recording": False,
            }
        )
        snapshot = provider()
        self.assertEqual(snapshot["version"], "v4.0.7")
        self.assertEqual(snapshot["uptime_seconds"], 3661)
        self.assertEqual(snapshot["monitoring"], 3)
        self.assertEqual(snapshot["recording_count"], 1)
        self.assertEqual(snapshot["recording_time_list"]["甲"]["quality"], "原画")
        self.assertEqual(snapshot["running_list"], ["https://live.douyin.com/1"])
        self.assertEqual(snapshot["error_count"], 2)

    def test_provider_exception_is_swallowed(self) -> None:
        def broken() -> dict:
            raise RuntimeError("boom")

        snapshot = service.build_state_provider_wrapper(broken)()
        self.assertEqual(snapshot["monitoring"], 0)
        self.assertEqual(snapshot["recording"], {})


class WebServerIntegrationTestCase(unittest.TestCase):
    """HTTP 路由、静态资源和同源保护的轻量集成测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config_file = os.path.join(self.tmp.name, "config.ini")
        url_file = os.path.join(self.tmp.name, "URL_config.ini")
        log_file = os.path.join(self.tmp.name, "streamget.log")
        backup_dir = os.path.join(self.tmp.name, "backup")
        with open(config_file, "w", encoding="utf-8") as file_obj:
            file_obj.write("[录制设置]\n循环时间(秒) = 120\n\n[Cookie]\n抖音cookie =\n")
        with open(url_file, "w", encoding="utf-8") as file_obj:
            file_obj.write("")

        context = web_server.WebContext(
            service.UrlConfigService(url_file, backup_dir),
            service.ConfigService(config_file, backup_dir),
            service.CookieService(config_file, backup_dir),
            service.LogService(log_file),
            service.SystemService(app_version="test"),
            state_provider=lambda: {"version": "test", "recording": [], "running_list": []},
            bind_host="127.0.0.1",
            bind_port=0,
        )
        self.server = web_server.WebAdminServer(("127.0.0.1", 0), web_server.WebAdminHandler)
        self.server.context = context
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, body: dict | None = None,
                headers: dict | None = None) -> tuple[int, bytes, dict[str, str]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        request_headers = dict(headers or {})
        raw_body = None
        if body is not None:
            raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=raw_body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key: value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        return status, payload, response_headers

    def test_static_index_and_health(self) -> None:
        status, body, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"DouyinLiveRecorder", body)
        self.assertIn("Content-Security-Policy", headers)

        status, body, _headers = self.request("GET", "/api/health")
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_room_post_and_list(self) -> None:
        status, body, _headers = self.request(
            "POST",
            "/api/rooms",
            {"url": "https://live.douyin.com/999", "name": "测试", "quality": "原画"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body.decode("utf-8"))["data"]["platform"], "抖音")

        status, body, _headers = self.request("GET", "/api/rooms")
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)

    def test_cookie_get_masks_and_put_writes(self) -> None:
        status, body, _headers = self.request("GET", "/api/cookies")
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(status, 200)
        for item in payload["data"]["fields"]:
            self.assertNotIn("value", item)

        status, body, _headers = self.request(
            "PUT", "/api/cookies", {"values": {"抖音cookie": "ttwid=1%7Cx%7C9"}}
        )
        self.assertEqual(status, 200)
        status, body, _headers = self.request("GET", "/api/cookies?reveal=1")
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["data"]["reveal"])
        self.assertEqual(payload["data"]["fields"][0]["value"], "ttwid=1%7Cx%7C9")

    def test_cross_origin_mutation_is_rejected(self) -> None:
        status, body, _headers = self.request(
            "POST",
            "/api/rooms",
            {"url": "https://live.douyin.com/999"},
            {"Origin": "http://evil.example"},
        )
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(status, 403)
        self.assertEqual(payload["code"], "origin_mismatch")


if __name__ == "__main__":
    unittest.main()
