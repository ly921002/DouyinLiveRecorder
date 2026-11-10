# -*- coding: utf-8 -*-
"""src/spider.parse_json_response 单元测试（全离线）。

线上报错：
    ERROR | __main__:start_record:1810 - 错误信息: Expecting value: line 1 column 1 (char 0)

成因：``async_req`` 请求失败时不抛异常，而是把 ``str(e)`` 当响应体返回，
直接 ``json.loads`` 只会得到这句无意义的 JSON 报错，真实原因被掩盖。
本测试直接加载**真实的 spider 模块**，验证该函数把各类非 JSON 响应翻译成可行动的异常。

环境说明：运行环境若缺少 execjs/loguru 等运行时依赖，会注入最小 stub；
被测的 parse_json_response 与其依赖的 utils.PlatformBlockedError 均为真实实现。
"""

import importlib.util
import json
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _ensure_stub(name, **attrs):
    """运行环境缺少某依赖时注入最小 stub，避免测试被环境问题拖累。"""
    if name in sys.modules:
        return
    try:
        __import__(name)
        return
    except ImportError:
        pass
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module


def _load_src_module(pkg, name, filename):
    spec = importlib.util.spec_from_file_location(f"{pkg.__name__}.{name}",
                                                  os.path.join(ROOT, "src", filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _build_spider():
    """按真实相对导入结构加载 src.spider（跳过 src/__init__.py 的 check_node）。"""
    _ensure_stub("execjs", compile=lambda *a, **k: None, ProgramError=type("ProgramError", (Exception,), {}))
    _ensure_stub("loguru")
    if "loguru" in sys.modules and not hasattr(sys.modules["loguru"], "logger"):
        class _Logger:
            def _noop(self, *a, **k):
                return None

            add = remove = _noop
            debug = info = warning = error = critical = _noop

        sys.modules["loguru"].logger = _Logger()

    if "src" not in sys.modules:
        pkg = types.ModuleType("src")
        pkg.__path__ = [os.path.join(ROOT, "src")]
        pkg.JS_SCRIPT_PATH = os.path.join(ROOT, "src", "javascript")
        sys.modules["src"] = pkg

    pkg = sys.modules["src"]
    if not hasattr(pkg, "JS_SCRIPT_PATH"):
        pkg.JS_SCRIPT_PATH = os.path.join(ROOT, "src", "javascript")

    for name in ("utils", "logger", "room", "ab_sign"):
        _load_src_module(pkg, name, f"{name}.py")

    _ensure_stub("httpx")

    return _load_src_module(pkg, "spider", "spider.py")


spider = _build_spider()
utils = sys.modules["src.utils"]


class ParseJsonResponseTestCase(unittest.TestCase):
    def setUp(self):
        self.parse = spider.parse_json_response

    def test_proxy_credential_failure_raises_blocked(self):
        """线上真实报错来源：代理凭证失效，async_req 返回异常文本。"""
        raw = "ProxyError: Invalid username/password"
        with self.assertRaises(utils.PlatformBlockedError) as ctx:
            self.parse(raw, proxy_addr="socks5h://u:p@1.1.1.1:1080",
                       url="https://www.pandalive.co.kr/live/play/x", platform="PandaTV")
        self.assertEqual(ctx.exception.platform, "PandaTV")
        self.assertEqual(ctx.exception.reason, "proxy_error")
        self.assertIn("Invalid username/password", ctx.exception.detail)
        self.assertIn("pandalive", ctx.exception.url)
        # 措辞必须是"代理不可用"，不能误报成"平台封禁 IP"
        self.assertNotIn("封禁该代理出口 IP", str(ctx.exception))

    def test_connect_error_raises_blocked(self):
        with self.assertRaises(utils.PlatformBlockedError):
            self.parse("ConnectError: All connection attempts failed", platform="PandaTV")

    def test_read_timeout_raises_blocked(self):
        with self.assertRaises(utils.PlatformBlockedError):
            self.parse("ReadTimeout: The read operation timed out", platform="PandaTV")

    def test_empty_response_raises_connection_error(self):
        with self.assertRaises(ConnectionError) as ctx:
            self.parse("   ", platform="PandaTV", url="https://x/y")
        self.assertIn("空响应", str(ctx.exception))

    def test_none_response_raises_connection_error(self):
        with self.assertRaises(ConnectionError):
            self.parse(None, platform="PandaTV")

    def test_html_response_raises_connection_error_with_snippet(self):
        with self.assertRaises(ConnectionError) as ctx:
            self.parse("<html><body>Access Denied</body></html>", platform="PandaTV")
        self.assertIn("不是 JSON", str(ctx.exception))
        self.assertIn("Access Denied", str(ctx.exception))

    def test_json_array_rejected(self):
        with self.assertRaises(ConnectionError) as ctx:
            self.parse("[1,2,3]", platform="PandaTV")
        self.assertIn("结构异常", str(ctx.exception))

    def test_valid_json_object_returned(self):
        data = self.parse('{"bjInfo":{"id":"abc"}}')
        self.assertEqual(data["bjInfo"]["id"], "abc")

    def test_json_with_whitespace_ok(self):
        self.assertEqual(self.parse('\n  {"a":1}  \n')["a"], 1)

    def test_block_payload_still_parsed(self):
        """封禁响应本身是合法 JSON，应原样返回，由调用方判 code=block。"""
        body = json.dumps({"result": False, "errorData": {"code": "block"},
                           "message": "blocked"}, ensure_ascii=False)
        data = self.parse(body, platform="PandaTV")
        self.assertEqual(data["errorData"]["code"], "block")


class PlatformBlockedErrorTestCase(unittest.TestCase):
    def test_is_connection_error_subclass(self):
        """main.py 先捕获 PlatformBlockedError 再捕获 ConnectionError，顺序依赖此继承关系。"""
        self.assertTrue(issubclass(utils.PlatformBlockedError, ConnectionError))

    def test_message_includes_context(self):
        err = utils.PlatformBlockedError("PandaTV", detail="HTTP 403 block", url="https://x/y")
        self.assertIn("PandaTV", str(err))
        self.assertIn("HTTP 403 block", str(err))
        self.assertIn("https://x/y", str(err))


if __name__ == "__main__":
    unittest.main()
