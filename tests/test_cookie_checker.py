# -*- coding: utf-8 -*-
"""cookie_checker 单元测试。

全部离线：用假的 httpx 替换真实网络层，不会发出任何请求，也不触发录制逻辑。
"""

import importlib.util
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MODULE_PATH = os.path.join(ROOT, "src", "cookie_checker.py")


def load_module():
    """按文件路径加载，绕开 src/__init__.py 里的 check_node()（它会检查/准备 node 环境）。"""
    spec = importlib.util.spec_from_file_location("_cookie_checker_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cc = load_module()


class FakeResponse:
    def __init__(self, status_code=200, text="", url="https://example.com/"):
        self.status_code = status_code
        self.text = text
        self.url = url


class FakeClient:
    """httpx.AsyncClient 替身：按 URL 返回预设响应。"""

    def __init__(self, mapping, raise_exc=None):
        self.mapping = mapping
        self.raise_exc = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, url, headers=None):
        if self.raise_exc:
            raise self.raise_exc
        return self.mapping.get(url, FakeResponse(200, "ok", url))

    async def post(self, url, headers=None):
        return await self.get(url, headers=headers)


def fake_httpx(mapping, raise_exc=None):
    def factory(*_args, **_kwargs):
        return FakeClient(mapping, raise_exc=raise_exc)

    return type("httpx", (), {"AsyncClient": staticmethod(factory)})


class ClassifyTestCase(unittest.TestCase):
    """判定逻辑（纯函数）。"""

    def test_bilibili_logged_in(self):
        body = '{"code":0,"data":{"isLogin":true,"uname":"tester"}}'
        status, _detail = cc.classify_response(
            200, "https://api.bilibili.com/x/web-interface/nav", body,
            rule=cc.PLATFORM_PROBES["b站cookie"],
        )
        self.assertEqual(status, cc.STATUS_VALID)

    def test_bilibili_not_logged_in(self):
        body = '{"code":-101,"data":{"isLogin":false}}'
        status, detail = cc.classify_response(
            200, "https://api.bilibili.com/x/web-interface/nav", body,
            rule=cc.PLATFORM_PROBES["b站cookie"],
        )
        self.assertEqual(status, cc.STATUS_INVALID)
        self.assertIn("-101", detail)

    def test_bilibili_login_flag_false(self):
        body = '{"code":0,"data":{"isLogin":false}}'
        status, _detail = cc.classify_response(
            200, "https://api.bilibili.com/x/web-interface/nav", body,
            rule=cc.PLATFORM_PROBES["b站cookie"],
        )
        self.assertEqual(status, cc.STATUS_INVALID)

    def test_http_401_is_invalid(self):
        status, _detail = cc.classify_response(401, "https://x.com/me", "")
        self.assertEqual(status, cc.STATUS_INVALID)

    def test_http_403_is_invalid(self):
        status, _detail = cc.classify_response(403, "https://x.com/me", "")
        self.assertEqual(status, cc.STATUS_INVALID)

    def test_redirect_to_login_page_is_invalid(self):
        status, detail = cc.classify_response(
            200, "https://www.douyin.com/passport/login?redirect=1", "<html></html>"
        )
        self.assertEqual(status, cc.STATUS_INVALID)
        self.assertIn("登录页", detail)

    def test_body_login_marker_is_invalid(self):
        status, _detail = cc.classify_response(200, "https://x.com/", '{"isLogin":false}')
        self.assertEqual(status, cc.STATUS_INVALID)

    def test_login_code_is_invalid(self):
        status, detail = cc.classify_response(
            200, "https://x.com/api", '{"code":-101}', rule=cc.ProbeRule(url="u", json_ok_codes=frozenset({0}))
        )
        self.assertEqual(status, cc.STATUS_INVALID)
        self.assertIn("code", detail)

    def test_generic_probe_without_rule_is_unknown(self):
        """没有专用规则的平台，200 只能说明可访问，不能误报成失效。"""
        status, _detail = cc.classify_response(200, "https://www.huya.com/", "<html>直播</html>")
        self.assertEqual(status, cc.STATUS_UNKNOWN)

    def test_server_error_is_error_not_invalid(self):
        status, _detail = cc.classify_response(500, "https://x.com/", "")
        self.assertEqual(status, cc.STATUS_ERROR)

    def test_empty_body_is_unknown(self):
        status, _detail = cc.classify_response(200, "https://x.com/", "")
        self.assertEqual(status, cc.STATUS_UNKNOWN)

    def test_pandatv_not_logged_in(self):
        """实测未登录返回：HTTP 401 + {"result":false,"errorData":{"code":"loginMust"}}"""
        body = ('{"result":false,"message":"\\ub85c\\uadf8\\uc778 \\ud6c4 \\uc774\\uc6a8\\ud574 '
                '\\uc8fc\\uc138\\uc694.","errorData":{"code":"loginMust"},"userIp":"1.2.3.4"}')
        status, detail = cc.classify_response(
            401, "https://api.pandalive.co.kr/v1/member/info", body,
            rule=cc.PLATFORM_PROBES["pandatv_cookie"],
        )
        self.assertEqual(status, cc.STATUS_INVALID)
        self.assertIn("401", detail)

    def test_pandatv_result_false_even_on_200(self):
        status, _detail = cc.classify_response(
            200, "https://api.pandalive.co.kr/v1/member/info",
            '{"result":false,"errorData":{"code":"loginMust"}}',
            rule=cc.PLATFORM_PROBES["pandatv_cookie"],
        )
        self.assertEqual(status, cc.STATUS_INVALID)

    def test_pandatv_logged_in_shows_account(self):
        """真实已登录响应结构：{"userInfo":{"idx":..,"id":"lirh12",...},"result":true}"""
        body = '{"userInfo":{"idx":332083,"id":"lirh12","nick":"tester"},"result":true}'
        status, detail = cc.classify_response(
            200, "https://api.pandalive.co.kr/v1/member/info", body,
            rule=cc.PLATFORM_PROBES["pandatv_cookie"],
        )
        self.assertEqual(status, cc.STATUS_VALID)
        self.assertIn("已登录", detail)
        self.assertIn("lirh12", detail)

    def test_pandatv_logged_in_without_userinfo(self):
        status, detail = cc.classify_response(
            200, "https://api.pandalive.co.kr/v1/member/info", '{"result":true}',
            rule=cc.PLATFORM_PROBES["pandatv_cookie"],
        )
        self.assertEqual(status, cc.STATUS_VALID)
        self.assertEqual(detail, "已登录")

    def test_pandatv_rule_uses_api_host(self):
        self.assertIn("api.pandalive.co.kr", cc.PLATFORM_PROBES["pandatv_cookie"].url)
        self.assertEqual(cc.PLATFORM_PROBES["pandatv_cookie"].json_true_path, "result")

    def test_precise_rule_without_json_is_unknown(self):
        rule = cc.ProbeRule(url="https://x.com/api", json_true_path="data.isLogin")
        status, _detail = cc.classify_response(200, "https://x.com/api", "<html>风控</html>", rule=rule)
        self.assertEqual(status, cc.STATUS_UNKNOWN)


class DispatchTestCase(unittest.TestCase):
    """调度与并发。"""

    def test_empty_cookie_is_skipped(self):
        calls = []

        async def fake_probe(key, value, **_kwargs):
            calls.append(key)
            return cc.CookieCheckResult(key=key, platform=key, status=cc.STATUS_VALID)

        with mock.patch.object(cc, "probe_one", fake_probe):
            results = cc.run_check({"抖音cookie": "   ", "b站cookie": "SESSDATA=xxx"})
        self.assertEqual(calls, ["b站cookie"])
        self.assertEqual(len(results), 1)

    def test_all_empty_returns_empty_list(self):
        with mock.patch.object(cc, "probe_one", None):
            self.assertEqual(cc.run_check({"抖音cookie": ""}), [])

    def test_run_check_collects_results(self):
        mapping = {
            "https://api.bilibili.com/x/web-interface/nav": FakeResponse(
                200, '{"code":0,"data":{"isLogin":true}}'
            ),
            "https://www.huya.com/": FakeResponse(200, "<html>ok</html>"),
        }
        with mock.patch.object(cc, "httpx", fake_httpx(mapping)):
            results = cc.run_check({"b站cookie": "SESSDATA=1", "虎牙cookie": "a=b", "抖音cookie": ""})
        by_key = {item.key: item for item in results}
        self.assertEqual(set(by_key), {"b站cookie", "虎牙cookie"})
        self.assertEqual(by_key["b站cookie"].status, cc.STATUS_VALID)
        self.assertEqual(by_key["虎牙cookie"].status, cc.STATUS_UNKNOWN)
        self.assertTrue(by_key["虎牙cookie"].checked_at > 0)

    def test_network_exception_is_error_not_invalid(self):
        with mock.patch.object(cc, "httpx", fake_httpx({}, raise_exc=TimeoutError("timeout"))):
            results = cc.run_check({"b站cookie": "SESSDATA=1"})
        self.assertEqual(results[0].status, cc.STATUS_ERROR)
        self.assertIn("超时", results[0].detail)

    def test_unknown_platform_without_probe_url(self):
        result = cc.CookieCheckResult(key="火星cookie", platform="火星", status=cc.STATUS_UNKNOWN)
        with mock.patch.object(cc, "httpx", fake_httpx({})):
            with mock.patch.dict(cc.PLATFORM_HOME, {}, clear=True):
                pass
        self.assertEqual(result.status, cc.STATUS_UNKNOWN)

    def test_summarize_counts(self):
        results = [
            cc.CookieCheckResult("a", "A", cc.STATUS_VALID),
            cc.CookieCheckResult("b", "B", cc.STATUS_INVALID),
            cc.CookieCheckResult("c", "C", cc.STATUS_UNKNOWN),
            cc.CookieCheckResult("d", "D", cc.STATUS_ERROR),
        ]
        self.assertEqual(
            cc.summarize(results),
            {cc.STATUS_VALID: 1, cc.STATUS_INVALID: 1, cc.STATUS_UNKNOWN: 1, cc.STATUS_ERROR: 1},
        )

    def test_to_dict_contains_status_text(self):
        data = cc.CookieCheckResult("b站cookie", "B站", cc.STATUS_INVALID, checked_at=1.0).to_dict()
        self.assertEqual(data["status_text"], "失效")
        self.assertEqual(data["key"], "b站cookie")

    def test_normalize_proxy(self):
        self.assertIsNone(cc._normalize_proxy(None))
        self.assertIsNone(cc._normalize_proxy("  "))
        self.assertEqual(cc._normalize_proxy("127.0.0.1:7890"), "http://127.0.0.1:7890")
        self.assertEqual(cc._normalize_proxy("http://127.0.0.1:7890"), "http://127.0.0.1:7890")

    def test_dig_nested(self):
        payload = {"data": {"isLogin": True}}
        self.assertTrue(cc._dig(payload, "data.isLogin"))
        self.assertIsNone(cc._dig(payload, "data.missing"))
        self.assertIsNone(cc._dig(payload, "a.b.c"))


class CoverageTestCase(unittest.TestCase):
    """探测表要覆盖 config.ini 里所有平台。"""

    def test_all_config_keys_have_probe_target(self):
        from web.service import COOKIE_LABELS

        missing = [key for key in COOKIE_LABELS if key not in cc.PLATFORM_HOME]
        self.assertFalse(missing, f"以下平台缺少探测地址: {missing}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
