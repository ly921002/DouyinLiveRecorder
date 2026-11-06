# -*- coding: utf-8 -*-
"""src/ip2free 单元测试（全离线）。

用假的 ip2free 客户端与假的探测函数替代真实网络，不发出任何请求。
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from dataclasses import replace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def load_module(name, filename):
    """按文件路径加载，绕开 src/__init__.py 里的 check_node()。"""
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "src", filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ip2free = load_module("_ip2free_under_test", "ip2free.py")
ProxyEntry = ip2free.ProxyEntry
Ip2FreeSettings = ip2free.Ip2FreeSettings
Ip2FreeProxyPool = ip2free.Ip2FreeProxyPool
ProbeResult = ip2free.ProbeResult


def make_entry(ip, port=1080, latency=0, **kwargs):
    if "latency_ms" in kwargs:
        latency = kwargs.pop("latency_ms")
    return ProxyEntry(ip=ip, port=port, latency_ms=latency, **kwargs)


class ProxyEntryTestCase(unittest.TestCase):
    def test_url_with_and_without_auth(self):
        entry = make_entry("1.2.3.4", 1080, username="u", password="p@ss")
        self.assertEqual(entry.url, "socks5h://u:p%40ss@1.2.3.4:1080")
        self.assertEqual(make_entry("1.2.3.4", 1080).url, "socks5h://1.2.3.4:1080")

    def test_invalid_entry_rejected(self):
        with self.assertRaises(ValueError):
            ProxyEntry(ip="", port=1080)
        with self.assertRaises(ValueError):
            ProxyEntry(ip="1.2.3.4", port=0)
        with self.assertRaises(ValueError):
            ProxyEntry(ip="1.2.3.4", port=70000)

    def test_round_trip_dict(self):
        entry = make_entry("1.2.3.4", 1080, username="u", password="p", country="US", latency_ms=42)
        self.assertEqual(ProxyEntry.from_dict(entry.to_dict()), entry)


class NormalizeTestCase(unittest.TestCase):
    def test_filters_protocol_country_and_duplicates(self):
        raw = [
            {"ip": "1.1.1.1", "port": 1080, "protocol": "socks5", "country_code": "US"},
            {"ip": "1.1.1.1", "port": 1080, "protocol": "socks5", "country_code": "US"},
            {"ip": "2.2.2.2", "port": 1080, "protocol": "http", "country_code": "US"},
            {"ip": "3.3.3.3", "port": 1080, "protocol": "socks5", "country_code": "GB"},
            {"ip": "not-an-ip", "port": 1080, "protocol": "socks5"},
            {"ip": "4.4.4.4", "port": "bad", "protocol": "socks5"},
        ]
        entries = ip2free.normalize_proxies(raw, countries=["US"])
        self.assertEqual([e.ip for e in entries], ["1.1.1.1"])

    def test_country_filter_is_optional(self):
        raw = [
            {"ip": "3.3.3.3", "port": 1080, "protocol": "socks5", "country_code": "GB"},
            {"ip": "1.1.1.1", "port": 1080, "protocol": "socks5", "country_code": "US"},
        ]
        self.assertEqual(len(ip2free.normalize_proxies(raw)), 2)


class ProxychainsConfTestCase(unittest.TestCase):
    def test_parse_line_with_and_without_auth(self):
        plain = ip2free.parse_proxychains_line("socks5 1.2.3.4 1080")
        self.assertEqual((plain.ip, plain.port), ("1.2.3.4", 1080))
        self.assertEqual(plain.username, "")
        authed = ip2free.parse_proxychains_line("socks5 1.2.3.4 1080 user pass")
        self.assertEqual((authed.username, authed.password), ("user", "pass"))

    def test_parse_rejects_noise(self):
        for line in ("", "# socks5 1.2.3.4 1080", "[ProxyList]", "socks5 1.2.3.4",
                     "socks5 1.2.3.4 notaport"):
            self.assertIsNone(ip2free.parse_proxychains_line(line), line)

    def test_http_line_parsed_but_filtered_out(self):
        entry = ip2free.parse_proxychains_line("http 1.2.3.4 1080")
        self.assertEqual(entry.protocol, "http")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "proxychains.conf")
            with open(path, "w", encoding="utf-8") as file_obj:
                file_obj.write("[ProxyList]\nhttp 1.2.3.4 1080\nsocks5 5.6.7.8 2080\n")
            loaded = ip2free.read_proxychains_conf(path)
        self.assertEqual([e.ip for e in loaded], ["5.6.7.8"])

    def test_write_then_read_round_trip(self):
        entries = [
            make_entry("1.2.3.4", 1080, username="u", password="p"),
            make_entry("5.6.7.8", 2080),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "proxychains.conf")
            ip2free.write_proxychains_conf(path, entries)
            with open(path, "r", encoding="utf-8") as file_obj:
                content = file_obj.read()
            self.assertIn("[ProxyList]", content)
            self.assertIn("socks5 1.2.3.4 1080 u p", content)
            self.assertIn("socks5 5.6.7.8 2080", content)
            loaded = ip2free.read_proxychains_conf(path)
        self.assertEqual([(e.ip, e.port) for e in loaded], [("1.2.3.4", 1080), ("5.6.7.8", 2080)])

    def test_read_missing_file_returns_empty(self):
        self.assertEqual(ip2free.read_proxychains_conf(os.path.join(os.sep, "nope", "x.conf")), [])


class SettingsTestCase(unittest.TestCase):
    def test_env_overrides_config_and_parsing(self):
        config = {
            "是否使用ip2free动态socks5代理(是/否)": "是",
            "ip2free账号": "cfg@example.com",
            "ip2free密码": "cfg-pass",
            "ip2free代理国家代码": "us，gb",
            "ip2free最多挑选代理数": "9",
            "ip2free测速并发数": "999",
            "ip2free测速超时(秒)": "3.5",
            "ip2free代理刷新间隔(分钟)": "0",
        }

        def reader(section, option, default):
            self.assertEqual(section, "录制设置")
            return config.get(option, default)

        settings = Ip2FreeSettings.from_reader(
            reader, environ={"IP2FREE_EMAIL": "env@example.com", "IP2FREE_PASSWORD": "env-pass"}
        )
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.email, "env@example.com")
        self.assertEqual(settings.password, "env-pass")
        self.assertEqual(settings.countries, ("US", "GB"))
        self.assertEqual(settings.max_pick, 9)
        self.assertEqual(settings.max_workers, 64)  # 越界被夹到上限
        self.assertAlmostEqual(settings.probe_timeout, 3.5)
        self.assertEqual(settings.refresh_minutes, 1)  # 下限保护

    def test_defaults_when_reader_raises(self):
        def reader(section, option, default):
            raise RuntimeError("boom")

        settings = Ip2FreeSettings.from_reader(reader, environ={})
        self.assertFalse(settings.enabled)
        self.assertFalse(settings.has_credentials)
        self.assertEqual(settings.max_pick, 5)
        self.assertEqual(settings.test_url, ip2free.DEFAULT_TEST_URL)


class SelectWorkingTestCase(unittest.TestCase):
    def test_sorted_by_latency_and_fastest_mode(self):
        candidates = [make_entry("1.1.1.1"), make_entry("2.2.2.2"), make_entry("3.3.3.3")]
        latency = {"1.1.1.1": 300, "2.2.2.2": 100, "3.3.3.3": 200}

        def probe(entry, url, timeout):
            return ProbeResult(ok=True, latency_ms=latency[entry.ip])

        picked = ip2free.select_working(
            candidates, max_pick=2, probe=probe, pick_mode=ip2free.PICK_MODE_FASTEST
        )
        self.assertEqual([e.ip for e in picked], ["2.2.2.2", "3.3.3.3"])
        self.assertEqual([e.latency_ms for e in picked], [100, 200])

    def test_random_mode_only_uses_working_proxies(self):
        candidates = [make_entry(ip) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")]

        def probe(entry, url, timeout):
            # 3、4 号不可用
            return ProbeResult(ok=entry.ip in ("1.1.1.1", "2.2.2.2"), latency_ms=10)

        for _ in range(20):
            picked = ip2free.select_working(candidates, max_pick=2, probe=probe)
            self.assertEqual(len(picked), 2)
            self.assertTrue({e.ip for e in picked} <= {"1.1.1.1", "2.2.2.2"})

    def test_failed_and_raising_probes_excluded(self):
        candidates = [make_entry("1.1.1.1"), make_entry("2.2.2.2"), make_entry("3.3.3.3")]

        def probe(entry, url, timeout):
            if entry.ip == "1.1.1.1":
                return ProbeResult(ok=False, detail="ProxyError")
            if entry.ip == "2.2.2.2":
                raise RuntimeError("boom")
            return ProbeResult(ok=True, latency_ms=50)

        picked = ip2free.select_working(candidates, max_pick=5, probe=probe)
        self.assertEqual([e.ip for e in picked], ["3.3.3.3"])

    def test_empty_input(self):
        self.assertEqual(ip2free.select_working([], max_pick=3), [])


class FakeClient:
    """假 ip2free 客户端：返回构造时给定的代理列表。"""

    def __init__(self, entries, error=None):
        self.entries = entries
        self.error = error
        self.calls = 0

    def fetch_free_proxies(self, countries=()):
        self.calls += 1
        if self.error:
            raise self.error
        return list(self.entries)


class PoolTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pools = []

    def tearDown(self):
        # 后台刷新线程可能仍在写 .ip2free/，先等它们结束再清理临时目录
        for pool in self.pools:
            pool.wait_idle(timeout=10)

    @property
    def settings(self):
        if getattr(self, "_settings", None) is None:
            self._settings = Ip2FreeSettings(enabled=True, email="a@b.c", password="p", max_pick=2)
        return self._settings

    @settings.setter
    def settings(self, value):
        self._settings = value

    def build(self, client=None, entries=None, probe=None):
        self.client = client or FakeClient(entries or [])
        self.now = getattr(self, "now", [1000.0])
        pool = Ip2FreeProxyPool(
            self.settings,
            state_dir=self.tmp.name,
            client_factory=lambda **kwargs: self.client,
            probe=probe or (lambda entry, url, timeout: ProbeResult(ok=True, latency_ms=10)),
            clock=lambda: self.now[0],
        )
        self.pools.append(pool)
        return pool

    def test_refresh_picks_proxies_and_writes_files(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries=entries)
        working = pool.refresh()
        self.assertEqual([e.ip for e in working], ["1.1.1.1", "2.2.2.2"])
        picked = pool.pick()
        self.assertIn(picked.ip, {"1.1.1.1", "2.2.2.2"})
        self.assertTrue(os.path.isfile(pool.cache_path))
        self.assertTrue(os.path.isfile(pool.proxychains_path))

        with open(pool.cache_path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        self.assertEqual(len(payload["proxies"]), 2)
        self.assertEqual(payload["updated_at"], 1000.0)

    def test_refresh_only_keeps_working_proxies(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]

        def probe(entry, url, timeout):
            return ProbeResult(ok=entry.ip == "2.2.2.2", latency_ms=30)

        pool = self.build(entries=entries, probe=probe)
        pool.refresh()
        self.assertEqual([e.ip for e in pool.proxies], ["2.2.2.2"])
        self.assertEqual(pool.pick().ip, "2.2.2.2")

    def test_pick_excludes_failed_proxy(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries=entries)
        pool.refresh()
        for _ in range(20):
            self.assertEqual(pool.pick(exclude=["1.1.1.1:1080"]).ip, "2.2.2.2")

    def test_pick_randomly_spreads_over_pool(self):
        self.settings = replace(self.settings, max_pick=3)
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2"), make_entry("3.3.3.3")]
        pool = self.build(entries=entries)
        pool.refresh()
        seen = {pool.pick().ip for _ in range(80)}
        self.assertEqual(seen, {"1.1.1.1", "2.2.2.2", "3.3.3.3"})

    def test_pick_fastest_mode_is_stable(self):
        self.settings = replace(self.settings, pick_mode=ip2free.PICK_MODE_FASTEST)

        def probe(entry, url, timeout):
            return ProbeResult(ok=True, latency_ms={"1.1.1.1": 90, "2.2.2.2": 10}[entry.ip])

        pool = self.build(entries=[make_entry("1.1.1.1"), make_entry("2.2.2.2")], probe=probe)
        pool.refresh()
        self.assertEqual({pool.pick().ip for _ in range(10)}, {"2.2.2.2"})

    def test_mark_failed_removes_from_pool(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries=entries)
        pool.refresh()
        pool.mark_failed("1.1.1.1:1080")
        self.assertEqual([e.ip for e in pool.proxies], ["2.2.2.2"])
        for _ in range(10):
            self.assertEqual(pool.pick().ip, "2.2.2.2")

    def test_recheck_drops_dead_proxies(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries=entries)
        pool.refresh()

        def dead_probe(entry, url, timeout):
            return ProbeResult(ok=entry.ip == "1.1.1.1", latency_ms=20)

        pool._probe = dead_probe
        alive = pool.recheck()
        self.assertEqual([e.ip for e in alive], ["1.1.1.1"])
        self.assertEqual([e.ip for e in pool.proxies], ["1.1.1.1"])

    def test_refresh_failure_keeps_previous_pool(self):
        pool = self.build(entries=[make_entry("1.1.1.1")])
        pool.refresh()
        self.client.error = RuntimeError("接口挂了")
        self.assertEqual(pool.refresh(), [])
        self.assertEqual(pool.current.ip, "1.1.1.1")  # 旧缓存保留
        self.assertIn("接口挂了", pool.last_error)

    def test_offline_fallback_reads_proxychains(self):
        conf = os.path.join(self.tmp.name, "offline.conf")
        ip2free.write_proxychains_conf(conf, [make_entry("9.9.9.9", 1080)])
        pool = self.build(client=FakeClient([], error=RuntimeError("no net")))
        pool.offline_conf = conf
        working = pool.refresh()
        self.assertEqual([e.ip for e in working], ["9.9.9.9"])

    def test_cache_loaded_when_fresh(self):
        entries = [make_entry("1.1.1.1")]
        pool = self.build(entries=entries)
        pool.refresh()

        second_client = FakeClient([], error=RuntimeError("不该被调用"))
        pool2 = Ip2FreeProxyPool(
            self.settings,
            state_dir=self.tmp.name,
            client_factory=lambda **kwargs: second_client,
            probe=lambda entry, url, timeout: ProbeResult(ok=True, latency_ms=10),
            clock=lambda: self.now[0] + 60,
        )
        current = pool2.bootstrap()
        self.assertEqual(current.ip, "1.1.1.1")
        self.assertEqual(second_client.calls, 0)

    def test_stale_cache_triggers_refresh(self):
        pool = self.build(entries=[make_entry("1.1.1.1")])
        pool.refresh()
        self.now[0] += self.settings.refresh_minutes * 60 + 1
        self.assertTrue(pool.is_stale())
        rotated = pool.rotate()
        self.assertEqual(rotated.ip, "1.1.1.1")

    def test_rotate_cycles_through_pool(self):
        pool = self.build(entries=[make_entry("1.1.1.1"), make_entry("2.2.2.2")])
        pool.refresh()
        picked = {pool.rotate().ip for _ in range(20)}
        self.assertEqual(picked, {"1.1.1.1", "2.2.2.2"})

    def test_needs_recheck_after_interval(self):
        pool = self.build(entries=[make_entry("1.1.1.1")])
        pool.refresh()
        self.assertFalse(pool.needs_recheck())
        self.now[0] += self.settings.recheck_minutes * 60 + 1
        self.assertTrue(pool.needs_recheck())

    def test_ensure_fresh_background_is_non_blocking(self):
        pool = self.build(entries=[make_entry("1.1.1.1")])
        released = threading.Event()

        def slow_probe(entry, url, timeout):
            released.wait(5)
            return ProbeResult(ok=True, latency_ms=5)

        pool._probe = slow_probe
        self.assertTrue(pool.ensure_fresh(background=True))
        self.assertTrue(pool.is_stale())  # 后台刷新尚未完成，调用方没有被阻塞
        released.set()
        for _ in range(300):
            if pool.current is not None:
                break
            threading.Event().wait(0.01)
        self.assertIsNotNone(pool.current)
        self.assertFalse(pool.is_stale())

    def test_close_clears_pool(self):
        pool = self.build(entries=[make_entry("1.1.1.1")])
        pool.refresh()
        pool.close()
        self.assertIsNone(pool.current)
        self.assertIsNone(pool.rotate())


if __name__ == "__main__":
    unittest.main()
