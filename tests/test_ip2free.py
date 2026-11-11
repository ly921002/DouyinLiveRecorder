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
BlockResult = ip2free.BlockResult


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

    def build(self, client=None, entries=None, probe=None, block_probe=None):
        self.client = client or FakeClient(entries or [])
        self.now = getattr(self, "now", [1000.0])
        pool = Ip2FreeProxyPool(
            self.settings,
            state_dir=self.tmp.name,
            client_factory=lambda **kwargs: self.client,
            probe=probe or (lambda entry, url, timeout: ProbeResult(ok=True, latency_ms=10)),
            block_probe=block_probe or (lambda entry, platforms, timeout: {}),
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

    def test_refresh_api_failure_keeps_working_old_credentials(self):
        """接口挂了但旧凭证仍可用时，旧凭证必须继续生效（旧行为会返回空）。"""
        pool = self.build(entries=[make_entry("1.1.1.1", username="old", password="oldpw")])
        pool.refresh()
        self.client.error = RuntimeError("接口挂了")
        working = pool.refresh()
        self.assertEqual([e.ip for e in working], ["1.1.1.1"])
        self.assertEqual(pool.current.username, "old")  # 旧凭证未被清掉
        self.assertIn("接口挂了", pool.last_error)

    def test_refresh_drops_dead_old_credentials_when_api_fails(self):
        """接口挂了且旧凭证也实测失效时，明确舍弃，不留死凭证在池里。"""
        pool = self.build(entries=[make_entry("1.1.1.1", username="old")])
        pool.refresh()
        self.client.error = RuntimeError("接口挂了")
        pool._probe = lambda entry, url, timeout: ProbeResult(ok=False)
        self.assertEqual(pool.refresh(), [])
        self.assertEqual(pool.proxies, [])

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

    # ---------------- 凭证粘性 ----------------

    def test_refresh_keeps_working_old_credentials_over_new(self):
        """接口换了同节点账号密码，但旧凭证仍可用 -> 必须继续用旧的。"""
        old = make_entry("1.1.1.1", 1080, username="olduser", password="oldpass")
        new = make_entry("1.1.1.1", 1080, username="newuser", password="newpass")
        pool = self.build(entries=[old])
        pool.refresh()
        self.assertEqual(pool.proxies[0].username, "olduser")

        self.client.entries = [new]
        # 探测只认旧凭证；若实现误用了新凭证就会直接测速失败
        pool._probe = lambda entry, url, timeout: ProbeResult(
            ok=entry.username == "olduser", latency_ms=25
        )
        pool.refresh()
        self.assertEqual([e.username for e in pool.proxies], ["olduser"])
        self.assertEqual(pool.current.username, "olduser")
        self.assertEqual(pool.proxies[0].latency_ms, 25)

    def test_refresh_accepts_new_credential_only_when_old_is_dead(self):
        """旧凭证实测失效时，才接纳同节点的新凭证。"""
        old = make_entry("1.1.1.1", 1080, username="olduser")
        new = make_entry("1.1.1.1", 1080, username="newuser")
        pool = self.build(entries=[old])
        pool.refresh()

        self.client.entries = [new]
        pool._probe = lambda entry, url, timeout: ProbeResult(
            ok=entry.username == "newuser", latency_ms=30
        )
        pool.refresh()
        self.assertEqual([e.username for e in pool.proxies], ["newuser"])

    def test_refresh_drops_node_when_both_credentials_dead(self):
        """旧凭证和新凭证都不可用 -> 节点被舍弃。"""
        old = make_entry("1.1.1.1", 1080, username="olduser")
        new = make_entry("1.1.1.1", 1080, username="newuser")
        pool = self.build(entries=[old])
        pool.refresh()

        self.client.entries = [new]
        pool._probe = lambda entry, url, timeout: ProbeResult(ok=False)
        self.assertEqual(pool.refresh(), [])
        self.assertEqual(pool.proxies, [])

    def test_refresh_keeps_delisted_node_with_working_old_credential(self):
        """接口已下线该节点，但旧凭证仍可用 -> 继续保留，不因列表变化被清掉。"""
        old = make_entry("1.1.1.1", 1080, username="olduser")
        pool = self.build(entries=[old])
        pool.refresh()

        self.client.entries = [make_entry("2.2.2.2", 1080, username="fresh")]
        pool._probe = lambda entry, url, timeout: ProbeResult(ok=True, latency_ms=20)
        pool.refresh()
        keys = {e.key for e in pool.proxies}
        self.assertIn("1.1.1.1:1080", keys)
        self.assertEqual(
            next(e.username for e in pool.proxies if e.ip == "1.1.1.1"), "olduser"
        )

    def test_refresh_adds_new_nodes_alongside_sticky_ones(self):
        """保留旧凭证的同时，接口里的全新节点也要能加进来。"""
        self.settings = replace(self.settings, max_pick=3)
        old = make_entry("1.1.1.1", 1080, username="olduser")
        pool = self.build(entries=[old])
        pool.refresh()

        self.client.entries = [
            make_entry("1.1.1.1", 1080, username="newuser"),
            make_entry("2.2.2.2", 1080, username="fresh"),
        ]
        pool._probe = lambda entry, url, timeout: ProbeResult(ok=True, latency_ms=15)
        pool.refresh()
        by_ip = {e.ip: e.username for e in pool.proxies}
        self.assertEqual(by_ip.get("1.1.1.1"), "olduser")
        self.assertEqual(by_ip.get("2.2.2.2"), "fresh")

    def test_sticky_credentials_survive_restart(self):
        """可用旧凭证写进缓存，重启后仍用它，且不被接口新凭证覆盖。"""
        old = make_entry("1.1.1.1", 1080, username="olduser", password="pw")
        pool = self.build(entries=[old])
        pool.refresh()
        pool._probe = lambda entry, url, timeout: ProbeResult(
            ok=entry.username == "olduser", latency_ms=12
        )
        pool.recheck()  # 触发落盘
        pool.wait_idle(timeout=5)

        new_client = FakeClient([make_entry("1.1.1.1", 1080, username="newuser")])
        pool2 = Ip2FreeProxyPool(
            self.settings,
            state_dir=self.tmp.name,
            client_factory=lambda **kwargs: new_client,
            probe=lambda entry, url, timeout: ProbeResult(
                ok=entry.username == "olduser", latency_ms=12
            ),
            clock=lambda: self.now[0],
        )
        self.pools.append(pool2)
        current = pool2.bootstrap()
        self.assertEqual(current.username, "olduser")
        pool2.refresh()
        self.assertEqual([e.username for e in pool2.proxies], ["olduser"])

    def test_mark_failed_with_full_url_discards_credential(self):
        """main.py 传的是完整 socks5h 连接串，必须能正确归一并舍弃。"""
        entry = make_entry("1.1.1.1", 1080, username="olduser", password="pw")
        pool = self.build(entries=[entry])
        pool.refresh()
        pool.mark_failed(entry.url)
        self.assertEqual(pool.proxies, [])
        # 落盘后重启也不会把已舍弃的凭证读回来
        pool3 = Ip2FreeProxyPool(
            self.settings, state_dir=self.tmp.name,
            client_factory=lambda **kwargs: FakeClient([]),
            probe=lambda e, u, t: ProbeResult(ok=True), clock=lambda: self.now[0],
        )
        self.pools.append(pool3)
        pool3._load_cache()
        self.assertEqual(pool3.proxies, [])

    def test_pick_exclude_accepts_full_url(self):
        pool = self.build(entries=[make_entry("1.1.1.1"), make_entry("2.2.2.2")])
        pool.refresh()
        excluded = make_entry("1.1.1.1").url
        for _ in range(20):
            self.assertEqual(pool.pick(exclude=[excluded]).ip, "2.2.2.2")

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


class BlockProbeParseTestCase(unittest.TestCase):
    """平台封禁探测配置解析。"""

    def test_aliases_and_disable(self):
        self.assertEqual(ip2free._parse_block_probes("pandatv"), ("pandatv",))
        self.assertEqual(ip2free._parse_block_probes("PandaTV"), ("pandatv",))
        self.assertEqual(ip2free._parse_block_probes("熊猫"), ("pandatv",))
        self.assertEqual(ip2free._parse_block_probes("pandatv，熊猫"), ("pandatv",))
        self.assertEqual(ip2free._parse_block_probes(""), ())
        self.assertEqual(ip2free._parse_block_probes(None), ())
        self.assertEqual(ip2free._parse_block_probes("unknown"), ())

    def test_settings_reads_option(self):
        values = {"ip2free平台封禁探测": "pandatv"}
        settings = Ip2FreeSettings.from_reader(
            lambda s, o, d: values.get(o, d), environ={}
        )
        self.assertEqual(settings.block_probes, ("pandatv",))

    def test_settings_default_enables_panda(self):
        settings = Ip2FreeSettings.from_reader(lambda s, o, d: d, environ={})
        self.assertEqual(settings.block_probes, (ip2free.DEFAULT_BLOCK_PROBES,))


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeClientCtx:
    """模拟 httpx.Client 的上下文管理器，用于探测函数单测。"""

    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, *args, **kwargs):
        return self._response

    def get(self, *args, **kwargs):
        return self._response


class PandaBlockProbeTestCase(unittest.TestCase):
    """PandaTV 封禁判定：优先结构化字段，网络异常不误判。"""

    def probe(self, status_code, body):
        factory = lambda url, timeout: FakeClientCtx(FakeResponse(status_code, body))
        return ip2free.probe_pandatv_block("socks5h://u:p@1.1.1.1:1080",
                                           timeout=5, client_factory=factory)

    def test_detects_block_via_error_data_code(self):
        body = ('{"result":false,"message":"\\uc81c\\uc7ac\\ub41c \\uc544\\uc774\\ud53c\\uc785\\ub2c8'
                '\\ub2e4.","errorData":{"code":"block"},"userIp":"1.1.1.1"}')
        result = self.probe(403, body)
        self.assertTrue(result.blocked)
        self.assertEqual(result.platform, "pandatv")
        self.assertIn("block", result.detail)

    def test_detects_block_with_spaced_json(self):
        body = '{"errorData": {"code": "block"}, "message": "blocked"}'
        self.assertTrue(self.probe(403, body).blocked)

    def test_detects_block_via_korean_text(self):
        self.assertTrue(self.probe(403, '{"message":"제재된 아이피입니다."}').blocked)

    def test_healthy_response_not_blocked(self):
        body = '{"result":true,"PlayList":{"hls":[{"url":"https://x/y.m3u8"}]}}'
        result = self.probe(200, body)
        self.assertFalse(result.blocked)

    def test_user_not_found_is_not_block(self):
        body = '{"result":false,"message":"유저 정보가 없습니다.","userIp":"1.1.1.1"}'
        self.assertFalse(self.probe(400, body).blocked)

    def test_network_error_is_not_block(self):
        def boom(url, timeout):
            raise ConnectionError("timed out")

        result = ip2free.probe_pandatv_block("socks5h://1.1.1.1:1080", 5, client_factory=boom)
        self.assertFalse(result.blocked)
        self.assertIn("ConnectionError", result.detail)


class BlockFilteringTestCase(unittest.TestCase):
    """被封禁的代理要和连不上一样被舍弃，并切换其他代理。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pools = []

    def tearDown(self):
        for pool in self.pools:
            pool.wait_idle(timeout=10)

    def build(self, entries, blocked_ips=(), settings=None):
        settings = settings or Ip2FreeSettings(
            enabled=True, email="a@b.c", password="p", max_pick=5
        )

        def block_probe(entry, platforms, timeout):
            self.assertIn("pandatv", platforms)
            if entry.ip in blocked_ips:
                return {"pandatv": BlockResult(True, "pandatv", "HTTP 403 errorData.code=block")}
            return {"pandatv": BlockResult(False, "pandatv", "HTTP 200")}

        self.client = FakeClient(entries)
        pool = Ip2FreeProxyPool(
            settings,
            state_dir=self.tmp.name,
            client_factory=lambda **kwargs: self.client,
            probe=lambda e, u, t: ProbeResult(ok=True, latency_ms=10),
            block_probe=block_probe,
            clock=lambda: 1000.0,
        )
        self.pools.append(pool)
        return pool

    def test_blocked_proxy_is_dropped_on_refresh(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries, blocked_ips={"1.1.1.1"})
        working = pool.refresh()
        self.assertEqual([e.ip for e in working], ["2.2.2.2"])
        self.assertEqual([e.ip for e in pool.proxies], ["2.2.2.2"])

    def test_blocked_proxy_is_dropped_on_recheck(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries, blocked_ips=set())
        pool.refresh()
        self.assertEqual(len(pool.proxies), 2)
        # 第二次复检时 2.2.2.2 被封
        pool._block_probe = lambda e, p, t: (
            {"pandatv": BlockResult(True, "pandatv", "block")} if e.ip == "2.2.2.2"
            else {"pandatv": BlockResult(False, "pandatv", "ok")}
        )
        alive = pool.recheck()
        self.assertEqual([e.ip for e in alive], ["1.1.1.1"])

    def test_pick_never_returns_blocked_proxy(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries, blocked_ips={"1.1.1.1"})
        pool.refresh()
        for _ in range(30):
            self.assertEqual(pool.pick().ip, "2.2.2.2")

    def test_blocked_info_records_reason(self):
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries, blocked_ips={"1.1.1.1"})
        pool.refresh()
        info = pool.blocked_info()
        self.assertIn("1.1.1.1:1080", info)
        self.assertIn("pandatv", info["1.1.1.1:1080"])

    def test_blocked_proxy_not_reprobed_on_next_refresh(self):
        """核心诉求：舍弃后就不再复用，也不重复刷同样的 WARNING。"""
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        calls = []

        def counting_probe(entry, platforms, timeout):
            calls.append(entry.ip)
            if entry.ip == "1.1.1.1":
                return {"pandatv": BlockResult(True, "pandatv", "HTTP 403 errorData.code=block")}
            return {"pandatv": BlockResult(False, "pandatv", "HTTP 200")}

        pool = self.build(entries, blocked_ips=set(), settings=Ip2FreeSettings(
            enabled=True, email="a@b.c", password="p", max_pick=5))
        pool._block_probe = counting_probe

        pool.refresh()
        self.assertEqual(sorted(calls), ["1.1.1.1", "2.2.2.2"])  # 首次两条都要探测
        self.assertEqual([e.ip for e in pool.proxies], ["2.2.2.2"])

        calls.clear()
        pool.refresh()   # 第二次刷新：1.1.1.1 已在封禁名单，不应再被探测
        self.assertNotIn("1.1.1.1", calls)
        self.assertEqual([e.ip for e in pool.proxies], ["2.2.2.2"])

    def test_blocked_record_persists_across_restart(self):
        """封禁名单落盘，重启后也不复用。"""
        entries = [make_entry("1.1.1.1"), make_entry("2.2.2.2")]
        pool = self.build(entries, blocked_ips={"1.1.1.1"}, settings=Ip2FreeSettings(
            enabled=True, email="a@b.c", password="p", max_pick=5))
        pool.refresh()
        pool.wait_idle(timeout=5)
        self.assertTrue(os.path.isfile(pool.blocked_path))

        probed = []
        pool2 = Ip2FreeProxyPool(
            pool.settings, state_dir=self.tmp.name,
            client_factory=lambda **kwargs: FakeClient(entries),
            probe=lambda e, u, t: ProbeResult(ok=True, latency_ms=10),
            block_probe=lambda e, p, t: (probed.append(e.ip) or {
                "pandatv": BlockResult(True, "pandatv", "block")}),
            clock=lambda: 1000.0,
        )
        self.pools.append(pool2)
        pool2._load_blocked()
        self.assertIn("1.1.1.1:1080", pool2.blocked_info())
        pool2.refresh()
        self.assertNotIn("1.1.1.1", probed)   # 重启后仍不复用

    def test_block_record_expires_after_ttl(self):
        """封禁不是永久的：超过有效期后允许重新探测。"""
        entries = [make_entry("1.1.1.1")]
        now = [1000.0]
        pool = self.build(entries, blocked_ips={"1.1.1.1"}, settings=Ip2FreeSettings(
            enabled=True, email="a@b.c", password="p", max_pick=5, block_ttl_hours=1))
        pool._clock = lambda: now[0]
        pool.refresh()
        self.assertEqual(pool.proxies, [])

        probed = []
        pool._block_probe = lambda e, p, t: (probed.append(e.ip) or {
            "pandatv": BlockResult(False, "pandatv", "ok")})
        now[0] += 2 * 3600      # 超过 1 小时有效期
        pool.refresh()
        self.assertIn("1.1.1.1", probed)
        self.assertEqual([e.ip for e in pool.proxies], ["1.1.1.1"])

    def test_block_probe_disabled_keeps_proxy(self):
        settings = Ip2FreeSettings(
            enabled=True, email="a@b.c", password="p", max_pick=5, block_probes=()
        )
        entries = [make_entry("1.1.1.1")]
        pool = self.build(entries, blocked_ips={"1.1.1.1"}, settings=settings)
        self.assertEqual([e.ip for e in pool.refresh()], ["1.1.1.1"])

    def test_block_probe_exception_does_not_drop_proxy(self):
        """探测本身异常时按未封禁处理，避免误杀。"""
        def broken(entry, platforms, timeout):
            raise RuntimeError("probe crashed")

        entries = [make_entry("1.1.1.1")]
        settings = Ip2FreeSettings(enabled=True, email="a@b.c", password="p", max_pick=5)
        pool = Ip2FreeProxyPool(
            settings, state_dir=self.tmp.name,
            client_factory=lambda **kwargs: FakeClient(entries),
            probe=lambda e, u, t: ProbeResult(ok=True, latency_ms=10),
            block_probe=broken, clock=lambda: 1000.0,
        )
        self.pools.append(pool)
        # 让异常发生在封禁探测内部（模拟单一平台探测失败）
        pool._block_probe = lambda e, p, t: ip2free.probe_platform_blocks(
            e, p, 5, probe_funcs={"pandatv": lambda proxy, timeout: (_ for _ in ()).throw(RuntimeError("x"))}
        )
        self.assertEqual([e.ip for e in pool.refresh()], ["1.1.1.1"])


if __name__ == "__main__":
    unittest.main()
