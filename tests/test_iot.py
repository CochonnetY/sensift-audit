"""IoT 设备三元组识别的回归测试。

起因：用户贴来一段真实设备日志，PK/DN/DS 一个都没扫出来。根因是三类字段名
（含缩写与 C 指针箭头写法）完全不在规则表里，而值是无格式随机串，只能靠字段名定位。

样例是用户日志的同构改写——保留全部难写的字段形态，值换成编造的假值，
避免把用户贴来的疑似真实凭据写进仓库。
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from senscan import report  # noqa: E402
from senscan import utils as U  # noqa: E402
from senscan.detectors import RULES, detect  # noqa: E402
from senscan.models import Risk  # noqa: E402
from senscan.scanner import scan  # noqa: E402

PK = "NFsjvbSelFOzEwWOxSKq"
DN = "xJCLhJSMVwJ22qTh28nC"
DS = "n0W2pGZLdZt5DFnsSp627fEAtVLYR1"

DEVICE_LOG = f"""Device info loaded from config_managerproduct_key: {PK}, device_name: {DN}, device_secret: {DS}, domain_name: , region: CN
===========streamsdk version: 1.7.0.1_81184cda_20261022 ===========
device_msg->product_key: {PK}
device_msg->device_name: {DN}
device_msg->device_secret: {DS}
device_msg->domain_name:
device_msg->region: CN
Using device triplet: PK={PK}, DN={DN}, DS={DS}
\x1b[36;22mI/XOS_IOT_SDK [1970-01-01 01:16:17.904] (xos_iot_device.c:31 setMasterDeviceInfo)set master device info ,device name:{DN}
\x1b[0m
stacksize:524288
"""

TRAPS = [
    ("数据库主键缩写", "INSERT INTO t (id) VALUES (1); PK=12345678, DN=row_0001, DS=shard01"),
    ("LDAP DN", "bind DN=cn=admin,dc=corp,dc=com DS=directory_service"),
    ("磁盘路径", "mount DS=/dev/sda1 PK=/usr/local/bin"),
    ("占位符", "device_secret: your_device_secret_here product_key: XXXXXXXXXXXXXXXXXXXX"),
    ("版本与系统字段", "streamsdk version: 1.7.0.1_81184cda_20261022 stacksize:524288 region: CN"),
    ("SQL AS 别名", "SELECT user_id AS customer_identifier FROM t"),
    ("裸 iot 短词", "[iot watchdog] AS=alias_name_value_here SK=sort_key_order_value"),
    ("孤立缩写无语境", f"boot: DS={DS}"),
    ("值内含 triplet 字样", "boot: DS=isolated_value_without_any_triplet_context"),
]


class TestDeviceTriplet(unittest.TestCase):
    def test_user_reported_log_all_three_entities(self):
        got = detect(DEVICE_LOG, "device.log")
        by_entity = {f.entity: f for f in got}
        self.assertEqual(
            set(by_entity),
            {"IOT_PRODUCT_KEY", "IOT_DEVICE_NAME", "IOT_DEVICE_SECRET"},
        )
        self.assertEqual(by_entity["IOT_PRODUCT_KEY"].value, PK)
        self.assertEqual(by_entity["IOT_DEVICE_NAME"].value, DN)
        self.assertEqual(by_entity["IOT_DEVICE_SECRET"].value, DS)
        self.assertIs(by_entity["IOT_DEVICE_SECRET"].risk, Risk.CRITICAL)

    def test_repeated_values_collapse_to_one_each(self):
        """同一组三元组在日志里出现 4 次，报告里应各只占一行但带出现次数。"""
        got = detect(DEVICE_LOG, "device.log")
        self.assertEqual(len(got), 3)
        for f in got:
            self.assertGreaterEqual(f.occurrences, 3, f.entity)

    def test_field_name_variants(self):
        cases = [
            ("模块名粘连", f"config_managerproduct_key:{PK}"),
            ("C 指针箭头", f"device_msg->device_secret:{DS}"),
            ("空格分隔字段名", f"device name:{DN}"),
            ("冒号后无空格", f"product_key:{PK}"),
            ("驼峰字段名", f'{{"deviceSecret":"{DS}"}}'),
            ("JSON 键值", f'{{"device_name": "{DN}"}}'),
        ]
        for name, text in cases:
            with self.subTest(name=name):
                got = detect(text, "t.log")
                self.assertTrue(got, f"{name} 未命中")
                self.assertIn(got[0].entity,
                              {"IOT_PRODUCT_KEY", "IOT_DEVICE_NAME", "IOT_DEVICE_SECRET"})

    def test_abbreviations_need_triplet_context(self):
        with_ctx = f"Using device triplet: PK={PK}, DN={DN}, DS={DS}"
        got = detect(with_ctx, "t.log")
        self.assertEqual({f.entity for f in got},
                         {"IOT_PRODUCT_KEY", "IOT_DEVICE_NAME", "IOT_DEVICE_SECRET"})
        self.assertEqual(detect(f"boot: DS={DS}", "t.log"), [])

    def test_all_false_positive_traps_clean(self):
        for name, text in TRAPS:
            with self.subTest(name=name):
                got = detect(text + "\n", "t.log")
                iot = [f for f in got if f.entity.startswith("IOT_") or f.rule_id.startswith("iot-")]
                self.assertEqual(iot, [], f"{name} 误报：{[f.rule_id for f in iot]}")

    def test_context_hit_excludes_matched_value(self):
        """通用修复：命中值本身不能充当自己的上下文，否则缩写规则自我提权。"""
        text = "boot: DS=isolated_value_without_any_triplet_context"
        m_start = text.index("isolated_value")
        m_end = len(text)
        self.assertIsNone(U.context_hit(text, m_start, m_end, ("triplet",), 96))
        # 左侧真有关键词时仍然命中
        text2 = "Using device triplet: DS=AAAAAAAAAAAAAAAAAAAA"
        s2 = text2.index("AAAAAAAA")
        self.assertEqual(U.context_hit(text2, s2, len(text2), ("triplet",), 96), "triplet")
        # 规则层面：缩写键名不能出现在自己的语境词表里，否则会自我提权。
        # context_hit 作为通用函数返回左侧键名是正确行为，约束应落在规则定义上。
        from senscan.rules.iot import IOT_RULES
        for r in IOT_RULES:
            if r.id.endswith("-abbrev") or r.id == "iot-cloud-ak-sk-abbrev":
                for bad in ("pk=", "dn=", "ds=", "ak=", "sk=", "as=", "cs=", "tk="):
                    self.assertNotIn(bad, r.context_keywords, f"{r.id} 含自我提权词 {bad}")


class TestTripletConclusion(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.td = tempfile.TemporaryDirectory()
        self.path = Path(self.td.name) / "iot-device.log"
        self.path.write_text(DEVICE_LOG, encoding="utf-8")
        self.result = scan([self.path])

    def tearDown(self):
        self.td.cleanup()

    def test_triplet_marked_on_all_three(self):
        self.assertEqual(len(self.result.iot_triplet_files), 1)
        for f in self.result.findings:
            self.assertTrue(f.extra.get("iot_triplet"), f.entity)
            self.assertIn("三类齐备", " ".join(f.reasons))
        secret = next(f for f in self.result.findings if f.entity == "IOT_DEVICE_SECRET")
        self.assertIn("必须作废凭据本身", secret.remediation)

    def test_partial_triplet_is_not_marked(self):
        """只有 DS 时不能宣称三元组齐备。"""
        only = Path(self.td.name) / "only-secret.log"
        only.write_text(f"device_secret: {DS}\n", encoding="utf-8")
        r = scan([only])
        self.assertEqual(r.iot_triplet_files, [])
        self.assertFalse(any(f.extra.get("iot_triplet") for f in r.findings))

    def test_json_and_html_carry_triplet_conclusion(self):
        payload = report._payload(self.result, False)  # noqa: SLF001
        self.assertEqual(len(payload["summary"]["iot_triplet_files"]), 1)
        from senscan.report_html import write_html
        out = Path(self.td.name) / "r.html"
        write_html(self.result, out, redact=False)
        html = out.read_text(encoding="utf-8")
        self.assertIn("设备三元组完整泄露", html)
        self.assertIn("trip-chip", html)
        # 报告里不能出现未转义的脚本标签
        self.assertNotIn("<script>alert", html)

    def test_rule_catalog_contains_iot_rules(self):
        payload = report._payload(self.result, False)  # noqa: SLF001
        ids = {r["id"] for r in payload["rule_catalog"]}
        self.assertIn("iot-device-secret", ids)
        self.assertIn("iot-triplet-inline", ids)
        self.assertEqual(len(payload["rule_catalog"]), len(RULES))


if __name__ == "__main__":
    unittest.main()
