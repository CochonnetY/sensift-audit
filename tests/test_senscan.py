"""回归测试：python -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from senscan import detectors  # noqa: E402
from senscan.detectors import detect  # noqa: E402
from senscan.models import Risk  # noqa: E402
from senscan.rules import RULES  # noqa: E402
from senscan.scanner import scan  # noqa: E402
from senscan.utils import luhn_valid  # noqa: E402
from senscan.whitelist import Whitelist  # noqa: E402

IMEI = "861234567890127"  # Luhn 校验位已算好


def scan_text(text: str, min_confidence: float = 0.55):
    return detectors.detect(text, "<mem>", min_confidence)


class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_valid(IMEI))
        self.assertFalse(luhn_valid("861234567890128"))

    def test_entropy_threshold(self):
        from senscan.utils import shannon_entropy
        self.assertLess(shannon_entropy("aaaaaaaaaaaaaaaa"), 1.0)
        self.assertGreater(shannon_entropy("Zk8vQ2mNp7Rt4Xy1Bw6Lc9Jd3Hs5Gf0A"), 3.5)


class TestDetection(unittest.TestCase):
    def test_imei_with_context(self):
        got = scan_text(f"2026-11-08 DEBUG [dev] imei={IMEI}\n")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].entity, "IMEI")
        self.assertGreater(got[0].confidence, 0.85)

    def test_imei_luhn_rejected(self):
        self.assertEqual(scan_text("imei=861234567890128\n"), [])

    def test_imei_zero_padded_rejected(self):
        self.assertEqual(scan_text("device_sn=000000000000000\n"), [])

    def test_private_key_header_only(self):
        """仅有 BEGIN 头（截断日志）也应命中，但定级 HIGH：不能排除是文档引用。"""
        got = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
        self.assertEqual(got[0].entity, "PRIVATE_KEY")
        self.assertEqual(got[0].rule_id, "pem-private-key-header")
        self.assertEqual(got[0].risk, Risk.HIGH)

    def test_rtsp_with_urlencoded_password(self):
        got = scan_text("open rtsp://admin:Camera%40123@192.168.1.64:554/s1 now\n")
        self.assertEqual([f.entity for f in got], ["RTSP_CRED"])

    def test_oss_url_keeps_full_signature(self):
        url = ("https://b.oss-cn-hangzhou.aliyuncs.com/a.mp4"
               "?OSSAccessKeyId=LTAI5tAbCdEfGhIjKlMn&Expires=1762500000&Signature=xJ3k%2B9Qz")
        got = [f for f in scan_text(f"upload {url}\n") if f.entity == "OSS_SIGNED_URL"]
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].value.endswith("Signature=xJ3k%2B9Qz"))

    def test_jwt_and_bearer_dedup(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dQw4w9WgXcQ7bKpXz1mNvQ3sT8yL")
        got = scan_text(f"Authorization: Bearer {jwt}\n")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].entity, "TOKEN")

    def test_json_key_value_form(self):
        got = scan_text('{"session_id": "d41f9a2c7b3e8560", "oaid": "5f8c1e2a-9b3d-4c7e-8f10-2a6b9d4e7c31"}\n')
        entities = sorted(f.entity for f in got)
        self.assertEqual(entities, ["OAID", "SESSION_ID"])

    def test_uuid_disambiguated_by_context(self):
        uuid = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"
        got = scan_text(f'{{"idfa": "{uuid}"}}\n')
        self.assertEqual([f.entity for f in got], ["IDFA"])


class TestNoiseSuppression(unittest.TestCase):
    """这些是真实日志里最常见的假阳性来源。"""

    def assertClean(self, text: str):
        got = scan_text(text)
        self.assertEqual(got, [], f"误报: {[(f.entity, f.value) for f in got]}")

    def test_bare_uuid(self):
        self.assertClean("request_id=9b2e4c7a-3d18-4f6b-a2c9-7e1f5b8d0a34\n")

    def test_bare_sha1(self):
        self.assertClean("build sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709\n")

    def test_broadcast_mac(self):
        self.assertClean("dst mac=ff:ff:ff:ff:ff:ff\n")

    def test_ipv6(self):
        self.assertClean("peer=2001:0db8:85a3:0000:0000:8a2e:0370:7334\n")

    def test_timestamp(self):
        self.assertClean("elapsed=1699512345678 ms\n")

    def test_placeholder_token(self):
        self.assertClean("token=example-token-for-docs\n")

    def test_masked_password(self):
        self.assertClean("password=********\n")

    def test_time_like_mac(self):
        self.assertClean("retry backoff 00:00:05, 00:00:10\n")

    def test_version_like_dotted_mac(self):
        """Cisco 点分格式误伤固件构建号：设备日志实测样本。"""
        for line in (
            "fw_version=2026.1029.0000 gpio_level=TDDEen (ALO_MSG_M)\n",
            "build 2025.1124.0000 r_enableHDR enable set enable=0;\n",
            "version: 2024.0101.0000, region CN\n",
        ):
            with self.subTest(line=line):
                self.assertClean(line)

    def test_real_dotted_mac_needs_context(self):
        """真点分 MAC 有地址上下文仍要能报出来，且不能标成「已校验」。"""
        got = scan_text("bssid=0011.2233.4455 assoc ok\n")
        self.assertEqual([f.entity for f in got], ["MAC"])
        self.assertNotEqual(got[0].validation, "checksum")
        self.assertClean("build 0011.2233.4455 finished\n")

    def test_colon_mac_without_context(self):
        got = scan_text("peer=00:1a:2b:3c:4d:5e\n")
        self.assertEqual([f.entity for f in got], ["MAC"])
        self.assertEqual(got[0].validation, "format")


class TestEndToEnd(unittest.TestCase):
    SAMPLES = ROOT / "demo" / "samples"

    def test_traps_file_is_clean(self):
        p = self.SAMPLES / "traps.log"
        if not p.exists():
            self.skipTest("样本未生成，先跑 python demo/make_demo.py")
        r = scan([p])
        self.assertEqual(len(r.findings), 0, [(f.entity, f.value) for f in r.findings])

    def test_full_scan_recall(self):
        if not self.SAMPLES.exists():
            self.skipTest("样本未生成")
        r = scan([self.SAMPLES])
        entities = {f.entity for f in r.findings}
        expected = {
            "PRIVATE_KEY", "API_KEY", "TOKEN", "PASSWORD", "RTSP_CRED",
            "OSS_SIGNED_URL", "SESSION_ID", "IMEI", "OAID", "IDFA", "LTK",
            "CERT_FINGERPRINT",
        }
        self.assertEqual(expected - entities, set())

    def _saas_sample(self) -> Path:
        """saas.log 是生成产物且不入库；缺失时直接取生成器模板写到临时目录。"""
        p = self.SAMPLES / "saas.log"
        if p.exists():
            return p
        import importlib.util
        import shutil
        spec = importlib.util.spec_from_file_location(
            "_senscan_demo_v2", ROOT / "demo" / "make_demo_v2.py")
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tmpdir = Path(tempfile.mkdtemp(prefix="senscan-saas-"))
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        q = tmpdir / "saas.log"
        q.write_text(mod.SAAS_LOG, encoding="utf-8")
        return q

    def test_v2_sample_recall(self):
        """扩充样本：国际 SaaS / 国内云 / 连接串 / PII 全部要命中。"""
        p = self._saas_sample()
        r = scan([p])
        entities = {f.entity for f in r.findings}
        expected = {
            "API_KEY", "PASSWORD", "DB_CREDENTIAL",
            "ID_CARD", "BANK_CARD", "PHONE", "EMAIL", "ICCID", "IMSI", "DEVICE_SN",
        }
        self.assertEqual(expected - entities, set(), f"漏报: {expected - entities}")
        # 关键规则逐一确认（防止被同值合并吞掉）
        rules = {f.rule_id for f in r.findings}
        for rid in (
            "stripe-key", "aws-access-key-id", "aws-secret-access-key", "github-pat",
            "slack-webhook", "telegram-bot-token", "sendgrid-token", "npm-token",
            "wechat-app-secret", "db-uri-credential", "jdbc-credential", "http-basic-uri",
            "azure-storage-account-key", "aliyun-access-key-secret", "basic-auth-header",
            "cn-id-card", "bank-card", "cn-mobile", "iccid", "imsi", "device-serial",
        ):
            self.assertIn(rid, rules, f"规则 {rid} 未命中")

    def test_pii_traps_clean(self):
        p = self.SAMPLES / "traps-pii.log"
        if not p.exists():
            self.skipTest("样本未生成")
        r = scan([p])
        self.assertEqual(r.findings, [], [(f.entity, f.rule_id) for f in r.findings])

    def test_pcap_channel(self):
        from senscan import pcap as pcapmod
        p = self.SAMPLES / "track.pcap"
        if not p.exists():
            self.skipTest("pcap 样本未生成，先跑 python demo/make_pcap.py")
        if pcapmod.tshark_path() is None:
            self.skipTest("未安装 tshark")
        r = scan([p])
        entities = {f.entity for f in r.findings}
        self.assertTrue(
            {"API_KEY", "TOKEN", "IMEI", "OAID", "SESSION_ID", "PASSWORD"} <= entities,
            f"pcap 漏报，实际: {sorted(entities)}",
        )
        self.assertTrue(all(f.extra.get("frame") == 1 for f in r.findings))

    def test_whitelist(self):
        if not self.SAMPLES.exists():
            self.skipTest("样本未生成")
        wl_path = ROOT / "demo" / "wl.txt"
        wl = Whitelist.from_file(wl_path) if wl_path.exists() else None
        if wl is None:
            self.skipTest("白名单样本不存在")
        r = scan([self.SAMPLES], whitelist=wl)
        self.assertGreater(r.stats.whitelisted, 0)
        self.assertFalse([f for f in r.findings if f.entity == "MAC"])

    def test_progress_callback_and_cancel(self):
        """进度回调供工作台显示第几个文件；返回 False 可协作式中止。"""
        from senscan.scanner import ScanCancelled

        if not self.SAMPLES.exists():
            self.skipTest("样本未生成")
        seen: list[tuple[int, int]] = []

        def cb(done: int, total: int, path):
            seen.append((done, total))
            return done < 2

        with self.assertRaises(ScanCancelled):
            scan([self.SAMPLES], on_progress=cb)
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0][0], 1)
        self.assertGreaterEqual(seen[0][1], 2)


class TestHtmlReport(unittest.TestCase):
    def test_escapes_hostile_values(self):
        import tempfile

        from senscan.models import Finding, Risk
        from senscan.report_html import write_html
        from senscan.scanner import ScanResult, ScanStats

        f = Finding(
            entity="TOKEN", value="<script>alert(1)</script>", risk=Risk.HIGH,
            confidence=0.9, rule_id="x", source='C:/a"b.log', offset=0, line=1, column=1,
            context="<img src=x onerror=alert(1)>", reasons=(),
            normalized="", occurrences=1, extra={},
        )
        res = ScanResult(
            findings=[f], stats=ScanStats(files_scanned=1), targets=["<x>"],
            started_at="2026-11-09T00:00:00", duration_ms=1, min_confidence=0.5,
        )
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.html"
            write_html(res, out)
            doc = out.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", doc)
        self.assertNotIn("<img src=x", doc)
        self.assertIn("&lt;script&gt;", doc)
        self.assertIn("&lt;img", doc)
        self.assertIn("<!DOCTYPE html>", doc)
        # 口径说明折叠收起、明细只留「详情」入口：正文默认不刷屏
        self.assertIn('<details class="notes">', doc)
        self.assertIn("<summary>详情</summary>", doc)


class TestValidatorsV2(unittest.TestCase):
    """v2 扩充的校验算法。"""

    def test_id_card(self):
        from senscan.utils import cn_id_check_digit, cn_id_card_valid
        body = "11010519491231002"
        card = body + cn_id_check_digit(body)
        self.assertTrue(cn_id_card_valid(card))
        self.assertTrue(cn_id_card_valid(card.lower()))
        self.assertFalse(cn_id_card_valid("110105194912310021"))  # 校验位错
        self.assertFalse(cn_id_card_valid("11010519991331002X"))  # 日期非法

    def test_mobile(self):
        from senscan.utils import cn_mobile_valid
        self.assertTrue(cn_mobile_valid("13912345678"))
        self.assertFalse(cn_mobile_valid("13800138000"))  # 经典假号
        self.assertFalse(cn_mobile_valid("12345678901"))  # 号段不存在
        self.assertFalse(cn_mobile_valid("12800001111"))  # 号段不存在

    def test_bank_card_vs_imei(self):
        from senscan.utils import bank_card_valid
        # 15 位非 AMEX 必须拒绝（否则与 IMEI 互撞）
        self.assertFalse(bank_card_valid("411111111111111"))  # 15 位 visa 形态
        # 16 位合法卡号（程序生成）
        from senscan.utils import luhn_check_digit
        card = "622202314589647" + luhn_check_digit("622202314589647")
        self.assertTrue(bank_card_valid(card))

    def test_jwt_decodable(self):
        from senscan.utils import jwt_decodable
        good = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        self.assertTrue(jwt_decodable(good))
        self.assertFalse(jwt_decodable("eyJub3RfYWxnX2hlcmU.abcdef.ghijkl"))

    def test_basic_auth(self):
        import base64

        from senscan.utils import basic_auth_is_pair
        real = base64.b64encode(b"svc-report:Xk7#mP2$vQ9").decode()
        fake = base64.b64encode(b"user:password").decode()
        self.assertTrue(basic_auth_is_pair(real))
        self.assertFalse(basic_auth_is_pair(fake))  # 文档示例

    def test_cred_uri(self):
        from senscan.utils import cred_uri_ok
        self.assertTrue(cred_uri_ok("mysql://appuser:Tr0ub4dor&3@10.20.30.40:3306/orders"))
        self.assertFalse(cred_uri_ok("mysql://user:password@localhost:3306/test"))
        self.assertFalse(cred_uri_ok("mysql://root:changeme@db.internal/app"))

    def test_email(self):
        from senscan.utils import email_ok
        self.assertTrue(email_ok("wang.wu@example-corp.com.cn"))
        self.assertFalse(email_ok("3@10.20.30.40"))     # 连接串片段
        self.assertFalse(email_ok("logo@2x.png"))       # 静态资源
        self.assertFalse(email_ok("a@b@example.com"))   # 示例域

    def test_email_not_from_uri(self):
        """连接串里的凭据片段不能被报成邮箱。"""
        got = detect("mysql://appuser:Tr0ub4dor&3@10.20.30.40:3306/orders", "t")
        self.assertEqual([f.entity for f in got], ["DB_CREDENTIAL"])


class TestPrioritiesAndValidation(unittest.TestCase):
    def test_pem_priority(self):
        got = detect("-----BEGIN RSA PRIVATE KEY-----\n" + ("QUJDreGF7hK2mNp9sXvB4wLz8qYdJ6cT3fRgUh5kW2nEe9aZb4Cx7VhM2kPq8Ld" + "Ax9KmP3vR7sT2wYzC5bN8jF1hD4gK6mQe") + "\n-----END RSA PRIVATE KEY-----", "t")
        self.assertEqual(got[0].priority, "P0")
        self.assertEqual(got[0].validation, "checksum")

    def test_no_duplicate_pem(self):
        """完整私钥块只应出一条，BEGIN 头规则要被子串去重吞掉。"""
        text = "-----BEGIN RSA PRIVATE KEY-----\n" + ("QUJDreGF7hK2mNp9sXvB4wLz8qYdJ6cT3fRgUh5kW2nEe9aZb4Cx7VhM2kPq8Ld" + "Ax9KmP3vR7sT2wYzC5bN8jF1hD4gK6mQe") + "\n-----END RSA PRIVATE KEY-----"
        got = detect(text, "t")
        self.assertEqual(len(got), 1)

    def test_jdbc_password_subsumed(self):
        got = detect("jdbc:mysql://10.20.30.40:3306/oms?useSSL=false&password=Hk93mXq7Lw2d", "t")
        self.assertEqual(len(got), 1, [(f.entity, f.rule_id) for f in got])
        self.assertEqual(got[0].rule_id, "jdbc-credential")

    def test_cross_entity_uuid_collapse(self):
        text = 'oaid="5f8c1e2a-9b3d-4c7e-8f10-2a6b9d4e7c31"'
        got = detect(text, "t")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].entity, "OAID")

    def test_validators_registry_complete(self):
        """规则表里引用的校验器必须都存在，防止拼错名字静默失效。"""
        from senscan.detectors import VALIDATORS
        from senscan.rules import RULES
        for r in RULES:
            for v in (*r.validators, *r.bonus_validators):
                self.assertIn(v, VALIDATORS, f"{r.id} 引用了不存在的校验器 {v}")


class TestReportsV2(unittest.TestCase):
    def _result(self):
        got = detect(
            "aws_secret_access_key = " + "aB3dEf7hJk9lMn2pQr4sTv6wXy8zA1bC" + "\n"
            "imei=356938035643809",
            "t.log",
        )
        return got

    def test_json_summary_fields(self):
        from senscan.scanner import ScanResult, ScanStats
        from senscan.report import _payload
        res = ScanResult(
            findings=self._result(),
            stats=ScanStats(),
            targets=["t"],
            started_at="now",
            duration_ms=1,
            min_confidence=0.55,
        )
        p = _payload(res, False)
        for key in ("by_category", "by_priority", "by_validation", "by_file", "spread_values"):
            self.assertIn(key, p["summary"])
        self.assertEqual(len(p["rule_catalog"]), len(RULES))
        self.assertIn("suppressed_no_context", p["stats"])

    def test_sarif_security_severity(self):
        from senscan.scanner import ScanResult, ScanStats
        from senscan.report import write_sarif
        res = ScanResult(
            findings=self._result(),
            stats=ScanStats(),
            targets=["t"],
            started_at="now",
            duration_ms=1,
            min_confidence=0.55,
        )
        out = Path(tempfile.mkdtemp()) / "r.sarif"
        write_sarif(res, out)
        s = json.loads(out.read_text(encoding="utf-8"))
        run = s["runs"][0]
        self.assertTrue(all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"]))
        self.assertTrue(all("rank" in r for r in run["results"]))

    def test_csv_columns(self):
        from senscan.report import CSV_HEADER
        for col in ("priority", "category", "validation", "remediation"):
            self.assertIn(col, CSV_HEADER)


if __name__ == "__main__":
    unittest.main(verbosity=2)
