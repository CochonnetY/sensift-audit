"""安全加固与检测正确性回归测试（2026-11-10 代码审查发现的问题）。

每条都对应一个可复现的缺陷，防止后续改动把修复冲掉。
"""

from __future__ import annotations

import base64
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from senscan import pcap, report, scanner, utils as U, verify as V, webui
from senscan.detectors import detect


def _finding(**kw):
    base = dict(
        priority="P0", risk=SimpleNamespace(value="critical", order=0), risk_score=9,
        confidence=0.9, validation="checksum", category="credential", entity="API_KEY",
        rule_id="unit", value="abc", occurrences=1, source="x.log", line=1, column=1,
        remediation="轮换", reasons=("规则 unit",), context="ctx", extra={},
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestVerifyRobustness(unittest.TestCase):
    def test_millisecond_timestamp_does_not_crash(self):
        # 13 位毫秒时间戳曾让 datetime.fromtimestamp 抛 OSError，整次 scan 结果全丢
        self.assertEqual(V._expiry_result(1762586400000).status, V.EXPIRED)
        self.assertEqual(V._expiry_result(999999999999999999).status, V.UNKNOWN)
        self.assertEqual(V._expiry_result(0).status, V.UNKNOWN)

    def test_jwt_millisecond_exp_does_not_crash(self):
        tok = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NjI1ODY0MDAwMDB9.c2ln"
        self.assertEqual(V._jwt_check(tok).status, V.EXPIRED)

    def test_local_check_failure_is_isolated(self):
        # 单条畸形值不能让整次验证/扫描崩溃
        bad = _finding(entity="OSS_SIGNED_URL", rule_id="signed-url-cos",
                       value="https://x/a?q-sign-time=1;99999999999999999999")
        summary = V.run([bad], V.VerifyConfig(local=True, online=False))
        self.assertGreaterEqual(summary.local_checked, 1)

    def test_custom_endpoint_public_host_requires_allowlist(self):
        cfg = V.VerifyConfig(online=True, custom=({"url": "https://attacker.example.com/c"},))
        with self.assertRaises(V.VerifyPolicyError):
            cfg.validate()
        V.VerifyConfig(online=True,
                       custom=({"url": "https://verify.corp.internal/c"},)).validate()
        V.VerifyConfig(online=True, custom_hosts=("attacker.example.com",),
                       custom=({"url": "https://attacker.example.com/c"},)).validate()

    def test_process_level_throttle_ceiling(self):
        saved = dict(V._THROTTLE)
        try:
            V._THROTTLE["count"] = V.GLOBAL_MAX_ONLINE_PER_MIN
            V._THROTTLE["window"] = __import__("time").time()
            self.assertFalse(V._throttle(0.0))
        finally:
            V._THROTTLE.update(saved)


class TestOutputSafety(unittest.TestCase):
    def test_csv_formula_injection_is_neutralized(self):
        f = _finding(value='=HYPERLINK("http://evil","click")', context="=1+1")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.csv"
            report.write_csv(SimpleNamespace(findings=[f]), p)
            body = p.read_text(encoding="utf-8-sig")
        self.assertIn("'=HYPERLINK", body)
        self.assertIn("'=1+1", body)

    def test_pcap_nonzero_exit_is_not_silent(self):
        class FakeProc:
            stdout = io.StringIO("")
            stderr = io.StringIO("bad pcap")
            returncode = 2

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                pass

        with patch.object(pcap.subprocess, "Popen", return_value=FakeProc()), \
             patch.object(pcap.shutil, "which", return_value="tshark"):
            with self.assertRaises(RuntimeError):
                list(pcap.iter_frames(Path("fake.pcap")))


class TestOnlineAuthorization(unittest.TestCase):
    class _FakeHandler:
        path = "/api/verify"

        def _auth_ok(self):
            return True

        def _body(self):
            return {"job_id": "x", "indices": [0],
                    "config": {"online": True, "allow_public": True}}

        def _json(self, obj, status=200):
            self.result = (status, obj)

    def test_unauthorized_post_is_rejected_server_side(self):
        h = self._FakeHandler()
        webui.Handler.do_POST(h)
        self.assertEqual(h.result[0], 403)

    def test_authorized_post_passes_gate(self):
        h = self._FakeHandler()
        original = h._body

        def body():
            d = original()
            d.update(authorized=True, confirm_phrase="允许在线验证")
            return d

        h._body = body
        webui.Handler.do_POST(h)
        # 授权已通过，后面因 job 不存在而 400，不能再是 403
        self.assertEqual(h.result[0], 400)


class TestDetectionCorrectness(unittest.TestCase):
    def test_chinese_adjacent_prefix_credential(self):
        # \b 按 Unicode 判词时，汉字紧邻会让前缀型凭据整体漏报
        token = "ghp_" + "aB3xY7qLmN0pRsTuVwZ2cD4eF5gH6iJ8kL9m"
        self.assertIn("API_KEY", [f.entity for f in detect("密钥" + token, "x")])
        self.assertEqual([], detect("key" + token, "x"))
        self.assertIn("TOKEN", [f.entity for f in detect(
            "令牌eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "x")])

    def test_otp_keyword_and_value_on_separate_lines(self):
        self.assertIn("OTP", [f.entity for f in detect("验证码:\n123456", "x")])
        self.assertIn("OTP", [f.entity for f in detect("验证码: 123456", "x")])

    def test_large_file_chunk_overlap_keeps_multiline_pem(self):
        der = bytes.fromhex("302e020100300506032b657004220420" + "11" * 32)
        b64 = base64.b64encode(der).decode()
        lines = ["[INFO] filler %04d padding padding padding padding" % i for i in range(14)]
        lines += ["-----BEGIN PRIVATE KEY-----", b64, "-----END PRIVATE KEY-----"]
        lines += ["[INFO] tail %04d" % i for i in range(10)]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "big.log"
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            saved = scanner.CHUNK_CHARS
            scanner.CHUNK_CHARS = 100
            try:
                fs = scanner._scan_large(p, str(p), 0.55, scanner.ScanStats())
            finally:
                scanner.CHUNK_CHARS = saved
        pem = [f for f in fs if f.entity == "PRIVATE_KEY"]
        self.assertEqual(len(pem), 1)
        self.assertEqual(pem[0].rule_id, "pem-private-key-block")
        self.assertIn("-----END", pem[0].value)


class TestPhoneVsNumericField(unittest.TestCase):
    """11 位 1 开头数字既是合法号段，也是普通整数（size/字节数/计数/时间戳）。

    手机号没有校验位，语法上分不开，只能靠字段语义反证 + 证据标签分级。
    """

    N = "13912345678"

    def _phones(self, text, **kw):
        return [f for f in detect(text, "t.log", **kw) if f.entity == "PHONE"]

    def test_numeric_field_is_rejected(self):
        samples = (
            '{"size":13912345678,"core":"0","breadth":"0","temperature":39}',
            '{"file_size":13912345678}',
            '{"bytes":13912345678}',
            '{"content_length":13912345678}',
            '{"count":13912345678}',
            '{"total":13912345678}',
            '{"timestamp":13912345678}',
            '{"temperature":13912345678}',
            'size=13912345678 width=0',
        )
        for text in samples:
            with self.subTest(text=text):
                self.assertEqual(self._phones(text), [])

    def test_bare_json_number_with_unknown_key_is_rejected(self):
        # 手机号业务上几乎总是字符串，未加引号的 JSON number 按数值处理
        self.assertEqual(self._phones('{"payload":13912345678}'), [])

    def test_phone_field_kept_as_context_evidence(self):
        samples = (
            '{"phone":"13912345678"}',
            '{"mobile":"13912345678"}',
            '{"tel":"13912345678"}',
            '{"phone":13912345678}',
            'phone=13912345678',
            '手机号：13912345678',
            '联系方式 13912345678',
        )
        for text in samples:
            with self.subTest(text=text):
                got = self._phones(text)
                self.assertEqual(len(got), 1)
                self.assertEqual(got[0].validation, "context")

    def test_phone_never_marked_as_checksum(self):
        from senscan.detectors import STRONG_VALIDATORS
        self.assertNotIn("cn_mobile", STRONG_VALIDATORS)
        got = self._phones('{"phone":"%s"}' % self.N)
        self.assertNotEqual(got[0].validation, "checksum")

    def test_bare_number_hidden_by_default_and_recoverable(self):
        text = "req done id=42 cost 13912345678 end"
        self.assertEqual(self._phones(text), [])
        got = self._phones(text, min_confidence=0.35)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].validation, "format")
        self.assertLess(got[0].confidence, 0.55)

    def test_short_keyword_does_not_match_inside_another_word(self):
        # "hotel" 里的 "tel" 曾会让裸数字自我提权成「上下文」
        got = self._phones('{"hotel":"13912345678"}', min_confidence=0.35)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].validation, "format")

    def test_rejection_is_counted(self):
        stats = {}
        detect('{"size":13912345678}', "t.log", stats=stats)
        self.assertGreaterEqual(stats.get("rejected_context", 0), 1)

    def test_id_card_and_bank_card_unaffected(self):
        from senscan.utils import cn_id_card_valid, bank_card_valid
        self.assertTrue(cn_id_card_valid("11010519491231002X"))
        self.assertTrue(bank_card_valid("4539578763621486"))
        got = detect('{"idcard":"11010519491231002X"}', "t.log")
        ids = [f for f in got if f.entity == "ID_CARD"]
        self.assertEqual(len(ids), 1)
        self.assertEqual(ids[0].validation, "checksum")
        self.assertEqual([f for f in got if f.entity == "PHONE"], [])


class TestAccuracyHardening(unittest.TestCase):
    """整体准确性审查（2026-11-11）：每条都对应探针复现过的真实缺陷。"""

    IMEI = "35341807450811" + U.luhn_check_digit("35341807450811")

    def _types(self, text, **kw):
        return [(f.entity, f.validation) for f in detect(text, "t.log", **kw)]

    def test_context_does_not_leak_across_json_fields(self):
        # 相邻字段的 phone 曾经给 trace 的值提权，左右两个方向都会串味
        self.assertEqual(self._types('{"trace":"13912345678","phone":"13900000000"}'), [])
        self.assertEqual(self._types('{"phone":"13900000000","trace":"13912345678"}'), [])

    def test_free_text_context_is_not_narrowed(self):
        # 无引号键名的自由文本要保留整行语境，否则 IoT 三元组会被砍掉
        t = ("Using device triplet: PK=a1zk9qm2xv7bn4lp8tc, "
             "DN=devgw0331kb7yt2rs9qm, DS=kd8svn2lq9zx4wp7rm3bt6yc1fh5nj")
        self.assertIn("IOT_DEVICE_SECRET", {e for e, _ in self._types(t)})

    def test_official_example_credential_is_placeholder(self):
        self.assertTrue(U.looks_placeholder("AKIAIOSFODNN7EXAMPLE"))
        self.assertEqual(self._types("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"), [])

    def test_bare_numeric_identifiers_are_suppressed(self):
        self.assertEqual(self._types('{"order_no":"460001234567890"}'), [])
        self.assertEqual(self._types('{"seq":"%s"}' % self.IMEI), [])
        self.assertEqual(self._types("req 13912345678 done"), [])

    def test_shape_only_validators_never_mark_checksum(self):
        from senscan.detectors import STRONG_VALIDATORS
        for name in ("cn_mobile", "imsi", "hex32", "mac", "serial_no", "email"):
            self.assertNotIn(name, STRONG_VALIDATORS)
        self.assertEqual(self._types("imsi=460001234567890"), [("IMSI", "context")])
        self.assertEqual(self._types("ltk=00112233445566778899aabbccddeeff"),
                         [("LTK", "context")])

    def test_real_identifiers_with_field_name_kept(self):
        self.assertEqual(self._types("imei=%s" % self.IMEI), [("IMEI", "checksum")])
        self.assertEqual(self._types('{"imei":"%s"}' % self.IMEI), [("IMEI", "checksum")])
        self.assertEqual(self._types('{"imei":"%s","phone":"13912345678"}' % self.IMEI),
                         [("IMEI", "checksum"), ("PHONE", "context")])

    def test_chinese_phone_context_recall(self):
        for text in ("用户13912345678登录成功", '{"user":"13912345678"}',
                     "手机号:13912345678", "联系方式 13912345678"):
            with self.subTest(text=text):
                self.assertEqual(self._types(text), [("PHONE", "context")])

    def test_chinese_numeric_field_is_not_phone(self):
        self.assertEqual(self._types('{"用户数":"13912345678"}'), [])

    def test_md5_and_version_still_clean(self):
        self.assertEqual(self._types('{"md5":"d41d8cd98f00b204e9800998ecf8427e"}'), [])
        self.assertEqual(self._types('{"fw":"2026.1029.0000"}'), [])


class TestChineseKeyNames(unittest.TestCase):
    """中文键名 / 前缀粘连 / 全角分隔符的召回（2026-11-12）。

    这三类写法在真实设备日志里比英文写法更常见。原先把英文键名写死在正则里，
    `密码:xxx` 和 `db_password=xxx` 一条都报不出来，是系统性的漏报面。
    """

    def _types(self, text):
        return [(f.entity, f.validation) for f in detect(text, "t.log")]

    def test_chinese_key_recall(self):
        cases = {
            "密码:Passw0rd!2024": "PASSWORD",
            "登录密码：Abc123456": "PASSWORD",
            "序列号:SN2024AB1234": "DEVICE_SN",
            "设备序列号：SN2024AB1234": "DEVICE_SN",
            "设备密钥:KD8SVN2LQ9ZX4WP7RM3BT6YC1FH5NJ": "IOT_DEVICE_SECRET",
            "产品密钥:a1zk9qm2xv7bn4lp8tc": "IOT_PRODUCT_KEY",
            "蓝牙密钥:00112233445566778899aabbccddeeff": "LTK",
            "访问令牌:abcdef1234567890abcdef": "TOKEN",
            "会话ID:A1B2C3D4E5F6A7B8": "SESSION_ID",
        }
        for text, entity in cases.items():
            with self.subTest(text=text):
                self.assertEqual([e for e, _ in self._types(text)][:1], [entity])

    def test_json_chinese_key_recall(self):
        self.assertEqual([e for e, _ in self._types('{"私钥":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"}')],
                         ["PRIVATE_KEY"])
        self.assertEqual([e for e, _ in self._types('{"公钥":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"}')],
                         ["PUBLIC_KEY"])

    def test_prefixed_key_recall(self):
        # `db_password` 里 password 前面是下划线，`\b` 不成立，曾经整条漏掉
        self.assertEqual(self._types("db_password=Passw0rd!2024"), [("PASSWORD", "format")])
        self.assertEqual([e for e, _ in self._types("user_login_password: Abc123456")],
                         ["PASSWORD"])

    def test_fullwidth_separators(self):
        self.assertEqual([e for e, _ in self._types("设备密钥＝KD8SVN2LQ9ZX4WP7RM3BT6YC1FH5NJ")],
                         ["IOT_DEVICE_SECRET"])
        self.assertEqual([e for e, _ in self._types("密码＝Abc123456")], ["PASSWORD"])

    def test_policy_words_are_not_credentials(self):
        # 负向断言：这些是说明文字，值也长得像口令/密钥，不能报
        for text in ("密码策略: 长度不少于 8 位，包含大小写", "密码强度:高",
                     "密钥管理: 由 KMS 统一托管", "令牌桶限流: 100r/s",
                     "序列号规则: 8-32 位字母数字", "公钥算法: EC P-256"):
            with self.subTest(text=text):
                self.assertEqual(self._types(text), [])

    def test_generic_key_does_not_steal_specific_entity(self):
        # 裸「密钥」曾让 generic-api-key（HIGH）抢走 LTK（MEDIUM）与
        # IOT_PRODUCT_KEY（LOW）——风险等级高的规则在冲突消解里会胜出
        self.assertEqual([e for e, _ in self._types("蓝牙密钥:00112233445566778899aabbccddeeff")],
                         ["LTK"])
        self.assertEqual([e for e, _ in self._types("产品密钥:a1zk9qm2xv7bn4lp8tc")],
                         ["IOT_PRODUCT_KEY"])


if __name__ == "__main__":
    unittest.main()
