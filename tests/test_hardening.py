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

from senscan import pcap, report, scanner, verify as V, webui
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


if __name__ == "__main__":
    unittest.main()
