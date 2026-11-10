"""验证层与可视化工作台的回归测试。

在线验证一律走本机 mock server，不触达任何公网端点；审计日志写在临时目录。
"""

from __future__ import annotations

import base64
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from senscan import report  # noqa: E402
from senscan import verify as V  # noqa: E402
from senscan import webui  # noqa: E402
from senscan.models import Finding, Risk  # noqa: E402
from senscan.scanner import scan  # noqa: E402
from senscan.whitelist import Whitelist  # noqa: E402


def b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def mk(entity: str, value: str, rule_id: str, risk: Risk = Risk.HIGH) -> Finding:
    return Finding(entity=entity, value=value, risk=risk, confidence=0.9, rule_id=rule_id,
                   source="unit-test", offset=0, line=1, column=1, context="ctx")


class TestLocalVerification(unittest.TestCase):
    def test_jwt_expired_and_active(self):
        old = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"exp": 1000000000}) + ".sig"
        future = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"exp": 4102444800}) + ".sig"
        self.assertEqual(V.local_check(mk("TOKEN", old, "jwt")).status, V.EXPIRED)
        self.assertEqual(V.local_check(mk("TOKEN", future, "jwt")).status, V.UNKNOWN)
        self.assertIn("签名密钥", V.local_check(mk("TOKEN", old, "jwt")).detail)

    def test_jwt_alg_none_is_flagged(self):
        tok = b64({"alg": "none"}) + "." + b64({"sub": "1"}) + ".sig"
        self.assertEqual(V.local_check(mk("TOKEN", tok, "jwt")).status, V.ACTIVE)

    def test_signed_url_expiry(self):
        expired = "https://x.oss-cn.aliyuncs.com/a?OSSAccessKeyId=LTAIx&Expires=1000000000&Signature=ab"
        self.assertEqual(V.local_check(mk("OSS_SIGNED_URL", expired, "signed-url-aliyun-oss")).status,
                         V.EXPIRED)
        future = expired.replace("1000000000", "4102444800")
        self.assertEqual(V.local_check(mk("OSS_SIGNED_URL", future, "signed-url-aliyun-oss")).status,
                         V.ACTIVE)

    def test_pem_structure_and_encrypted(self):
        # 最小合法 DER SEQUENCE：30 03 02 01 01
        body = base64.b64encode(bytes.fromhex("3003020101")).decode()
        pem = "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(V.local_check(mk("PRIVATE_KEY", pem, "pem-private-key-block")).status,
                         V.STRUCTURE)
        enc = "Proc-Type: 4,ENCRYPTED\n" + pem
        self.assertIn("加密", V.local_check(mk("PRIVATE_KEY", enc, "pem-private-key-block")).detail)

    def test_temporary_and_test_credentials(self):
        self.assertEqual(V.local_check(mk("API_KEY", "ASIA1234567890123456", "aws-access-key-id")).status,
                         V.EXPIRED)
        self.assertEqual(V.local_check(mk("API_KEY", "sk_test_abcdefghijklmn", "stripe-key")).status,
                         V.EXPIRED)
        self.assertEqual(V.local_check(mk("API_KEY", "sk_live_abcdefghijklmn", "stripe-key")).status,
                         V.STRUCTURE)

    def test_pii_and_device_are_not_liveness_checks(self):
        self.assertEqual(V.local_check(mk("ID_CARD", "11010519491231002X", "cn-id-card")).status,
                         V.STRUCTURE)
        self.assertEqual(V.local_check(mk("MAC", "00:1a:2b:3c:4d:5e", "mac-address")).status, V.NA)


class TestPolicy(unittest.TestCase):
    def test_online_requires_endpoints(self):
        with self.assertRaises(V.VerifyPolicyError):
            V.VerifyConfig(online=True).validate()

    def test_public_endpoints_need_explicit_authorization(self):
        with self.assertRaises(V.VerifyPolicyError):
            V.VerifyConfig(online=True, endpoint_ids=("github-user",)).validate()
        V.VerifyConfig(online=True, endpoint_ids=("github-user",), allow_public=True).validate()

    def test_custom_endpoint_scheme(self):
        with self.assertRaises(V.VerifyPolicyError):
            V.VerifyConfig(online=True, custom=({"url": "http://evil.example/check"},)).validate()
        V.VerifyConfig(online=True, custom=({"url": "http://127.0.0.1:9/check"},)).validate()
        V.VerifyConfig(online=True, custom=({"url": "https://verify.corp.internal/check"},)).validate()

    def test_unknown_endpoint_rejected(self):
        with self.assertRaises(V.VerifyPolicyError):
            V.VerifyConfig(online=True, endpoint_ids=("not-a-real-endpoint",),
                           allow_public=True).validate()

    def test_catalog_has_no_side_effect_endpoints(self):
        catalog = V.endpoint_catalog()
        self.assertTrue(all("webhook" not in (e.get("id") or "") for e in catalog if e.get("public")))
        self.assertIn("github-user", [e["id"] for e in catalog])

    def test_whitelist_from_text(self):
        wl = Whitelist.from_text("# comment\nMAC:001a2b3c4d5e\nregex:^04:7\n")
        self.assertEqual(len(wl), 2)
        self.assertTrue(wl.matches(mk("MAC", "00:1A:2B:3C:4D:5E", "mac-address")))


class _MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        code = 200 if "GOODSECRET" in body else 401
        payload = b'{"ok":true}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # noqa: ANN002
        pass


class TestOnlineVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _MockHandler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _cfg(self, audit: Path, **kw) -> V.VerifyConfig:
        return V.VerifyConfig(
            local=False, online=True, qps=200, timeout=2, audit_path=audit,
            custom=({"id": "mock", "provider": "mock",
                     "url": f"http://127.0.0.1:{self.port}/check", "method": "POST",
                     "headers": {"X-Test": "{{SECRET}}"},
                     "body": '{"secret":"{{SECRET}}"}',
                     "match_entities": ["API_KEY"],
                     "success_codes": [200], "invalid_codes": [401]},),
            **kw,
        )

    def test_active_inactive_and_audit_has_no_plaintext(self):
        with TemporaryDirectory() as td:
            audit = Path(td) / "audit.jsonl"
            items = [mk("API_KEY", "GOODSECRET123456", "generic-api-key"),
                     mk("API_KEY", "BADSECRET123456", "generic-api-key")]
            s = V.run(items, self._cfg(audit))
            self.assertEqual([V.liveness_of(x) for x in items], [V.ACTIVE, V.INACTIVE])
            self.assertEqual((s.active, s.inactive, s.online_checked), (1, 1, 2))
            text = audit.read_text(encoding="utf-8")
            self.assertNotIn("GOODSECRET123456", text)
            self.assertIn("value_sha256", text)
            self.assertEqual(len(text.strip().splitlines()), 2)

    def test_active_forces_p0(self):
        with TemporaryDirectory() as td:
            f = mk("API_KEY", "GOODSECRET123456", "generic-api-key", Risk.LOW)
            self.assertEqual(f.priority, "P2")
            V.run([f], self._cfg(Path(td) / "a.jsonl"))
            self.assertEqual(f.priority, "P0")

    def test_same_value_is_verified_once(self):
        with TemporaryDirectory() as td:
            items = [mk("API_KEY", "GOODSECRET123456", "generic-api-key") for _ in range(4)]
            s = V.run(items, self._cfg(Path(td) / "a.jsonl"))
            self.assertEqual(s.online_checked, 1)
            self.assertTrue(all(V.liveness_of(x) == V.ACTIVE for x in items))

    def test_max_checks_skips_without_calling_out(self):
        with TemporaryDirectory() as td:
            items = [mk("API_KEY", f"GOODSECRET{n:04d}", "generic-api-key") for n in range(4)]
            s = V.run(items, self._cfg(Path(td) / "a.jsonl", max_checks=1))
            self.assertEqual(s.online_checked, 1)
            self.assertEqual(s.skipped_limit, 3)
            self.assertEqual(V.liveness_of(items[0]), V.ACTIVE)
            self.assertEqual(V.liveness_of(items[-1]), V.UNKNOWN)

    def test_host_allowlist_is_enforced_before_request(self):
        from dataclasses import replace
        with TemporaryDirectory() as td:
            cfg = self._cfg(Path(td) / "a.jsonl")
            ep = cfg.resolved_endpoints()[0]
            bad = replace(ep, url="https://evil.example/check")
            with self.assertRaises(V.VerifyPolicyError):
                V._call_endpoint(bad, "GOODSECRET123456", cfg)


class TestReportsAndWebUI(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.root = Path(self.td.name)
        (self.root / "a.log").write_text(
            'api_key="sk_test_abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")
        self.result = scan([self.root / "a.log"], verify_config=V.VerifyConfig(local=True))

    def tearDown(self):
        self.td.cleanup()

    def test_json_csv_html_carry_liveness(self):
        p = report._payload(self.result, False)
        self.assertIn("by_liveness", p["summary"])
        self.assertIn("verification", p)
        with TemporaryDirectory() as td:
            j = Path(td) / "r.json"
            c = Path(td) / "r.csv"
            h = Path(td) / "r.html"
            report.write_json(self.result, j)
            report.write_csv(self.result, c)
            report.write_html(self.result, h)
            self.assertIn("liveness", c.read_text(encoding="utf-8-sig").splitlines()[0])
            self.assertIn("lchip", h.read_text(encoding="utf-8"))

    def test_html_escapes_verification_detail(self):
        f = self.result.findings[0]
        f.extra["verification"] = {
            "layer": "local", "status": "active",
            "detail": "<script>alert(1)</script>", "endpoint": "",
        }
        with TemporaryDirectory() as td:
            p = Path(td) / "r.html"
            report.write_html(self.result, p)
            self.assertNotIn("<script>alert(1)</script>", p.read_text(encoding="utf-8"))

    def test_webui_payloads_and_export(self):
        st = webui.state_payload()
        self.assertGreaterEqual(st["rules_total"], 60)
        self.assertGreater(len(st["endpoints"]), 5)
        self.assertEqual(len(webui.rules_payload("gitleaks")["rows"]), 25)
        b = webui.browse_payload(str(self.root))
        self.assertEqual(Path(b["path"]), self.root)
        self.assertTrue(any(e["name"] == "a.log" for e in b["entries"]))

        job = webui.Job(id="unit", status="done", result=self.result)
        webui.STATE["jobs"]["unit"] = job
        for fmt in ("json", "csv", "sarif", "html"):
            data, _ctype, name = webui.export_bytes("unit", fmt, False)
            self.assertGreater(len(data), 100)
            self.assertTrue(name.endswith("." + fmt))
        webui.STATE["jobs"].pop("unit", None)

    def test_cancel_running_job(self):
        job = webui.Job(id="cancel-unit")
        webui.STATE["jobs"]["cancel-unit"] = job
        try:
            r = webui.cancel_scan("cancel-unit")
            self.assertTrue(r["ok"])
            self.assertTrue(job.cancelled)
            self.assertEqual(job.phase, "正在停止…")
        finally:
            webui.STATE["jobs"].pop("cancel-unit", None)


if __name__ == "__main__":
    unittest.main()
