"""裸 DER 密钥 / JSON 密钥字段 / 串口日志折行的回归测试。

起因：用户贴来设备串口日志截图，里面把密钥分区整块 base64 dump 出来，
有 "PrivateKey" / "PublicKey" 字段但**没有 PEM 头**，且日志按列宽硬折行把
键名和值都拆断了。原有 PEM 规则一个都命中不了。

测试里的 DER 值是按 ASN.1 结构拼出来的**假密钥材料**（内容全为重复字节），
不是真实私钥，只用于验证前缀识别与 base64 解码校验。
"""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from senscan import utils as U  # noqa: E402
from senscan.detectors import detect  # noqa: E402
from senscan.models import VALID_CHECKSUM, Risk  # noqa: E402


def _der(hex_head: str, fill: int = 64) -> str:
    """按给定 ASN.1 头构造结构合法、内容无意义的 base64 串。"""
    return base64.b64encode(bytes.fromhex(hex_head) + b"\x11" * fill).decode()


EC_PUB = _der("3049301306072a8648ce3d020106082a8648ce3d03010703420004")
EC_PRIV = _der("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420", 32)

# 同构于用户截图：ANSI 颜色、加密分区 dump、驼峰 JSON、按列宽硬折行
PARAM_LOG = f"""[36;22mI/IPC MAIN [2026-11-03 18:07:38.004] (main.c:904 main)>>>>>>>>>>>>>>>>> xos_aes_hw_crypto_init finished![0m
[36;22mI/XOS_PARAM_PART_RW [2026-11-03 18:07:38.010] (xos_bind_param_rw_api.c:235 xos_bind_param_rw_read_param)buf:
F0f8XMmdXGXgyraI5yGU262jQkvknTraWF39OH7qqvA6yh34ZSHMGVAMSL0YcD1ENs6o2F7GEbbUEZUDzKv5s/b8nFe1ZfAKZkWzAWFF9pD+IDzB8nMcRkD5W8ar1Y60dc4hx7iVQg
+CqBlyQ1BVggr8xUOOs2Uod4IViyiJ/ueqoMGHFK9MmBeVOQnseleTItIy8YNIQO2sDsd1SgYoyOoAxtJIs6Jg8
"Factory","mode":"user","sn":"0|080200U6100006A","version":"1.0.0","PrivateKey":"AbCd9f
==","PublicKey":"{EC_PUB[:40]}
{EC_PUB[40:]}","productModel":"","hw_version":"OD800PRO-
MAIN-02A","macaddr":"AA0D800E8S0205","again_time":0,"cpKeySize":"164","productKey":"NFsjvbSelFOzEwWOxSKq","deviceName":"xJCLhJSMVwJ22qTh28nC","dev
Secret":"n0W2pGZLdZt5DFnsSp627fEAtVLYR1","region":"CN","userId":"1374012"
[0m
[36;22mI/XOS_PARAM_PART_RW [2026-11-03 18:07:38.012] (xos_bind_param_rw_api.c:42 xos_bind_param_rw_parse_param_json)is: 0|080200U6100006A[0m
"""


class TestDerValidation(unittest.TestCase):
    def test_kind_known_prefixes(self):
        self.assertEqual(U.der_key_kind(EC_PUB), "public")
        self.assertEqual(U.der_key_kind(EC_PRIV), "private")
        self.assertTrue(U.der_public_ok(EC_PUB))
        self.assertTrue(U.der_private_ok(EC_PRIV))
        self.assertFalse(U.der_private_ok(EC_PUB))

    def test_padding_at_end_is_handled(self):
        """DER base64 常以 = / == 结尾，补 padding 前必须先去掉原有 =。"""
        padded = EC_PUB + "=="
        self.assertEqual(U.der_key_kind(padded), "public")

    def test_wrapped_value_is_normalized(self):
        half = len(EC_PUB) // 2
        self.assertEqual(U.der_key_kind(EC_PUB[:half] + "\n" + EC_PUB[half:]), "public")

    def test_random_base64_rejected(self):
        for v in (
            "M" + "A" * 80,                       # 以 M 开头但不是 ASN.1
            base64.b64encode(b"hello world" * 10).decode(),
            "MIIDXTCCAkWgAwIBAgIU",             # 证书 DER 前缀，不是私钥
            "not-base64-at-all-xxxx",
        ):
            with self.subTest(v=v[:20]):
                self.assertIsNone(U.der_key_kind(v))


class TestKeyDetection(unittest.TestCase):
    def test_screenshot_log_covers_all_field_shapes(self):
        got = detect(PARAM_LOG, "param.log")
        by_entity = {f.entity: f for f in got}
        self.assertIn("PRIVATE_KEY", by_entity)
        self.assertIn("PUBLIC_KEY", by_entity)
        self.assertIn("IOT_PRODUCT_KEY", by_entity)
        self.assertIn("IOT_DEVICE_NAME", by_entity)
        self.assertIn("IOT_DEVICE_SECRET", by_entity)
        self.assertIs(by_entity["PRIVATE_KEY"].risk, Risk.CRITICAL)
        self.assertIs(by_entity["IOT_DEVICE_SECRET"].risk, Risk.CRITICAL)

    def test_wrapped_private_key_value_restored(self):
        """值被折成 `AbCd9f` + 换行 + `==`，报告里应还原成完整值。"""
        got = detect(PARAM_LOG, "param.log")
        k = next(f for f in got if f.entity == "PRIVATE_KEY")
        self.assertEqual(k.value, "AbCd9f==")
        self.assertNotIn("\n", k.value)

    def test_wrapped_key_name_dev_secret(self):
        """键名被折成 `dev` + 换行 + `Secret":`，仍要认出来。"""
        got = detect(PARAM_LOG, "param.log")
        sec = next(f for f in got if f.entity == "IOT_DEVICE_SECRET")
        self.assertEqual(sec.value, "n0W2pGZLdZt5DFnsSp627fEAtVLYR1")

    def test_wrapped_public_key_is_der_validated(self):
        got = detect(PARAM_LOG, "param.log")
        pub = next(f for f in got if f.entity == "PUBLIC_KEY")
        self.assertTrue(U.der_public_ok(pub.value))
        self.assertNotIn("\n", pub.value)

    def test_bare_der_private_without_field_name(self):
        """没有字段名也要靠 DER 结构前缀认出来，并标为「已校验」。"""
        got = detect(f"blob: {EC_PRIV}\n", "t.log")
        keys = [f for f in got if f.entity == "PRIVATE_KEY"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].rule_id, "der-private-key-bare")
        self.assertEqual(keys[0].validation, VALID_CHECKSUM)

    def test_pem_block_not_double_reported(self):
        """PEM 块 + 块内被单独认出的 DER body 只能报一条。"""
        body = "MIIEowIBAAKCAQEA" + "A" * 60
        head = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        tail = "-" * 5 + "END RSA PRIVATE KEY" + "-" * 5
        text = f"{head}\n{body}\n{tail}\n"
        got = detect(text, "t.log")
        keys = [f for f in got if f.entity == "PRIVATE_KEY"]
        self.assertEqual(len(keys), 1, [(f.rule_id, len(f.value)) for f in keys])
        self.assertEqual(keys[0].rule_id, "pem-private-key-block")

    def test_false_positives_clean(self):
        cases = [
            ("普通 base64", "config blob: " + base64.b64encode(b"factory-config-v1" * 8).decode()),
            ("加密分区 dump", "buf: F0f8XMmdXGXgyraI5yGU262jQkvknTraWF39OH7qqvA6yh34ZSHMGVAMSL0YcD1ENs6o2"),
            ("随机 M 长串", "token: M" + "Zk9Qm2Xv7Bn4Lp8TcKd3sVn2Lq9Zx4Wp7Rm3Bt6Yc1Fh5Nj" * 2),
            ("证书前缀", "cert: MIIDXTCCAkWgAwIBAgIUKd8sVn2Lq9Zx4Wp7Rm3Bt6Yc1Fh5Nj"),
            ("普通 JSON", '{"mode":"user","version":"1.0.0","region":"CN","userId":"1374012"}'),
        ]
        for name, text in cases:
            with self.subTest(name=name):
                got = detect(text + "\n", "t.log")
                bad = [f for f in got if f.entity in ("PRIVATE_KEY", "PUBLIC_KEY")
                       or f.rule_id.startswith(("der-", "json-private", "json-public"))]
                self.assertEqual(bad, [], f"{name} 误报：{[f.rule_id for f in bad]}")

    def test_key_rules_in_catalog(self):
        from senscan import report
        from senscan.scanner import ScanResult, ScanStats
        empty = ScanResult([], ScanStats(), [], "now", 0, 0.55)
        ids = {r["id"] for r in report._payload(empty, False)["rule_catalog"]}  # noqa: SLF001
        self.assertTrue({
            "json-private-key-field", "der-private-key-bare",
            "json-public-key-field", "der-public-key-bare",
        } <= ids)


if __name__ == "__main__":
    unittest.main()
