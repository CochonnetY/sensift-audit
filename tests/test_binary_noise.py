"""二进制抽串的降噪回归（2026-11-12 真实 APK 扫描发现）。

一个 226MB 的 debug APK 上，旧版本报出 79 条，其中：
  · 2 条 CRITICAL PRIVATE_KEY，值形如 `processNameproximity...Usedrating=reasonCode`
  · 19 条 HIGH PRIVATE_KEY，全部是 .so 里编译进去的 PEM 解析器提示串
  · 22 条 OTP，值是哈希串里的数字子串 / `hotpink` 里的 otp
  · 若干 IOT_PRODUCT_KEY / SESSION_ID，是 `SDCardRecordMonthQueryReq(productKey=`
    这类「以分隔符结尾的字符串字面量」和下一条无关字符串拼出来的假字段

这些用例把每条修法钉死，避免以后调规则时又把噪声放回来。
"""

from __future__ import annotations

import base64
import struct
import unittest

from senscan import containers, utils as U
from senscan.detectors import detect
from senscan.detectors import detect


def _findings(text: str, strings_dump: bool = False):
    return detect(text, "<mem>", 0.55, strings_dump=strings_dump)


def _minimal_dex(strings: list[str]) -> bytes:
    """拼一个结构合法的最小 DEX：头部 0x70 + string_ids 表 + 字符串数据。"""
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    ids_off = 0x70
    data_off = ids_off + len(strings) * 4
    blobs = bytearray()
    offsets = []
    for s in strings:
        offsets.append(data_off + len(blobs))
        raw = s.encode("utf-8") + b"\x00"
        blobs += bytes([len(s) & 0x7F]) + raw      # 取巧：只处理 <128 字符
    struct.pack_into("<I", header, 32, data_off + len(blobs))   # file_size
    struct.pack_into("<I", header, 36, 0x70)                    # header_size
    struct.pack_into("<I", header, 40, 0x12345678)              # endian_tag
    struct.pack_into("<I", header, 56, len(strings))            # string_ids_size
    struct.pack_into("<I", header, 60, ids_off)                 # string_ids_off
    ids = b"".join(struct.pack("<I", o) for o in offsets)
    return bytes(header) + ids + bytes(blobs)


class TestDexStringPool(unittest.TestCase):
    def test_parses_pool_exactly(self):
        raw = _minimal_dex(["Lcom/demo/A;", "device_secret", "Kd8sVn2Lq9Zx4Wp7Rm"])
        text = containers.dex_strings(raw)
        self.assertEqual(text, "Lcom/demo/A;\ndevice_secret\nKd8sVn2Lq9Zx4Wp7Rm")

    def test_invalid_header_falls_back_to_strings(self):
        # 头部结构不成立（例如加了壳）时返回 None，由调用方退回抽串，不能漏报
        self.assertIsNone(containers.dex_strings(b"dex\n035\x00" + b"\x00" * 200))

    def test_strings_of_drops_mojibake(self):
        # 旧实现把 0x80 以上字节全当可打印，解码后是一片乱码；
        # 乱码里带着 = 和 private key 之类关键词，会把两条无关字符串粘成假字段。
        raw = b"\xff\xfeabc\x80\x81def\x00ghi"
        text = containers.strings_of(raw)
        self.assertIn("abc", text)
        self.assertIn("def", text)
        self.assertNotIn("\ufffd", text)


class TestStringsDumpBoundary(unittest.TestCase):
    """抽串里一行就是一条独立字符串，跨行拼接一定是假的。"""

    def test_field_at_end_of_string_is_not_a_pair(self):
        text = "SDCardRecordMonthQueryReq(productKey=\nSDCardRecordMonthRsp\n"
        self.assertEqual(_findings(text, strings_dump=True), [])
        # 同样的文本当作日志来读（硬折行），键值相邻是真实语义，仍然要报
        self.assertTrue(_findings(text, strings_dump=False))

    def test_standalone_marker_still_matches(self):
        # 单行独立凭据不受影响：它本来就自成一条
        got = _findings("sk_live_4eC3""9HqLyjWDarjtT1zdp7dc\n", strings_dump=True)
        self.assertEqual([f.entity for f in got], ["API_KEY"])


class TestPemHeaderNeedsBody(unittest.TestCase):
    def test_header_followed_by_end_marker_is_text(self):
        # libcrypto 里就长这样：一堆 BEGIN/END 说明串，不是密钥
        text = "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"
        self.assertFalse([f for f in _findings(text) if f.entity == "PRIVATE_KEY"])

    def test_header_with_body_still_reported(self):
        body = "MIIEowIBAAKCAQEA3sT9pQ7xK2mNvR8bY1cLdF4hJ6gA0eWzS5uPoI3rT7yUvX9"
        got = _findings(f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n")
        rules = {f.rule_id for f in got if f.entity == "PRIVATE_KEY"}
        # body 本身也是合法 DER，会同时被 der-private-key-bare 认出，两条都指向同一处
        self.assertIn("pem-private-key-header", rules)


class TestKeyMaterialShape(unittest.TestCase):
    def test_identifier_is_not_a_private_key(self):
        self.assertEqual(_findings('{"PrivateKey":"PrivateToThisPrivateZone"}'), [])

    def test_concatenated_noise_is_not_a_private_key(self):
        text = '{"privateKey":"processNameproximityOnpssramramUsedrating=reasonCode"}'
        self.assertEqual(_findings(text), [])

    def test_wrapped_key_material_still_reported(self):
        # 串口日志硬折行：值被拆到两行，strip_whitespace 还原后仍是 base64
        got = _findings('"PrivateKey":"AbCd9f\n=="\n')
        self.assertEqual([f.entity for f in got], ["PRIVATE_KEY"])

    def test_short_junk_value_dropped(self):
        self.assertEqual(_findings('{"PrivateKey":"abcdefgh"}'), [])


class TestI18nTextNoise(unittest.TestCase):
    """翻译资源里键名合法、值其实是 UI 文案，不能当凭据。

    一个 366MB 的 Flutter debug APK 曾报出 283 条，其中 237 条是
    `"input_hint_password": "パスワードを入力してください"` 这类多语言文案，
    以及 `"device_name": "Apparaatnaam"`、`Zugriffspasswort`。
    真正有价值的 3 条 EC 私钥被完全淹没。
    """

    NOISE = (
        ('"input_hint_password": "パスワードを入力してください"', "PASSWORD"),
        ('"access_password": "Zugriffspasswort"', "PASSWORD"),
        ('"device_name": "Apparaatnaam"', "IOT_DEVICE_NAME"),
        ("onGetWupPublicKey: begin save key to file", "PUBLIC_KEY"),
        ('"unable_to_get_third_party_netdisk_accessToken": "Drittanbieter-Netdisk-accessToken nicht abrufbar"', "TOKEN"),
    )

    def test_translation_values_not_reported(self):
        for text, entity in self.NOISE:
            with self.subTest(text=text[:40]):
                self.assertFalse([f for f in _findings(text + "\n")
                                  if f.entity == entity], text)

    def test_machine_shaped_values_still_reported(self):
        got = _findings("password=P@ssw0rd!2026\n")
        self.assertEqual([f.entity for f in got], ["PASSWORD"])

    def test_float_literal_is_not_a_bank_card(self):
        self.assertEqual(_findings("Ryt=1.2999999523162842,t3=abc\n"), [])

    def test_regex_source_is_not_a_db_credential(self):
        text = "ftp://)(?:(?:[-_0-9a-zA-Z.~!$&'()*+,;=%]+.)+[-_0-9a-zA-Z.~!$&'()*+,;=%]+@x"
        self.assertFalse([f for f in _findings(text) if f.entity == "DB_CREDENTIAL"])

    def test_compiler_symbol_is_not_an_email(self):
        self.assertEqual(_findings("secp384r1_CompactStyleWithPlurals@1346441731.formatter\n"), [])


class TestPublicSignatureMail(unittest.TestCase):
    """第三方 .so 里编译进去的公开署名邮箱，不是业务个人信息。

    旧版 email 规则的 context_keywords 含 to/from/user/mail 四个英文泛词，
    在二进制抽串里几乎必然命中，把 0.52 抬到 0.76 越过阈值，
    一个 debug APK 能刷出 11 条「已校验：上下文」的假 PII。
    """

    NOISE = (
        "CRYPTOGAMS by <appro@openssl.org>",
        "contact the ffmpeg-devel mailing list. (ffmpeg-devel@ffmpeg.org)",
        "For questions contact jsteffens@google.com",
        "buildrabbit-username@oouc14.prod.google.com",
    )

    def test_signature_mails_not_reported(self):
        for text in self.NOISE:
            with self.subTest(text=text[:40]):
                self.assertEqual(_findings(text + "\n"), [])

    def test_real_business_mail_still_reported(self):
        got = _findings("email mail_to: wang.wu@example-corp.com.cn\n")
        self.assertEqual([(f.entity, f.value) for f in got],
                         [("EMAIL", "wang.wu@example-corp.com.cn")])
        self.assertEqual(got[0].validation, "context")


class TestMarkupLiteral(unittest.TestCase):
    """JS 字典里 `password: "[type=password]"` 不是口令。"""

    def test_css_selector_is_not_a_password(self):
        text = 'checkbox: "[type=checkbox]",\npassword: "[type=password]",\nradio: "[type=radio]",\n'
        self.assertEqual(_findings(text), [])

    def test_real_password_still_found(self):
        got = _findings('password=P@ssw0rd!2026\n')
        self.assertEqual([f.entity for f in got], ["PASSWORD"])


class TestOtpNoise(unittest.TestCase):
    def test_keyword_inside_word(self):
        # hotpink 里含 otp；CSS 颜色表曾是 22 条误报的主要来源
        self.assertEqual(_findings("hotpink: 16738740,\n"), [])

    def test_digits_inside_hash(self):
        self.assertEqual(_findings('"X":"aa623e26"\n'), [])

    def test_real_otp_still_found(self):
        self.assertEqual([f.value for f in _findings("otp=123456\n")], ["123456"])
        self.assertEqual([f.value for f in _findings("验证码：123456\n")], ["123456"])


class TestFullPemBlock(unittest.TestCase):
    """真 RSA 私钥曾是 0.35 分被阈值丢掉，只剩 0.72 的 BEGIN 头弱命中。

    `char_diversity = 唯一字符数/长度` 对 2KB 的 PEM 必然 < 0.15，于是
    `looks_placeholder` 把它当占位值扣 0.55 分；同时 max_value_len=1024
    把密钥体截断。这两条一起让完整私钥「看起来只有个头」。
    """

    @staticmethod
    def _pem(nbytes: int = 1600) -> str:
        body = base64.b64encode(bytes((i * 7 + 13) % 256 for i in range(nbytes))).decode()
        lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        return f"-----BEGIN RSA PRIVATE KEY-----\n{lines}\n-----END RSA PRIVATE KEY-----\n"

    def test_long_pem_is_not_placeholder(self):
        pem = self._pem()
        self.assertGreater(len(pem), 1024)
        self.assertFalse(U.looks_placeholder(pem))
        self.assertTrue(U.looks_placeholder("A" * 200))  # 超长退化串仍要挡

    def test_full_block_is_critical_checksum_and_complete(self):
        got = [f for f in detect(self._pem(), "t", 0.55) if f.entity == "PRIVATE_KEY"]
        self.assertEqual(len(got), 1, "完整块与 BEGIN 头不该重复报两条")
        f = got[0]
        self.assertEqual((f.rule_id, f.risk.value, f.validation),
                         ("pem-private-key-block", "critical", "checksum"))
        self.assertGreaterEqual(f.confidence, 0.9)
        self.assertGreater(len(f.value), 1024)
        self.assertIn("-----END", f.value)

    def test_truncated_header_still_reported(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 64 + "\n"
        got = [f for f in detect(text, "t", 0.55) if f.entity == "PRIVATE_KEY"]
        self.assertEqual([f.rule_id for f in got], ["pem-private-key-header"])
        self.assertIn("A" * 20, got[0].context)  # 上下文能看到头后面的正文

    def test_context_window_is_wider(self):
        pem = self._pem()
        mid = len(pem) // 2
        ctx = U.extract_context(pem, mid, mid + 10)
        self.assertLessEqual(len(ctx), 600)
        self.assertGreater(len(ctx), 400, "展示半径应至少覆盖命中前后各 200 字符")


class ContextAlignmentTests(unittest.TestCase):
    """「原文」必须能让人找到命中值本身。

    2026-11-13 实测：完整 RSA 私钥压平后约 1.7KB，旧版把三段拼成长串再
    「留头 1/3 + 留尾 2/3」截到 600，命中值正好在中间被整段吃掉，报告里
    「原文」显示的是上一条 EC 密钥的尾巴和下张证书的头，看着像两码事。
    """

    def test_long_hit_head_and_tail_both_visible(self):
        before = "prefix-" + "A" * 300
        hit = ("-----BEGIN RSA PRIVATE KEY-----\n" + "B" * 1600
               + "\n-----END RSA PRIVATE KEY-----")
        after = "C" * 300 + "-suffix"
        text = before + hit + after
        start, end = len(before), len(before) + len(hit)
        ctx = U.extract_context(text, start, end)
        parts = U.context_parts(text, start, end)

        self.assertLessEqual(len(ctx), 600)
        self.assertIn(U.HIT_OPEN, ctx)
        self.assertIn(U.HIT_CLOSE, ctx)
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", ctx)
        self.assertIn("-----END RSA PRIVATE KEY-----", ctx)
        self.assertIn("省略", ctx)
        self.assertEqual(U.join_context(parts), ctx)
        self.assertIn("-----BEGIN", parts[1])
        self.assertTrue(parts[0].startswith("…"))   # 左邻只留贴近命中的一端
        self.assertTrue(parts[2].endswith("…"))     # 右邻同理

    def test_short_hit_keeps_full_neighbours(self):
        before, hit, after = "L" * 220, "AKIA1234567890ABCDEF", "R" * 220
        text = before + hit + after
        start, end = len(before), len(before) + len(hit)
        parts = U.context_parts(text, start, end)
        self.assertEqual(parts[1], hit)
        self.assertGreaterEqual(len(parts[0]), 200)
        self.assertGreaterEqual(len(parts[2]), 200)
        ctx = U.extract_context(text, start, end)
        self.assertIn(f"{U.HIT_OPEN}{hit}{U.HIT_CLOSE}", ctx)
        self.assertLessEqual(len(ctx), 600)

    def test_finding_carries_context_parts(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 120
               + "\n-----END RSA PRIVATE KEY-----")
        got = [f for f in detect(pem, "t", 0.55) if f.entity == "PRIVATE_KEY"]
        self.assertTrue(got)
        f = got[0]
        self.assertIsNotNone(f.context_parts)
        self.assertEqual(len(f.context_parts), 3)
        self.assertIn("-----BEGIN", f.context_parts[1])
        self.assertEqual(U.join_context(f.context_parts), f.context)
        d = f.to_dict()
        self.assertEqual(d["context_parts"]["hit"], f.context_parts[1])
        self.assertIn("⟦", d["context"])


if __name__ == "__main__":
    unittest.main()
