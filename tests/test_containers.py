"""容器扫描：APK / JAR / IPA / Office / 压缩包 / SQLite。"""

from __future__ import annotations

import io
import json
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from senscan import containers
from senscan.scanner import scan

SECRET = "KD8SVN2LQ9ZX4WP7RM3BT6YC1FH5NJ"
STRIPE = ("sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc")


class ContainerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ---------------------------------------------------------- helpers
    def _apk(self) -> Path:
        p = self.dir / "app.apk"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32 + b"com.demo\x00")
            z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64
                       + ("\x1aapi_key\x00" + STRIPE + "\x00").encode())
            z.writestr("assets/config.json", json.dumps({"phone": "13912345678"}))
            z.writestr("res/raw/secret.txt", f"device_secret:{SECRET}\n")
            z.writestr("res/drawable/icon.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        return p

    def _find(self, path: Path, **kw):
        r = scan([path], min_confidence=0.55, **kw)
        return r.findings, r

    # ---------------------------------------------------------- 类型识别
    def test_kind_detection(self) -> None:
        apk = self._apk()
        self.assertEqual(containers.is_container(apk.read_bytes()[:16]), "zip")
        names = zipfile.ZipFile(apk).namelist()
        self.assertEqual(containers._zip_kind(names), "apk")

        docx = self.dir / "a.docx"
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("word/document.xml", "<w:t>x</w:t>")
        self.assertEqual(containers._zip_kind(zipfile.ZipFile(docx).namelist()), "office")

        jar = self.dir / "a.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            z.writestr("a/B.class", b"\xca\xfe\xba\xbe")
        self.assertEqual(containers._zip_kind(zipfile.ZipFile(jar).namelist()), "jar")

        ipa = self.dir / "a.ipa"
        with zipfile.ZipFile(ipa, "w") as z:
            z.writestr("Payload/A.app/A", b"\xcf\xfa\xed\xfe")
        self.assertEqual(containers._zip_kind(zipfile.ZipFile(ipa).namelist()), "ipa")

    # ---------------------------------------------------------- APK
    def test_apk_assets_and_dex(self) -> None:
        findings, _ = self._find(self._apk())
        by_src = {f.source: f for f in findings}
        cfg = [s for s in by_src if s.endswith("!assets/config.json")]
        self.assertTrue(cfg, f"未扫到 APK 内 assets: {list(by_src)}")
        self.assertEqual(by_src[cfg[0]].entity, "PHONE")
        self.assertTrue(any(s.endswith("!classes.dex") for s in by_src), "DEX 字符串未命中")
        self.assertTrue(any(s.endswith("!res/raw/secret.txt") for s in by_src))

    def test_apk_container_meta(self) -> None:
        findings, _ = self._find(self._apk())
        f = next(f for f in findings if "!assets/config.json" in f.source)
        self.assertEqual(f.extra.get("container"), "apk")
        self.assertEqual(f.extra.get("entry"), "assets/config.json")
        self.assertTrue(str(f.extra.get("container_file")).endswith("app.apk"))

    def test_apk_png_skipped(self) -> None:
        # 图标是二进制且无扩展名白名单，不应被抽串误报
        findings, _ = self._find(self._apk())
        self.assertFalse([f for f in findings if "icon.png" in f.source])

    # ---------------------------------------------------------- JAR / IPA
    def test_jar_and_ipa(self) -> None:
        jar = self.dir / "a.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            z.writestr("application.properties", "db.password=Pr0dP@ssw0rd\n")
            z.writestr("a/B.class", b"\xca\xfe\xba\xbe" + b"\x00" * 20 + b"password=Sup3rS3cret!\x00")
        findings, _ = self._find(jar)
        ents = {f.source.split("!")[-1] for f in findings}
        self.assertIn("application.properties", ents)
        self.assertIn("a/B.class", ents)

    # ---------------------------------------------------------- Office
    def test_office_document_value_clean(self) -> None:
        p = self.dir / "a.docx"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("word/document.xml", "<w:document><w:t>数据库密码:MyS3cretPwd</w:t></w:document>")
            z.writestr("word/styles.xml", "<styles/>")
        findings, _ = self._find(p)
        pw = [f for f in findings if f.entity == "PASSWORD"]
        self.assertTrue(pw, "Office 正文密码未扫到")
        self.assertEqual(pw[0].value, "MyS3cretPwd")   # 不含 </w:t> 标签

    # ---------------------------------------------------------- 压缩包
    def test_zip_nested(self) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("inner.log", f"设备密钥:{SECRET}\n")
        p = self.dir / "bundle.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("logs/app.log", "phone=13912345678\n")
            z.writestr("nested.zip", inner.getvalue())
        findings, _ = self._find(p)
        srcs = [f.source for f in findings]
        self.assertTrue(any("logs/app.log" in s for s in srcs))
        self.assertTrue(any("nested.zip!/inner.log" in s for s in srcs), srcs)

    def test_zip_bomb_ratio_skipped(self) -> None:
        p = self.dir / "bomb.zip"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("zeros.log", b"\x00" * (20 * 1024 * 1024))   # 压缩比极高
            z.writestr("ok.log", "phone=13912345678\n")
        findings, _ = self._find(p)
        self.assertTrue([f for f in findings if "ok.log" in f.source])
        self.assertFalse([f for f in findings if "zeros.log" in f.source])

    def test_tar_gz(self) -> None:
        p = self.dir / "logs.tar.gz"
        with tarfile.open(p, "w:gz") as tf:
            data = "序列号:SN2024AB1234\n".encode()
            info = tarfile.TarInfo("device/serial.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        findings, _ = self._find(p)
        self.assertTrue([f for f in findings if f.entity == "DEVICE_SN"], findings)
        self.assertTrue(any(f.source.endswith("!device/serial.txt") for f in findings))

    # ---------------------------------------------------------- SQLite
    def test_sqlite_columns(self) -> None:
        p = self.dir / "app.db"
        con = sqlite3.connect(p)
        con.execute("create table users(id integer, phone text, token text)")
        con.execute("insert into users values(1,'13912345678',?)", (STRIPE,))
        con.commit()
        con.close()
        findings, _ = self._find(p)
        ents = {f.entity for f in findings}
        self.assertIn("PHONE", ents)
        self.assertIn("API_KEY", ents)
        phone = next(f for f in findings if f.entity == "PHONE")
        self.assertEqual(phone.source, str(p.resolve()))    # 单文件容器不重复拼条目名
        self.assertEqual(phone.extra.get("container"), "sqlite")

    def test_sqlite_corrupt_falls_back(self) -> None:
        p = self.dir / "bad.db"
        p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100 + STRIPE.encode())
        blobs = list(containers.iter_blobs(p, "sqlite"))
        self.assertTrue(blobs)
        self.assertIn(STRIPE, blobs[0].text)

    # ---------------------------------------------------------- 开关与统计
    def test_disable_container(self) -> None:
        findings, r = self._find(self._apk(), enable_container=False)
        self.assertEqual(findings, [])
        self.assertTrue(any("no-container" in s for s in r.stats.skipped))

    def test_stats_entries(self) -> None:
        _, r = self._find(self._apk())
        self.assertGreaterEqual(r.stats.container_entries, 4)

    def test_iot_triplet_across_entries(self) -> None:
        """三元组分散在同一个 APK 的两个条目里，仍应判定为设备身份可仿冒。"""
        p = self.dir / "t.apk"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 16 + b"x\x00")
            z.writestr("classes.dex", b"dex\n035\x00")
            z.writestr("assets/pk.json",
                       '{"product_key":"a1zk9qm2xv7bn4lp8tc","device_name":"devgw0331kb7yt2rs9qm"}')
            z.writestr("assets/ds.json", f'{{"device_secret":"{SECRET}"}}')
        findings, _ = self._find(p)
        secret = [f for f in findings if f.entity == "IOT_DEVICE_SECRET"]
        self.assertTrue(secret)
        self.assertTrue(secret[0].extra.get("iot_triplet"), "跨条目三元组未合并判定")


class TestLocaleDowngrade(unittest.TestCase):
    """翻译资源按来源降权：压掉词典条目，但不能吃掉真凭据。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_locale_path_detection(self) -> None:
        for label in ("assets/flutter_assets/packages/ug_mine/assets/locale/i18n_pt.json",
                      "assets/i18n_ja.json", "res/values/strings.xml",
                      "resources.arsc", "lib/l10n/app_en.arb"):
            with self.subTest(label=label):
                self.assertTrue(containers.is_locale_blob(label))
        for label in ("assets/config.json", "classes.dex",
                      "lib/arm64-v8a/libapp.so", "res/raw/secret.txt"):
            with self.subTest(label=label):
                self.assertFalse(containers.is_locale_blob(label))

    def test_dictionary_noise_downgraded_real_secret_kept(self) -> None:
        p = self.dir / "app.apk"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 16)
            z.writestr("classes.dex", b"dex\n035\x00")
            # 翻译条目：键名合法、值像紧凑串，旧版会报 PASSWORD
            z.writestr("assets/flutter_assets/packages/ug_mine/assets/locale/i18n_pt.json",
                       '{"input_hint_password": "Senha_de_acesso_2026"}')
            # 同一个 locale 文件里真有凭据，降权后仍必须报
            z.writestr("assets/flutter_assets/packages/ug_mine/assets/locale/i18n_en.json",
                       f'{{"note": "api_key={STRIPE}"}}')
            # 普通配置文件不受影响
            z.writestr("assets/config.json", 'password=P@ssw0rd!2026\n')
        r = scan([p], min_confidence=0.55)
        ents = [f.entity for f in r.findings]
        self.assertNotIn("PASSWORD", [f.entity for f in r.findings
                                      if "i18n_pt" in f.source])
        self.assertIn("API_KEY", ents, "locale 里的真凭据被降权吃掉了")
        self.assertIn("PASSWORD", ents, "普通配置文件不应被降权")
        self.assertGreaterEqual(r.stats.locale_entries, 2)

    def test_urn_uuid_is_not_a_device_id(self) -> None:
        from senscan.detectors import detect
        self.assertEqual(detect("urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\n", "t"), [])
        got = detect("oaid: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\n", "t")
        self.assertEqual([f.entity for f in got], ["OAID"])


if __name__ == "__main__":
    unittest.main()
