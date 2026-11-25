"""合规映射：法条准确性、口径差异、覆盖度与报告输出回归。

这些断言的存在意义是防「看起来对但条号错」——合规结论一旦写错条号，
评审会直接失去可信度。法条文字以中国人大网/中国网信网官方全文、
GB/T 35273-2020 标准目次为准（核实于 2026-11-25）。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from senscan import compliance as COMP
from senscan.report import write_all, write_json
from senscan.rules import RULES
from senscan.scanner import scan


class TestLegalAccuracy(unittest.TestCase):
    """逐条钉住容易被张冠李戴的条号与概念。"""

    def test_all_entities_are_mapped(self):
        ents = {r.entity for r in RULES}
        self.assertEqual(set(COMP.ENTITY_MAP), ents, "实体映射表与规则表不一致")
        self.assertEqual(len(ents), 26)

    def test_every_reference_exists(self):
        for entity, c in COMP.ENTITY_MAP.items():
            for k in c.refs:
                self.assertIn(k, COMP.REFS, f"{entity} 引用了不存在的条号 {k}")

    def test_recommendative_standard_not_law(self):
        """GB/T 是推荐性国标，不能标成法律。"""
        for k in ("GB-A1", "GB-B1", "GB-6.3", "GB-11.4", "GB-39335"):
            self.assertEqual(COMP.REFS[k].level, "推荐性国家标准")
        for k in ("PIPL-28", "PIPL-55", "CSL-42", "DSL-27"):
            self.assertEqual(COMP.REFS[k].level, "法律")

    def test_pipl_28_enumerates_sensitive_categories(self):
        g = COMP.REFS["PIPL-28"].gist
        for term in ("生物识别", "宗教信仰", "特定身份", "医疗健康",
                     "金融账户", "行踪轨迹", "不满十四周岁", "严格保护措施"):
            self.assertIn(term, g)

    def test_pipl_28_does_not_enumerate_phone_email_device(self):
        """法定列举里没有手机号/邮箱/设备标识 —— 这是两套口径的分界线。"""
        g = COMP.REFS["PIPL-28"].gist
        for term in ("电话号码", "邮箱地址", "IMEI", "MAC", "设备标识符"):
            self.assertNotIn(term, g)

    def test_gb35273_appendix_b_is_wider_than_pipl(self):
        b = COMP.REFS["GB-B1"]
        self.assertIn("附录 B 表 B.1", b.label)
        self.assertIn("个人电话号码", b.gist)
        self.assertIn("范围宽于 PIPL", b.gist)
        self.assertIn("不得直接等同", COMP.LEVEL_NOTE)

    def test_gb35273_appendix_a_lists_device_information(self):
        a = COMP.REFS["GB-A1"]
        self.assertIn("附录 A 表 A.1", a.label)
        for term in ("硬件序列号", "MAC", "IMEI", "IDFA", "IMSI"):
            self.assertIn(term, a.gist)

    def test_standard_clause_numbers(self):
        """6.3 加密、6.2 去标识化、7.2 展示限制、10.1 应急、11.4 影响评估。"""
        self.assertEqual(COMP.REFS["GB-6.3"].article, "6.3")
        self.assertIn("加密", COMP.REFS["GB-6.3"].gist)
        self.assertIn("去标识化", COMP.REFS["GB-6.2"].gist)
        self.assertIn("展示", COMP.REFS["GB-7.2"].gist)
        self.assertEqual(COMP.REFS["GB-11.4"].article, "11.4")
        self.assertEqual(COMP.REFS["GB-10.1"].article, "10.1")

    def test_pipl_55_five_scenarios_and_merged_item_3(self):
        g = COMP.REFS["PIPL-55"].gist
        self.assertIn("事前", g)
        self.assertIn("敏感个人信息", g)
        self.assertIn("自动化决策", g)
        self.assertIn("委托处理", g)
        self.assertIn("向境外提供", g)
        self.assertIn("不可拆成三类", g)

    def test_pipl_56_three_year_retention(self):
        self.assertIn("至少保存三年", COMP.REFS["PIPL-56"].gist)

    def test_safety_incident_is_57_not_47(self):
        """PIPL 第 47 条是「删除」，安全事件补救与通知是第 57 条。"""
        self.assertIn("补救", COMP.REFS["PIPL-57"].gist)
        self.assertIn("通知", COMP.REFS["PIPL-57"].gist)
        self.assertNotIn("PIPL-47", COMP.REFS)

    def test_csl_42_and_dsl_clauses(self):
        self.assertIn("立即采取补救措施", COMP.REFS["CSL-42"].gist)
        self.assertIn("分类分级", COMP.REFS["DSL-21"].gist)
        self.assertIn("全流程", COMP.REFS["DSL-27"].gist)
        self.assertIn("安全事件", COMP.REFS["DSL-29"].gist)

    def test_version_and_disclaimer_are_present(self):
        self.assertIn("以申报或出具报告时生效版本为准", COMP.VERSION_NOTE)
        self.assertIn("不构成正式法律意见", COMP.DISCLAIMER)
        self.assertIn("律师结合", COMP.DISCLAIMER)
        self.assertIn("待补充", COMP.DISCLAIMER)

    def test_gaps_are_explicit(self):
        self.assertTrue(any("合法性基础" in g for g in COMP.GAPS))
        self.assertTrue(any("境外提供" in g for g in COMP.GAPS))
        self.assertTrue(any("三年" in g for g in COMP.GAPS))


class TestClassification(unittest.TestCase):
    def test_id_card_and_bank_card_are_pipl_sensitive(self):
        for e in ("ID_CARD", "BANK_CARD"):
            c = COMP.for_entity(e)
            self.assertEqual(c.data_category, "pipl_sensitive")
            self.assertEqual(c.pia_trigger, "triggered")
            self.assertIn("PIPL-28", c.refs)

    def test_phone_and_email_are_gb_sensitive_only(self):
        """关键口径差异：国标敏感但法律口径为一般个人信息。"""
        for e in ("PHONE", "EMAIL"):
            c = COMP.for_entity(e)
            self.assertEqual(c.data_category, "gb_sensitive", e)
            self.assertIn("一般个人信息", c.pipl_class, e)
            self.assertIn("个人敏感信息", c.gb35273_class, e)
            self.assertIn("口径差异", c.caveat, e)
            self.assertEqual(c.pia_trigger, "conditional", e)
            self.assertNotIn("PIPL-28", c.refs, e)

    def test_device_identifiers_are_not_pipl_sensitive(self):
        for e in ("IMEI", "IMSI", "IDFA", "OAID", "MAC", "DEVICE_SN"):
            c = COMP.for_entity(e)
            self.assertEqual(c.data_category, "device_identifier", e)
            self.assertIn("非法定敏感", c.pipl_class, e)
            self.assertNotIn("PIPL-28", c.refs, e)

    def test_credentials_are_not_personal_information(self):
        for e in ("API_KEY", "PRIVATE_KEY", "DB_CREDENTIAL", "IOT_DEVICE_SECRET",
                  "TOKEN", "SESSION_ID", "PASSWORD", "OTP", "OSS_SIGNED_URL"):
            c = COMP.for_entity(e)
            self.assertEqual(c.data_category, "credential", e)
            self.assertIn("非个人信息", c.pipl_class, e)
            self.assertEqual(c.pia_trigger, "not_applicable", e)
            self.assertNotIn("PIPL-28", c.refs, e)
            self.assertNotIn("PIPL-51", c.refs, e)
            self.assertIn("CSL-42", c.refs, e)

    def test_account_credentials_have_manual_review_caveat(self):
        for e in ("PASSWORD", "OTP", "SESSION_ID", "TOKEN"):
            self.assertIn("附录 B", COMP.for_entity(e).caveat)

    def test_unknown_entity_does_not_invent_law(self):
        c = COMP.for_entity("MY_CORP_THING")
        self.assertEqual(c.data_category, "unclassified")
        self.assertEqual(c.refs, ())
        self.assertTrue(COMP.annotate("MY_CORP_THING")["needs_review"])
        self.assertEqual(COMP.annotate("MY_CORP_THING")["references"], [])

    def test_payload_counts(self):
        p = COMP.build_payload(["ID_CARD", "PHONE", "API_KEY", "IMEI"])
        s = p["summary"]
        self.assertEqual(s["pipl_sensitive_count"], 1)
        self.assertEqual(s["gb_sensitive_count"], 1)
        self.assertEqual(s["credential_count"], 1)
        self.assertEqual(s["by_pia_trigger"]["triggered"], 1)
        self.assertEqual(len(p["legal_catalog"]), len(COMP.REFS))
        self.assertEqual(p["gaps"], list(COMP.GAPS))


class TestReportIntegration(unittest.TestCase):
    def _result(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "a.log").write_text(
                "idcard: 11010519491231002X\nphone: 13800138000\n", encoding="utf-8"
            )
            return scan([str(d / "a.log")])

    def test_json_has_machine_readable_compliance(self):
        r = self._result()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            write_json(r, p)
            doc = json.loads(p.read_text(encoding="utf-8"))
        self.assertIn("compliance", doc)
        self.assertIn("legal_catalog", doc["compliance"])
        self.assertIn("summary", doc["compliance"])
        self.assertIn("gaps", doc["compliance"])
        self.assertIsNone(doc["baseline"])
        for f in doc["findings"]:
            self.assertIn("compliance", f)
            self.assertIn("fingerprint", f)
            self.assertIn("data_category", f["compliance"])

    def test_all_formats_carry_compliance_and_no_plaintext_when_redacted(self):
        r = self._result()
        sentinel = "Zx" + "9!Kq" + "7mN" + "p2wR"     # 打散，避免凭据字面量
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "b.log").write_text("password=" + sentinel + "\n", encoding="utf-8")
            r2 = scan([str(d / "b.log")])
            out = write_all(r2, d / "out", ("json", "csv", "sarif", "html"), redact=True)
            blob = "".join(p.read_text(encoding="utf-8", errors="replace") for p in out)
            self.assertNotIn(sentinel, blob)
            self.assertIn("GB/T 35273", blob)
            self.assertIn("第 28 条", blob)
            for p in out:
                if p.suffix == ".csv":
                    head = p.read_text(encoding="utf-8-sig").splitlines()[0]
                    for col in ("data_category", "pipl_class", "gb35273_class",
                                "pia_trigger", "compliance_refs", "fingerprint"):
                        self.assertIn(col, head)


if __name__ == "__main__":
    unittest.main()
