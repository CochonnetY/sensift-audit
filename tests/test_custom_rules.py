"""外部规则文件：格式校验、非法输入拦截、端到端检出与报告集成。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from senscan import custom_rules as CR
from senscan.detectors import detect
from senscan.report import write_json
from senscan.rules import RULES
from senscan.scanner import scan

_GOOD = {
    "id": "corp-internal-token",
    "entity": "TOKEN",
    "pattern": r"corp_tok_([A-Za-z0-9]{24,})",
    "risk": "high",
    "base_confidence": 0.9,
    "validators": ["not_placeholder"],
    "context_validators": ["not_numeric_field"],
    "flags": ["IGNORECASE"],
    "note": "内部令牌",
    "remediation": "到内部平台轮换",
}
# 运行期拼接，避免测试里出现形似真实凭据的连续字面量
_TOKEN = "corp_tok_" + "Zx9Kq7mNp2wR5tY8uI1oP3aS4d"


class TestValidation(unittest.TestCase):
    def test_valid_rules_merge_with_builtins(self):
        rules = CR.load_text(json.dumps([_GOOD]))
        self.assertEqual(len(rules), len(RULES) + 1)
        self.assertEqual(rules[-1].id, "corp-internal-token")
        self.assertEqual(rules[-1].risk.value, "high")
        self.assertEqual(rules[-1].base_confidence, 0.9)
        self.assertTrue(rules[-1].flags)
        self.assertEqual(rules[-1].validators, ("not_placeholder",))

    def test_object_form_and_multiple_rules(self):
        rows = [_GOOD, dict(_GOOD, id="corp-second", pattern=r"corp2_([A-Z0-9]{16,})")]
        rules = CR.load_text(json.dumps({"rules": rows}))
        self.assertEqual(len(rules), len(RULES) + 2)

    def test_rejects_bad_inputs(self):
        bad = {
            "坏正则": [dict(_GOOD, pattern="([")],
            "重复内置 id": [dict(_GOOD, id="github-pat")],
            "文件内重复 id": [_GOOD, _GOOD],
            "未知校验器": [dict(_GOOD, validators=["exec_shell"])],
            "上下文校验器用错表": [dict(_GOOD, context_validators=["luhn"])],
            "非法 risk": [dict(_GOOD, risk="super")],
            "置信度越界": [dict(_GOOD, base_confidence=1.5)],
            "非法 entity": [dict(_GOOD, entity="not_VALID")],
            "非法 id": [dict(_GOOD, id="../etc/passwd")],
            "未知 flag": [dict(_GOOD, flags=["EXEC"])],
            "非字符串 validators": [dict(_GOOD, validators=["valid", 3])],
            "超长 pattern": [dict(_GOOD, pattern="a" * 5000)],
            "非 JSON": "not json",
            "空数组": [],
            "非数组对象": {"rules": "nope"},
        }
        for name, payload in bad.items():
            text = payload if isinstance(payload, str) else json.dumps(payload)
            with self.subTest(name=name):
                with self.assertRaises(CR.RuleFileError):
                    CR.load_text(text)

    def test_file_limits(self):
        rows = [dict(_GOOD, id=f"r{i}") for i in range(CR.MAX_RULES + 1)]
        with self.assertRaises(CR.RuleFileError):
            CR.load_text(json.dumps(rows))

    def test_file_not_found(self):
        with self.assertRaises(CR.RuleFileError):
            CR.load("/definitely/not/here/rules.json")


class TestEndToEnd(unittest.TestCase):
    def test_custom_rule_detects_value(self):
        rules = CR.load_text(json.dumps([_GOOD]))
        got = detect(_TOKEN, "x.log", 0.55, {}, rules=rules)
        self.assertTrue(any(f.rule_id == "corp-internal-token" for f in got))
        # 内置规则集下不应命中
        self.assertFalse(any(f.rule_id == "corp-internal-token"
                             for f in detect(_TOKEN, "x.log", 0.55, {}, rules=RULES)))

    def test_scan_uses_custom_rules_everywhere(self):
        """普通文本、容器、大文件三条通道都应透传 rules。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            rules = CR.load_text(json.dumps([_GOOD]))
            (d / "a.log").write_text(_TOKEN + "\n", encoding="utf-8")
            r = scan([str(d / "a.log")], rules=rules)
            self.assertTrue(any(f.rule_id == "corp-internal-token" for f in r.findings))
            self.assertEqual(len(r.rules_used), len(RULES) + 1)

            # 容器通道：zip 里的文本也走同一规则集
            import zipfile
            zp = d / "bundle.zip"
            with zipfile.ZipFile(zp, "w") as z:
                z.writestr("inner.txt", _TOKEN + "\n")
            rc = scan([str(zp)], rules=rules)
            self.assertTrue(any(f.rule_id == "corp-internal-token" for f in rc.findings))

    def test_report_catalog_reflects_custom_rules(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            rules = CR.load_text(json.dumps([_GOOD]))
            (d / "a.log").write_text(_TOKEN + "\n", encoding="utf-8")
            r = scan([str(d / "a.log")], rules=rules)
            p = d / "out.json"
            write_json(r, p)
            doc = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(doc["scan"]["rules_total"], len(RULES) + 1)
            self.assertEqual(doc["scan"]["custom_rules"], 1)
            self.assertTrue(any(x["id"] == "corp-internal-token" and x["custom"]
                                for x in doc["rule_catalog"]))

    def test_unknown_entity_compliance_is_review_flagged(self):
        """自定义实体未收录时报告应标「需人工判定」，不编造法条。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            custom = dict(_GOOD, entity="CORP_SECRET_THING")
            rules = CR.load_text(json.dumps([custom]))
            (d / "a.log").write_text(_TOKEN + "\n", encoding="utf-8")
            r = scan([str(d / "a.log")], rules=rules)
            p = d / "out.json"
            write_json(r, p)
            doc = json.loads(p.read_text(encoding="utf-8"))
            f = doc["findings"][0]
            self.assertEqual(f["compliance"]["data_category"], "unclassified")
            self.assertTrue(f["compliance"]["needs_review"])
            self.assertEqual(f["compliance"]["references"], [])


if __name__ == "__main__":
    unittest.main()
