"""增量对比三态：身份键、脱敏基线、坏文件、报告输出。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from senscan import baseline as BL
from senscan.report import write_json
from senscan.scanner import scan


def _scan(text: str, root: Path, name: str = "a.log"):
    p = root / name
    p.write_text(text, encoding="utf-8")
    return scan([str(p)])


class TestBaseline(unittest.TestCase):
    def test_three_states(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            r1 = _scan("password=AlphaBetaGamma123\npassword=SecondValue45678\n", d)
            p = d / "base.json"
            write_json(r1, p)
            items, meta = BL.load(p)
            self.assertEqual(meta["baseline_total"], len(r1.findings))
            self.assertFalse(meta["degraded"], "新版报告应写入 fingerprint")

            # 删一条、加一条 → new 1 / persistent 1 / fixed 1
            r2 = _scan("password=AlphaBetaGamma123\npassword=ThirdValue999999\n", d, "b.log")
            blk = BL.compare(r2.findings, (items, meta))
            self.assertEqual(blk["counts"], {"new": 1, "persistent": 1, "fixed": 1})
            self.assertEqual(len(blk["new"]), 1)
            self.assertEqual(len(blk["fixed"]), 1)
            st = [BL.status_for(blk, f) for f in r2.findings]
            self.assertCountEqual(st, ["new", "persistent"])

    def test_identity_ignores_file_location(self):
        """同一个值换文件仍算「仍在」，不能当成新增。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            r1 = _scan("password=AlphaBetaGamma123\n", d, "one.log")
            p = d / "base.json"
            write_json(r1, p)
            r2 = _scan("password=AlphaBetaGamma123\n", d, "two.log")
            blk = BL.compare(r2.findings, BL.load(p))
            self.assertEqual(blk["counts"], {"new": 0, "persistent": 1, "fixed": 0})

    def test_redacted_baseline_still_aligns(self):
        """基线是 --redact 生成时，靠 fingerprint 仍能对齐，不退化。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            r1 = _scan("password=AlphaBetaGamma123456\n", d)
            p = d / "base.json"
            write_json(r1, p, True)
            items, meta = BL.load(p)
            self.assertTrue(meta["redacted"])
            self.assertFalse(meta["degraded"])
            r2 = _scan("password=AlphaBetaGamma123456\n", d, "b.log")
            blk = BL.compare(r2.findings, (items, meta))
            self.assertEqual(blk["counts"]["persistent"], 1)
            self.assertEqual(blk["counts"]["new"], 0)

    def test_fixed_values_are_redacted_when_requested(self):
        """明文基线 + 本次脱敏时，「已修复」里的历史值不能漏出去。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            secret = "Plain" + "TextSecret" + "987654321"
            r1 = _scan("password=" + secret + "\n", d)
            p = d / "base.json"
            write_json(r1, p, False)           # 基线为明文报告
            r2 = _scan("nothing here\n", d, "b.log")
            blk = BL.compare(r2.findings, BL.load(p), redact=True)
            self.assertEqual(blk["counts"]["fixed"], 1)
            self.assertNotIn(secret, json.dumps(blk, ensure_ascii=False))

    def test_legacy_report_degrades_loudly(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "old.json"
            p.write_text(json.dumps({
                "tool": "senscan",
                "scan": {"started_at": "2026-01-01T00:00:00", "redacted": False},
                "findings": [{"entity": "TOKEN", "value": "legacy-value-123456",
                              "rule_id": "generic-token", "source": "x.log"}],
            }), encoding="utf-8")
            items, meta = BL.load(p)
            self.assertTrue(meta["degraded"])
            blk = BL.compare([], (items, meta))
            self.assertIn("可能不准", blk["note"])

    def test_bad_baseline_files(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            with self.assertRaises(BL.BaselineError):
                BL.load(d / "missing.json")
            p = d / "bad.json"
            p.write_text("not json", encoding="utf-8")
            with self.assertRaises(BL.BaselineError):
                BL.load(p)
            p.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
            with self.assertRaises(BL.BaselineError):
                BL.load(p)

    def test_status_for_returns_none_without_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            r = _scan("password=AlphaBetaGamma123\n", Path(td))
            self.assertIsNone(BL.status_for(None, r.findings[0]))

    def test_scan_result_embeds_baseline_block(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            r1 = _scan("password=AlphaBetaGamma123\n", d)
            p = d / "base.json"
            write_json(r1, p)
            r2 = scan([str(d / "a.log")], baseline_path=p)
            self.assertIsNotNone(r2.baseline_block)
            self.assertEqual(r2.baseline_block["counts"]["persistent"], 1)
            # 对外视图不含内部索引
            from senscan.report import _payload
            doc = _payload(r2, False)
            self.assertNotIn("status_by_key", doc["baseline"])
            self.assertEqual(doc["baseline"]["counts"]["persistent"], 1)


if __name__ == "__main__":
    unittest.main()
