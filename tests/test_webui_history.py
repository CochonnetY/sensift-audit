"""工作台「不保存扫描记录 / 删除测试历史 / 可导出」回归测试。

对应三条语义，防止后续把自动恢复或历史累积重新打开：
1. state_payload 不暴露 last_job_id，页面刷新不会恢复上次结果；
2. start_scan 只保留当前一次，不累积历史任务；
3. clear_history 清空内存结果、取消运行中任务、删除审计日志，但保留导出能力。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from senscan import webui
from senscan.scanner import ScanResult, ScanStats


def _empty_result() -> ScanResult:
    return ScanResult([], ScanStats(), [], "now", 0, 0.55)


class TestNoSavedHistory(unittest.TestCase):
    def setUp(self):
        self._jobs = webui.STATE["jobs"]
        webui.STATE["jobs"] = {}
        self._audit = webui._AUDIT_PATH

    def tearDown(self):
        webui.STATE["jobs"] = self._jobs
        webui._AUDIT_PATH = self._audit

    def _done_job(self, jid: str):
        return webui.Job(id=jid, status="done", result=_empty_result())

    def test_state_does_not_expose_last_job(self):
        webui.STATE["jobs"]["old"] = self._done_job("old")
        st = webui.state_payload()
        self.assertNotIn("last_job_id", st)
        self.assertNotIn("has_result", st)

    def test_clear_removes_jobs_and_cancels_running(self):
        with tempfile.TemporaryDirectory() as td:
            webui._AUDIT_PATH = Path(td) / "audit.jsonl"
            webui._AUDIT_PATH.write_text('{"v":1}\n', encoding="utf-8")
            webui.STATE["jobs"]["a"] = self._done_job("a")
            webui.STATE["jobs"]["b"] = self._done_job("b")
            running = webui.Job(id="c", status="running")
            webui.STATE["jobs"]["c"] = running

            r = webui.clear_history()

            self.assertTrue(r["ok"])
            self.assertEqual(r["cleared"], 3)
            self.assertEqual(r["running_cancelled"], 1)
            self.assertTrue(running.cancelled)
            self.assertEqual(webui.STATE["jobs"], {})
            self.assertFalse(webui._AUDIT_PATH.exists())
            self.assertTrue(r["audit_removed"])

    def test_clear_can_keep_audit_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "audit.jsonl"
            p.write_text('{"v":1}\n', encoding="utf-8")
            webui._AUDIT_PATH = p
            r = webui.clear_history(include_audit=False)
            self.assertFalse(r["audit_removed"])
            self.assertTrue(p.exists())

    def test_clear_does_not_delete_exported_reports(self):
        # 导出结果落在用户自己的工作目录，清空按钮只管工作台内存数据
        with tempfile.TemporaryDirectory() as td:
            exported = Path(td) / "senscan-20260101.json"
            exported.write_text("{}", encoding="utf-8")
            webui._AUDIT_PATH = Path(td) / "audit.jsonl"
            webui.clear_history()
            self.assertTrue(exported.exists())

    def test_start_scan_drops_previous_results(self):
        """新扫描开始时旧结果必须被丢弃，不能留成「历史记录」。"""
        webui.STATE["jobs"]["old"] = self._done_job("old")
        seen: dict = {}

        def fake_thread(target, args, daemon):
            seen["target"] = target
            seen["args"] = args
            return Mock()

        with patch.object(webui, "_preflight", return_value=None), \
             patch.object(webui.threading, "Thread", side_effect=fake_thread):
            r = webui.start_scan({"paths": ["demo/samples"]})

        self.assertIn("job_id", r)
        self.assertEqual(set(webui.STATE["jobs"]), {r["job_id"]})
        self.assertNotIn("old", webui.STATE["jobs"])
        self.assertEqual(seen["args"][0].id, r["job_id"])

    def test_export_still_works_after_change(self):
        """不保存记录不等于不能导出：当前这一次结果仍可生成报告。"""
        job = webui.Job(id="cur", status="done", result=_empty_result())
        webui.STATE["jobs"]["cur"] = job
        data, _ctype, name = webui.export_bytes("cur", "json", False)
        self.assertGreater(len(data), 50)
        self.assertTrue(name.endswith(".json"))


if __name__ == "__main__":
    unittest.main()
