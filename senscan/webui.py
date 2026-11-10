"""senscan 本地可视化工作台（零第三方依赖）。

只监听 127.0.0.1。因为报告里含明文凭据，服务做了三层防护：
1. Host 头白名单（挡 DNS rebinding）；
2. 一次性 token 注入页面，所有 /api/* 请求必须携带（挡第三方页面静默读取）；
3. 不设置任何 CORS 头，CSP 只允许本页内联脚本与同源连接。

扫描在后台线程执行，前端轮询进度；结果保存在进程内存中，不落盘（导出时才写）。
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import tempfile
import threading
import traceback
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import pcap as pcapmod
from . import report
from . import verify as VER
from .rules import RULES
from .scanner import ScanCancelled, ScanResult, scan
from .version import __version__
from .whitelist import Whitelist

_WEB_DIR = Path(__file__).with_name("web")
_PORT = 8777
_TOKEN = ""
_AUDIT_PATH = Path("senscan-verify-audit.jsonl")
_FORMATS = {
    "json": ("application/json; charset=utf-8", report.write_json),
    "csv": ("text/csv; charset=utf-8", report.write_csv),
    "sarif": ("application/sarif+json; charset=utf-8", report.write_sarif),
    "html": ("text/html; charset=utf-8", report.write_html),
}


@dataclass
class Job:
    id: str
    status: str = "running"          # running | done | error | cancelled
    phase: str = "准备中"
    message: str = ""
    result: ScanResult | None = None
    error: str = ""
    options: dict[str, Any] = field(default_factory=dict)
    progress: int = 0
    total_files: int = 0
    cancelled: bool = False
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


STATE: dict[str, Any] = {"jobs": {}, "last": None}
_LOCK = threading.Lock()


# ---------------------------------------------------------------- 业务


def _workspace_demo() -> list[str]:
    for base in (Path.cwd(), Path(__file__).resolve().parent.parent):
        p = base / "demo" / "samples"
        if p.is_dir():
            return [str(p)]
    return []


def state_payload() -> dict[str, Any]:
    return {
        "version": __version__,
        "rules_total": len(RULES),
        "tshark": pcapmod.tshark_path() is not None,
        "cwd": str(Path.cwd()),
        "demo_paths": _workspace_demo(),
        "endpoints": VER.endpoint_catalog(),
        "audit_path": str(_AUDIT_PATH),
        "has_result": STATE.get("last") is not None,
        "last_job_id": STATE.get("last"),
    }


def rules_payload(q: str) -> dict[str, Any]:
    q = q.strip().lower()
    rows = [
        {
            "id": r.id, "entity": r.entity, "category": r.category,
            "risk": r.risk.value, "source": r.source,
            "note": r.note, "remediation": r.remediation,
            "context_required": r.context_required,
        }
        for r in RULES
        if not q or q in " ".join([r.id, r.entity, r.source, r.note, r.category]).lower()
    ]
    return {"total": len(RULES), "rows": rows}


def browse_payload(raw: str) -> dict[str, Any]:
    p = Path(raw).expanduser() if raw else Path.cwd()
    if not p.exists():
        raise FileNotFoundError(f"路径不存在：{p}")
    if p.is_file():
        p = p.parent
    entries = []
    try:
        children = sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
    except PermissionError as exc:
        raise PermissionError(f"无权读取该目录：{p}") from exc
    for c in children[:400]:
        if c.name.startswith(".") and c.name != ".workbuddy":
            continue
        entries.append({"name": c.name, "path": str(c), "dir": c.is_dir()})
    return {
        "path": str(p),
        "parent": str(p.parent) if p.parent != p else "",
        "entries": entries,
        "truncated": len(children) > 400,
    }


def _run_scan(job: Job, opts: dict[str, Any]) -> None:
    try:
        paths = [Path(x) for x in opts.get("paths", []) if str(x).strip()]
        if not paths:
            raise ValueError("请至少填写一个待扫描路径")
        job.phase = "枚举目标…"
        # 不预先跑一遍 iter_targets：目录很大时会重复遍历一次磁盘。
        # 真实文件数由 scan 的进度回调带回来。
        wl = Whitelist.from_text(opts.get("whitelist_text") or "")
        vconf = dict(opts.get("verify") or {})
        cfg = None
        if vconf.get("local") or vconf.get("online"):
            if vconf.get("online") and not vconf.get("audit_path"):
                vconf["audit_path"] = str(_AUDIT_PATH)
            cfg = VER.VerifyConfig.from_dict(vconf)
            cfg.validate()
        if cfg is not None and cfg.online:
            job.phase = "扫描中 · 完成后执行在线验证"

        def on_progress(done: int, total: int, path: Path) -> bool:
            if job.cancelled:
                return False
            job.progress, job.total_files = done, total
            job.phase = f"扫描中 {done}/{total} · {path.name}"
            return True

        result = scan(
            paths,
            whitelist=wl,
            min_confidence=float(opts.get("min_confidence", 0.55)),
            include_binary=bool(opts.get("include_binary")),
            max_file_mb=int(opts.get("max_file_mb", 512)),
            enable_pcap=not bool(opts.get("no_pcap")),
            verify_config=cfg,
            on_progress=on_progress,
        )
        if job.cancelled:  # 文件数为 0 时回调不会触发，也要响应停止
            raise ScanCancelled("扫描已停止")
        job.result = result
        job.status = "done"
        job.phase = "完成"
        job.message = f"{len(result.findings)} 条命中 / {result.stats.files_scanned} 文件 / {result.duration_ms} ms"
        with _LOCK:
            STATE["last"] = job.id
    except ScanCancelled:
        job.status = "cancelled"
        job.phase = "已停止"
        job.message = f"已处理 {job.progress} 个文件后停止"
    except Exception as exc:
        job.status = "error"
        job.phase = "失败"
        job.error = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()


def start_scan(opts: dict[str, Any]) -> dict[str, Any]:
    jid = secrets.token_hex(6)
    job = Job(id=jid, options=opts)
    with _LOCK:
        STATE["jobs"][jid] = job
        if len(STATE["jobs"]) > 12:
            for k in list(STATE["jobs"])[:-12]:
                STATE["jobs"].pop(k, None)
            # last 可能指向刚被淘汰的任务；留着会让页面初始化拿到 400。
            if STATE.get("last") not in STATE["jobs"]:
                STATE["last"] = None
    threading.Thread(target=_run_scan, args=(job, opts), daemon=True).start()
    return {"job_id": jid}


def cancel_scan(jid: str) -> dict[str, Any]:
    job = STATE["jobs"].get(jid)
    if job is None:
        raise KeyError("任务不存在")
    if job.status != "running":
        return {"ok": True, "status": job.status}
    job.cancelled = True
    job.phase = "正在停止…"
    return {"ok": True, "status": "stopping"}


def result_payload(jid: str, redact: bool = False) -> dict[str, Any]:
    job = STATE["jobs"].get(jid)
    if job is None or job.result is None:
        raise KeyError("结果不存在或扫描尚未完成")
    return report._payload(job.result, redact)  # noqa: SLF001 —— 同包内复用唯一的数据出口


def export_bytes(jid: str, fmt: str, redact: bool) -> tuple[bytes, str, str]:
    if fmt not in _FORMATS:
        raise ValueError(f"不支持的格式：{fmt}")
    job = STATE["jobs"].get(jid)
    if job is None or job.result is None:
        raise KeyError("结果不存在")
    ctype, writer = _FORMATS[fmt]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / f"senscan-{stamp}.{fmt}"
        writer(job.result, p, redact)
        data = p.read_bytes()
    return data, ctype, f"senscan-{stamp}.{fmt}"


def verify_selection(payload: dict[str, Any]) -> dict[str, Any]:
    """对已扫描结果里选中的命中单独发起在线验证（需前端二次确认）。"""
    jid = str(payload.get("job_id", ""))
    job = STATE["jobs"].get(jid)
    if job is None or job.result is None:
        raise KeyError("结果不存在")
    cfg = VER.VerifyConfig.from_dict(payload.get("config") or {})
    cfg.local = False
    cfg.online = True
    if not cfg.audit_path:
        cfg.audit_path = _AUDIT_PATH
    cfg.validate()
    idxs = payload.get("indices") or []
    subset = [job.result.findings[i] for i in idxs if isinstance(i, int) and 0 <= i < len(job.result.findings)]
    summary = VER.run(subset, cfg)
    old = dict(job.result.verification or {})
    merged = dict(old)
    for k, v in summary.to_dict().items():
        if isinstance(v, int):
            merged[k] = int(old.get(k, 0) or 0) + v
        elif k == "endpoints":
            merged[k] = sorted(set(list(old.get(k, []) or []) + v))
        else:
            merged[k] = v
    merged["enabled_online"] = True
    job.result.verification = merged
    job.result.findings.sort(key=lambda x: (
        {"P0": 0, "P1": 1, "P2": 2}[x.priority], x.risk.order, -x.confidence, x.source, x.line,
    ))
    return {
        "verification": merged,
        "by_liveness": job.result.by_liveness,
        "updated": [VER.liveness_of(f) for f in subset],
    }


def audit_payload() -> dict[str, Any]:
    if not _AUDIT_PATH.exists():
        return {"rows": [], "path": str(_AUDIT_PATH)}
    lines = _AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    rows.reverse()
    return {"rows": rows, "path": str(_AUDIT_PATH)}


# ---------------------------------------------------------------- HTTP


class Handler(BaseHTTPRequestHandler):
    server_version = "senscan-ui"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in {f"127.0.0.1:{_PORT}", f"localhost:{_PORT}"}

    def _auth_ok(self) -> bool:
        return self._host_ok() and hmac.compare_digest(
            self.headers.get("X-Senscan-Token", ""), _TOKEN
        )

    def _body(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n <= 0 or n > 2 * 1024 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_GET(self) -> None:  # noqa: N802
        u = urlsplit(self.path)
        if u.path in ("/", "/index.html"):
            if not self._host_ok():
                self._send(403, b"forbidden", "text/plain; charset=utf-8")
                return
            try:
                raw = (_WEB_DIR / "index.html").read_text(encoding="utf-8")
            except OSError as exc:
                self._send(500, str(exc).encode(), "text/plain; charset=utf-8")
                return
            html = raw.replace("__SENSCAN_TOKEN__", _TOKEN).replace("__SENSCAN_VERSION__", __version__)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        if u.path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if not self._auth_ok():
            self._json({"error": "未授权：Host 或 token 校验失败"}, 403)
            return
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == "/api/state":
                self._json(state_payload())
            elif u.path == "/api/job":
                job = STATE["jobs"].get(q.get("id", ""))
                if job is None:
                    self._json({"error": "任务不存在"}, 404)
                else:
                    self._json({"id": job.id, "status": job.status, "phase": job.phase,
                                "message": job.message, "error": job.error,
                                "progress": job.progress, "total_files": job.total_files,
                                "created_at": job.created_at})
            elif u.path == "/api/result":
                self._json(result_payload(q.get("id", ""), q.get("redact") == "1"))
            elif u.path == "/api/rules":
                self._json(rules_payload(q.get("q", "")))
            elif u.path == "/api/audit":
                self._json(audit_payload())
            elif u.path == "/api/export":
                data, ctype, name = export_bytes(q.get("id", ""), q.get("fmt", "html"),
                                                 q.get("redact") == "1")
                self._send(200, data, ctype, {
                    "Content-Disposition": f'attachment; filename="{name}"',
                })
            else:
                self._json({"error": "未知接口"}, 404)
        except (KeyError, ValueError, FileNotFoundError, PermissionError) as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:  # 单个请求失败不应打挂服务
            traceback.print_exc()
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth_ok():
            self._json({"error": "未授权：Host 或 token 校验失败"}, 403)
            return
        u = urlsplit(self.path)
        payload = self._body()
        # 在线验证会把命中凭据明文发往外部服务。前端的授权勾选只是 UX，
        # 服务端必须独立复核，否则直接 POST /api/verify 即可绕过并外带凭据。
        if u.path in ("/api/scan", "/api/verify"):
            v = payload.get("verify") or {}
            c = payload.get("config") or {}
            if bool(v.get("online")) or bool(c.get("online")):
                if (payload.get("authorized") is not True
                        or str(payload.get("confirm_phrase", "")).strip() != "允许在线验证"):
                    self._json({"error": "在线验证需显式授权：勾选授权并输入确认短语"}, 403)
                    return
                if not (v.get("allow_public") or c.get("allow_public")):
                    self._json({"error": "在线验证需显式确认公网端点授权"}, 403)
                    return
        try:
            if u.path == "/api/scan":
                self._json(start_scan(payload))
            elif u.path == "/api/browse":
                self._json(browse_payload(str(payload.get("path", ""))))
            elif u.path == "/api/cancel":
                self._json(cancel_scan(str(payload.get("job_id", ""))))
            elif u.path == "/api/verify":
                self._json(verify_selection(payload))
            else:
                self._json({"error": "未知接口"}, 404)
        except (KeyError, ValueError, FileNotFoundError, PermissionError, VER.VerifyPolicyError) as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv: list[str] | None = None) -> int:
    global _PORT, _TOKEN, _AUDIT_PATH
    ap = argparse.ArgumentParser(prog="senscan ui", description="启动本地工作台")
    ap.add_argument("--port", type=int, default=8777, help="端口（默认 8777，仅本机）")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    ap.add_argument("--audit", default="senscan-verify-audit.jsonl", help="审计日志路径")
    args = ap.parse_args(argv)

    _PORT = args.port
    _TOKEN = secrets.token_urlsafe(28)
    _AUDIT_PATH = Path(args.audit)
    url = f"http://127.0.0.1:{_PORT}/"
    server = Server(("127.0.0.1", _PORT), Handler)
    print(f"senscan {__version__} → {url}")
    print("仅监听本机 · Ctrl+C 结束 · 审计：", _AUDIT_PATH)
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
