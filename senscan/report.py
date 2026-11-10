"""报告输出：JSON（完整）、CSV（合规评审）、SARIF（CI 集成）、HTML（评审）、控制台摘要。"""

from __future__ import annotations

import csv
import json
import os
import sys
import unicodedata
from datetime import datetime
from typing import Any
from pathlib import Path

from . import utils as U
from . import verify as VER
from .models import CATEGORY_LABEL, Finding
from .report_html import write_html
from .rules import RULES
from .scanner import ScanResult
from .version import __version__

_ANSI = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
    "dim": "\033[90m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _c(text: str, key: str) -> str:
    if not _use_color() or key not in _ANSI:
        return text
    return f"{_ANSI[key]}{text}{_ANSI['reset']}"


def _width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in s)


def _pad(s: str, n: int) -> str:
    w = _width(s)
    return s + " " * max(0, n - w) if w < n else _truncate(s, n)


def _truncate(s: str, n: int) -> str:
    if _width(s) <= n:
        return s
    out = ""
    w = 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if w + cw > n - 1:
            break
        out += ch
        w += cw
    return out + "…"


def _display_value(f: Finding, redact: bool) -> str:
    v = U.redact(f.value, 4) if redact else f.value
    flat = v.replace("\r", " ").replace("\n", "⏎")
    return flat if len(flat) <= 80 else flat[:80] + "…"


# ---------------------------------------------------------------- JSON


def _rule_catalog() -> list[dict]:
    return [
        {
            "id": r.id,
            "entity": r.entity,
            "category": r.category,
            "risk": r.risk.value,
            "source": r.source,
        }
        for r in RULES
    ]


def _payload(result: ScanResult, redact: bool) -> dict:
    findings = []
    for f in result.findings:
        d = f.to_dict()
        if redact:
            d["value"] = U.redact(f.value, 4)
            d["context"] = U.redact(f.context, 8)
        findings.append(d)
    return {
        "tool": "senscan",
        "version": __version__,
        "scan": {
            "targets": result.targets,
            "started_at": result.started_at,
            "duration_ms": result.duration_ms,
            "min_confidence": result.min_confidence,
            "rules_total": len(RULES),
            "whitelist_entries": result.whitelist_size,
            "redacted": redact,
        },
        "stats": {
            "files_scanned": result.stats.files_scanned,
            "files_skipped": result.stats.files_skipped,
            "bytes_read": result.stats.bytes_read,
            "candidates": result.stats.candidates,
            "rejected_by_validator": result.stats.rejected,
            "suppressed": result.stats.suppressed,
            "suppressed_no_context": result.stats.suppressed_context,
            "suppressed_low_confidence": result.stats.suppressed_threshold,
            "whitelisted": result.stats.whitelisted,
        },
        "summary": {
            "total": len(findings),
            "by_risk": result.by_risk,
            "by_category": result.by_category,
            "by_priority": result.by_priority,
            "by_validation": result.by_validation,
            "by_liveness": result.by_liveness,
            "by_entity": result.by_entity,
            "iot_triplet_files": result.iot_triplet_files,
            "by_file": [
                {"file": src, "count": n, "max_risk": risk, "risk_score": score}
                for src, n, risk, score in result.by_file
            ],
            "spread_values": [
                {"entity": e, "value": v, "files": sorted(set(srcs))}
                for e, v, srcs in result.spread_values
            ],
        },
        "verification": result.verification,
        "findings": findings,
        "rule_catalog": _rule_catalog(),
    }


def write_json(result: ScanResult, path: Path, redact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_payload(result, redact), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------- CSV

CSV_HEADER = [
    "priority", "risk", "risk_score", "confidence", "validation", "liveness",
    "category", "entity", "rule_id", "value", "occurrences",
    "source", "line", "column", "remediation", "reasons", "context",
]


def _csv_safe(value: Any) -> Any:
    """Excel / WPS 会把以 = + - @ 开头的单元格当公式或 DDE 执行。

    日志里的命中值与上下文完全由被扫文件决定，属于不可信输入，统一前置单引号
    强制按文本解释（Excel 显示时不带该引号）。
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_csv(result: ScanResult, path: Path, redact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_HEADER)
        for f in result.findings:
            row = [
                f.priority,
                f.risk.value,
                f.risk_score,
                f"{f.confidence:.2f}",
                f.validation,
                VER.LIVENESS_LABEL.get(VER.liveness_of(f), "未验证"),
                CATEGORY_LABEL.get(f.category, f.category),
                f.entity,
                f.rule_id,
                U.redact(f.value, 4) if redact else f.value,
                f.occurrences,
                f.source,
                f.line,
                f.column,
                f.remediation,
                "; ".join(f.reasons),
                U.redact(f.context, 8) if redact else f.context,
            ]
            w.writerow([_csv_safe(x) for x in row])


# ---------------------------------------------------------------- SARIF


def write_sarif(result: ScanResult, path: Path, redact: bool = False) -> None:
    """SARIF 2.1.0。

    关键点：`security-severity` 是 GitHub Code Scanning 用来定级的官方属性
    （0-10），不带它 GitHub 会把所有 error 都当 8.0 处理。`rank` 用于平台
    侧的结果排序。规则元数据从规则表生成，CI 平台里能看到完整说明。
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    rule_meta: dict[str, dict] = {}
    for r in RULES:
        rule_meta[r.id] = {
            "id": r.id,
            "name": r.entity,
            "shortDescription": {"text": f"{r.entity} 泄露风险（{r.risk.value}）"},
            "fullDescription": {"text": r.note or f"检测 {r.entity}（{r.remediation or '见处置建议'}）"},
            "help": {
                "text": r.remediation or "确认该值影响面后按泄露流程处置",
                "markdown": f"**实体**：{r.entity}\n\n**处置**：{r.remediation or '见报告'}",
            },
            "defaultConfiguration": {"level": r.risk.sarif_level},
            "properties": {
                "tags": ["sensitive-data", "security", r.category, r.entity.lower()],
                "security-severity": r.risk.security_severity,
                "precision": "high" if r.base_confidence >= 0.85 else "medium",
            },
        }
    # 兜底：万一条目里的 rule_id 不在静态表（自定义规则注入时）
    for f in result.findings:
        rule_meta.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.entity,
                "shortDescription": {"text": f"{f.entity} 泄露风险（{f.risk.value}）"},
                "defaultConfiguration": {"level": f.risk.sarif_level},
                "properties": {
                    "tags": ["sensitive-data", f.category],
                    "security-severity": f.risk.security_severity,
                },
            },
        )

    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": list(rule_meta).index(f.rule_id),
            "level": f.risk.sarif_level,
            "rank": f.risk_score,
            "message": {
                "text": (
                    f"[{f.priority}] 发现 {f.entity}（{CATEGORY_LABEL.get(f.category, f.category)}，"
                    f"置信度 {f.confidence:.2f}，{f.validation}）：{_display_value(f, redact)}"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": Path(f.source).as_posix()},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
            "partialFingerprints": {"senscan/v1": f"{f.entity}:{f.normalized or f.value[:32]}"},
            "properties": {
                "entity": f.entity,
                "category": f.category,
                "priority": f.priority,
                "risk": f.risk.value,
                "confidence": round(f.confidence, 3),
                "validation": f.validation,
                "liveness": VER.liveness_of(f),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "senscan",
                    "version": __version__,
                    "informationUri": "https://localhost/senscan",
                    "rules": list(rule_meta.values()),
                }
            },
            "results": results,
        }],
    }
    path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- 控制台


def render_console(result: ScanResult, top: int = 20, redact: bool = False) -> str:
    s = result.stats
    lines: list[str] = []
    lines.append(_c(f"senscan {__version__}", "bold") + _c(" — 敏感实体审计", "dim"))
    lines.append(
        f"目标 {len(result.targets)} 个路径  |  扫描 {s.files_scanned} 文件 / 跳过 {s.files_skipped}"
        f"  |  {s.bytes_read / 1024:.0f} KB  |  {result.duration_ms} ms  |  阈值 {result.min_confidence}"
    )
    lines.append(
        _c(
            f"候选 {s.candidates}  →  校验淘汰 {s.rejected}  →  压制 {s.suppressed}"
            f"（缺上下文 {s.suppressed_context} / 低置信 {s.suppressed_threshold}）"
            f"  →  白名单 {s.whitelisted}  →  输出 {len(result.findings)}",
            "dim",
        )
    )
    lines.append("")

    prio = result.by_priority
    risk = result.by_risk
    parts = []
    for k in ("critical", "high", "medium", "low"):
        if risk[k]:
            parts.append(_c(f"{k.upper()} {risk[k]}", k))
    lines.append("风险分布  " + ("  ".join(parts) if parts else _c("无命中", "dim")))
    cat = "  ".join(f"{CATEGORY_LABEL.get(k, k)} {v}" for k, v in result.by_category.items())
    lines.append("类别分布  " + _c(cat if cat else "—", "dim"))
    if result.verification:
        v = result.verification
        lines.append(
            _c(f"存活验证  本地 {v.get('local_checked', 0)} 条 / 在线 {v.get('online_checked', 0)} 条", "dim")
            + f"  →  仍有效 {_c(str(v.get('active', 0)), 'critical')}"
            + f" · 已失效 {v.get('inactive', 0)} · 已过期 {v.get('expired', 0)}"
            + f" · 未验证 {v.get('unknown', 0)}"
        )
    if result.findings:
        lines.append(
            _c(
                f"处置批次  P0 立即 {prio['P0']}  ·  P1 迭代 {prio['P1']}  ·  P2 排期 {prio['P2']}",
                "bold" if prio["P0"] else "dim",
            )
        )
    lines.append("")

    if result.findings:
        header = (
            f"{_pad('#', 4)}{_pad('PRIO', 6)}{_pad('RISK', 10)}{_pad('ENTITY', 17)}"
            f"{_pad('CONF', 6)}{_pad('位置', 26)}值"
        )
        lines.append(_c(header, "bold"))
        lines.append(_c("─" * 108, "dim"))
        for i, f in enumerate(result.findings[:top], 1):
            loc = f"{Path(f.source).name}:{f.line}:{f.column}"
            row = (
                f"{_pad(str(i), 4)}"
                f"{_pad(f.priority, 6)}"
                f"{_pad(f.risk.value.upper(), 10)}"
                f"{_pad(f.entity, 17)}"
                f"{_pad(f'{f.confidence:.2f}', 6)}"
                f"{_pad(loc, 26)}"
                f"{_display_value(f, redact)}"
            )
            lines.append(row.replace(f.risk.value.upper(), _c(f.risk.value.upper(), f.risk.value), 1))
        if len(result.findings) > top:
            lines.append(_c(f"… 另有 {len(result.findings) - top} 条，见报告文件", "dim"))
        if prio["P0"]:
            lines.append("")
            lines.append(_c(f"⚠ {prio['P0']} 条 P0 建议立即处置，明细见 HTML 报告", "bold"))

    return "\n".join(lines)


def write_all(
    result: ScanResult,
    outdir: Path,
    formats: tuple[str, ...] = ("json", "csv", "sarif", "html"),
    redact: bool = False,
) -> list[Path]:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    written: list[Path] = []
    for fmt in formats:
        p = outdir / f"senscan-{stamp}.{fmt}"
        if fmt == "json":
            write_json(result, p, redact)
        elif fmt == "csv":
            write_csv(result, p, redact)
        elif fmt == "sarif":
            write_sarif(result, p, redact)
        elif fmt == "html":
            write_html(result, p, redact)
        else:
            raise ValueError(f"未知报告格式: {fmt}")
        written.append(p)
    return written
