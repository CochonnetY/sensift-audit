"""增量对比：与上一次 JSON 报告比较，输出「新增 / 仍在 / 已修复」三态。

身份键用 实体 + 值指纹，而不是「值 + 文件」：同一个密钥从 a.log 挪到 b.log
仍算同一条已知问题；值消失了才算已修复。指纹由报告层基于原始值计算，
因此基线报告即使用 --redact 生成，也能与本次明文结果对齐。

脱敏基线若来自旧版本报告（没有 fingerprint 字段），退回用可见值文本比对，
并在输出里标注 degraded=true，提示结论可能不准，不静默给出确定结论。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import verify as VER
from .models import Finding


@dataclass(frozen=True, slots=True)
class BaselineItem:
    entity: str
    key: str
    value_display: str
    sources: tuple[str, ...]
    rule_ids: tuple[str, ...]


def fingerprint(f: Finding) -> str:
    """与 redact 无关的稳定值指纹。

    getattr 兜底：报告层也会拿历史/模拟的 Finding 对象调用，未必带 normalized。
    """
    return VER.value_fingerprint(getattr(f, "normalized", "") or f.value)


def identity(entity: str, fp: str) -> str:
    return f"{entity}:{fp}"


class BaselineError(ValueError):
    """基线文件不可用：不存在、格式错误或非 senscan 报告。"""


def load(path: str | Path) -> tuple[list[BaselineItem], dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        raise BaselineError(f"基线文件不存在: {p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"基线文件读取/解析失败: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise BaselineError("基线文件不是 senscan JSON 报告（缺 findings 数组）")

    redacted = bool(doc.get("scan", {}).get("redacted"))
    degraded = False
    items: list[BaselineItem] = []
    for f in doc["findings"]:
        if not isinstance(f, dict):
            continue
        entity = str(f.get("entity") or "")
        fp = f.get("fingerprint")
        if not fp:
            degraded = True
            fp = VER.value_fingerprint(str(f.get("value") or ""))
        v = str(f.get("value") or "")
        items.append(BaselineItem(
            entity=entity,
            key=identity(entity, str(fp)),
            value_display=v[:64],
            sources=(str(f.get("source") or ""),),
            rule_ids=(str(f.get("rule_id") or ""),),
        ))
    meta = {
        "file": str(p),
        "baseline_total": len(items),
        "redacted": redacted,
        "degraded": degraded,
        "scan_started_at": str(doc.get("scan", {}).get("started_at") or ""),
    }
    return items, meta


def _index(items: list[BaselineItem]) -> dict[str, list[BaselineItem]]:
    out: dict[str, list[BaselineItem]] = {}
    for it in items:
        out.setdefault(it.key, []).append(it)
    return out


def _index_current(findings: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for f in findings:
        out.setdefault(identity(f.entity, fingerprint(f)), []).append(f)
    return out


def _brief_finding(f: Finding, redact: bool) -> dict[str, Any]:
    from . import utils as U
    v = U.redact(f.value, 4) if redact else f.value
    return {
        "entity": f.entity, "rule_id": f.rule_id, "risk": f.risk.value,
        "value": v[:64], "source": f.source, "line": f.line,
    }


def compare(
    findings: list[Finding],
    baseline: tuple[list[BaselineItem], dict[str, Any]],
    redact: bool = False,
) -> dict[str, Any]:
    """返回可机读增量块；同时给出逐条 status 映射，供报告层标注。"""
    base_items, meta = baseline
    b = _index(base_items)
    c = _index_current(findings)

    bkeys, ckeys = set(b), set(c)
    new_keys = ckeys - bkeys
    fixed_keys = bkeys - ckeys
    persistent_keys = bkeys & ckeys

    # 新增项按最高风险（risk.order 越小越严重）优先展示，便于复测先看要紧的。
    new_rows = []
    for k in sorted(new_keys, key=lambda x: (min(y.risk.order for y in c[x]), x)):
        rows = c[k]
        head = min(rows, key=lambda y: y.risk.order)
        new_rows.append({
            **_brief_finding(head, redact),
            "count": len(rows),
            "sources": sorted({x.source for x in rows}),
        })

    fixed_rows = []
    from . import utils as U
    for k in sorted(fixed_keys):
        rows = b[k]
        head = rows[0]
        # 基线报告可能是明文（未 --redact）；本次若要求脱敏，「已修复」里的
        # 历史值也必须同口径处理，不能因为值已不在本次结果里就漏出去。
        v = U.redact(head.value_display, 4) if redact else head.value_display
        fixed_rows.append({
            "entity": head.entity,
            "value": v[:64],
            "rule_ids": sorted({r.rule_ids[0] for r in rows if r.rule_ids}),
            "sources": sorted({s for r in rows for s in r.sources if s}),
            "count": len(rows),
        })

    persistent_rows = []
    for k in sorted(persistent_keys):
        rows = c[k]
        persistent_rows.append({
            **_brief_finding(rows[0], redact),
            "count": len(rows),
            "sources": sorted({x.source for x in rows}),
            "baseline_sources": sorted({s for r in b[k] for s in r.sources if s}),
        })

    status: dict[str, str] = {}
    for k, rows in c.items():
        st = "new" if k in new_keys else "persistent"
        for f in rows:
            status[f"{f.entity}:{fingerprint(f)}"] = st

    return {
        "enabled": True,
        **meta,
        "counts": {
            "new": len(new_keys),
            "persistent": len(persistent_keys),
            "fixed": len(fixed_keys),
        },
        "new": new_rows,
        "persistent": persistent_rows,
        "fixed": fixed_rows,
        "status_by_key": status,
        "note": (
            "身份键 = 实体 + 值指纹（与文件位置无关）。基线为脱敏旧报告且缺 fingerprint 时，"
            "退回按可见值文本比对，结论可能不准。" if meta["degraded"]
            else "身份键 = 实体 + 值指纹（与文件位置无关）；值消失即视为已修复，换文件不算新增。"
        ),
    }


def status_for(block: dict[str, Any] | None, f: Finding) -> str | None:
    if not block:
        return None
    return block["status_by_key"].get(identity(f.entity, fingerprint(f)))


__all__ = ["BaselineError", "BaselineItem", "load", "compare", "status_for",
           "fingerprint", "identity"]
