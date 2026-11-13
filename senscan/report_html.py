"""HTML 审计报告：单文件、离线可开、可筛选排序，适合直接发给评审。

安全要点（有回归测试盯着）：
- 所有落入 HTML 的动态内容一律 escape()，值里可能出现 `<script>` 或引号。
- 不把数据序列化进 <script>，避免 JSON 闭合注入；JS 只读 DOM 属性。

信息架构按"评审人实际会问的问题"排序：
1. 我要先处理什么？      → 行动摘要（P0/P1/P2）
2. 严重到什么程度？      → 风险分布 + 类别分布
3. 从哪漏出来的？        → 热点文件
4. 扩散面有多大？        → 重复值（同一凭据出现在多个文件）
5. 具体是什么、凭什么判定？→ 明细表（可筛选、可排序、可展开判定依据）
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from pathlib import Path

from . import utils as U
from . import verify as VER
from .models import (
    CATEGORY_LABEL,
    CATEGORY_ORDER,
    VALID_CHECKSUM,
    VALID_CONTEXT,
    VALID_FORMAT,
    Finding,
)
from .rules import RULES
from .scanner import ScanResult
from .version import __version__

_RISK_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
_PRIO_LABEL = {
    "P0": ("立即", "严重级别或已校验的高危凭据"),
    "P1": ("本迭代", "高危待确认 / 中危已校验"),
    "P2": ("排期", "低危或仅格式匹配"),
}
_VALID_CHIP = {
    VALID_CHECKSUM: ("ok", "已校验"),
    VALID_CONTEXT: ("ctx", "上下文"),
}


def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


def _shorten(v: str, n: int = 96) -> str:
    """PEM 私钥块之类的长值，报告里只展示开头，避免表格被撑爆。"""
    flat = v.replace("\r", " ").replace("\n", "⏎")
    if len(flat) <= n:
        return flat
    return f"{flat[:n]}…"


def _value_display(f: Finding, redact: bool) -> str:
    v = U.redact(f.value, 4) if redact else f.value
    return _shorten(v)


def _rel(path: str, bases: list[str]) -> str:
    """尽量显示相对路径，报告里全是绝对路径不利于阅读。

    容器内条目形如 `app.apk!assets/config.json`：只对包本身做相对化，
    `!` 后面的内部路径保持原样，否则会被 Windows 分隔符改得面目全非。
    """
    outer, sep, inner = path.partition("!")
    if sep:
        return f"{_rel(outer, bases)}!{inner}"
    try:
        common = os.path.commonpath([path, *bases]) if bases else ""
    except ValueError:
        common = ""
    if common and common != path:
        rel = os.path.relpath(path, common)
        return rel
    return Path(path).name


def _card(risk: str, count: int) -> str:
    zero = " zero" if count == 0 else ""
    return (
        f'<div class="card {risk}{zero}">'
        f'<div class="num">{count}</div>'
        f'<div class="lbl">{_RISK_LABEL[risk]}</div>'
        f'<div class="tag">{risk.upper()}</div>'
        f"</div>"
    )


def _prio_block(prio: str, items: list[Finding], bases: list[str]) -> str:
    title, desc = _PRIO_LABEL[prio]
    if not items:
        head = f'<div class="prio zero"><div class="pkey">{prio}</div><div class="ptitle">{title}</div>' \
               f'<div class="pnum">0</div><p class="pdesc">无</p></div>'
        return head

    shown = items[:3]
    lis = "".join(
        f'<li><span class="mono">{_e(f.entity)}</span> · {_e(_rel(f.source, bases))}:{f.line}'
        f'<span class="dim"> · {_e(f.remediation or f.entity)}</span></li>'
        for f in shown
    )
    more = f'<li class="dim">… 另有 {len(items) - len(shown)} 项</li>' if len(items) > len(shown) else ""
    return (
        f'<div class="prio {prio.lower()}">'
        f'<div class="pkey">{prio}</div>'
        f'<div class="ptitle">{title}</div>'
        f'<div class="pnum">{len(items)}</div>'
        f'<p class="pdesc">{desc}</p>'
        f"<ul>{lis}{more}</ul></div>"
    )


def _bars(counts: dict[str, int], labels: dict[str, str] | None = None, limit: int = 12) -> str:
    if not counts:
        return '<p class="empty">无命中</p>'
    top = max(counts.values())
    parts = ['<div class="bars">']
    for name, n in list(counts.items())[:limit]:
        pct = max(4, round(n / top * 100))
        label = labels.get(name, name) if labels else name
        parts.append(
            f'<div class="bar-row"><span class="bar-name">{_e(label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%"></span></span>'
            f'<span class="bar-num">{n}</span></div>'
        )
    parts.append("</div>")
    return "".join(parts)


def _hot_files(result: ScanResult, bases: list[str], limit: int = 8) -> str:
    rows = result.by_file
    if not rows:
        return '<p class="empty">无命中</p>'
    out = ['<table class="mini"><thead><tr><th>文件</th><th class="num">命中</th>'
           '<th>风险</th><th class="num">分值</th></tr></thead><tbody>']
    for src, n, risk, score in rows[:limit]:
        out.append(
            f'<tr><td class="mono ellip" title="{_e(src)}">{_e(_rel(src, bases))}</td>'
            f'<td class="num">{n}</td>'
            f'<td><span class="badge {risk}">{_RISK_LABEL[risk]}</span></td>'
            f'<td class="num">{score}</td></tr>'
        )
    out.append("</tbody></table>")
    if len(rows) > limit:
        out.append(f'<p class="empty">… 另有 {len(rows) - limit} 个文件</p>')
    return "".join(out)


def _spread(result: ScanResult, bases: list[str]) -> str:
    rows = result.spread_values
    if not rows:
        return ""
    lis = "".join(
        f'<li><span class="mono">{_e(e)}</span> <code>{_e(_shorten(v, 48))}</code> '
        f'出现在 <b>{len(set(srcs))}</b> 个文件：'
        f'{_e("、".join(_rel(s, bases) for s in sorted(set(srcs))[:4]))}'
        f'{"…" if len(set(srcs)) > 4 else ""}</li>'
        for e, v, srcs in rows[:10]
    )
    return (
        '<h2>扩散面</h2>'
        '<div class="panel spread"><ul class="plain">' + lis + "</ul>"
        '<p class="hint">同一值出现在多个文件：删一处不算处置完成，需逐处清理并轮换。</p></div>'
    )


_VALID_TIP = {
    VALID_CHECKSUM: "校验和或结构解析通过，无需再确认真假",
    VALID_CONTEXT: "格式成立且同行出现字段名，建议抽查",
    VALID_FORMAT: "只匹配形状，无附加证据，按 P1/P2 处理",
}

_LIVE_TIP = {
    VER.UNKNOWN: "未做验证，不代表已失效",
    VER.ERROR: "验证请求出错，不代表已失效",
    VER.NA: "身份标识不是凭据，没有存活概念",
    VER.STRUCTURE: "JWT / 证书结构有效，未联网确认",
}


def _validation_chip(v: str) -> str:
    if v == VALID_CHECKSUM:
        cls, text = _VALID_CHIP[VALID_CHECKSUM]
    elif v == VALID_CONTEXT:
        cls, text = _VALID_CHIP[VALID_CONTEXT]
    else:
        cls, text = "fmt", "仅格式"
    return f'<span class="vchip {cls}" title="{_e(_VALID_TIP.get(v, ""))}">{text}</span>'


def _liveness_chip(f: Finding) -> str:
    v = f.extra.get("verification")
    if not isinstance(v, dict):
        st, detail = VER.UNKNOWN, ""
    else:
        st = str(v.get("status", VER.UNKNOWN))
        detail = str(v.get("detail", ""))
    # MAC / IMEI / 序列号是身份标识，不是凭据，显示破折号而不是「不适用」
    label = "—" if st == VER.NA else VER.LIVENESS_LABEL.get(st, st)
    tip = detail or _LIVE_TIP.get(st, "")
    return f'<span class="lchip {_e(st.replace("/", ""))}" title="{_e(tip)}">{_e(label)}</span>'


def _verify_panel(result: ScanResult) -> str:
    v = result.verification
    if not v:
        return ""
    chips = "".join(
        f'<span class="lchip {_e(k.replace("/", ""))}">{_e(VER.LIVENESS_LABEL.get(k, k))} <b>{n}</b></span>'
        for k, n in result.by_liveness.items() if n
    )
    mode = "在线 + 离线" if v.get("enabled_online") else "仅离线 · 未外发数据"
    extra = ""
    if v.get("enabled_online"):
        extra = (
            f'<p class="hint">端点：{_e(", ".join(v.get("endpoints", [])))}；'
            f'审计 <span class="mono">{_e(v.get("audit_path", ""))}</span>（只记 hash）。'
            "<b>「未验证」不等于「已失效」</b>；webhook 类凭据不做在线验证。</p>"
        )
    return (
        "<h2>存活验证</h2>"
        f'<div class="panel"><p class="dim" style="font-size:12px">{_e(mode)} · '
        f'本地 {v.get("local_checked", 0)} · 在线 {v.get("online_checked", 0)}'
        f' · 超限跳过 {v.get("skipped_limit", 0)}</p>'
        f'<div class="lchips">{chips or "<span class=dim>无验证结果</span>"}</div>'
        + extra + "</div>"
    )


def _context_html(f: Finding, redact: bool) -> str:
    """原文三段渲染：命中值高亮，前后文常规色。

    以前「原文」栏是一个被截断的长串，长私钥恰好被切在中间，评审人看到的是
    上一条密钥的尾巴和下张证书的头，会以为命中的是另一段内容。现在把命中值
    明确标出来，一眼能确认它确实出自这段原文。
    """
    parts = f.context_parts
    if not parts or len(parts) != 3:
        return _e(U.redact(f.context, 8) if redact else f.context)
    before, hit, after = U.redact_context_parts(parts) if redact else parts
    return (
        f'{_e(before)} <mark class="hit" title="命中值">{_e(hit)}</mark> '
        f'{_e(after)}'
    )


def _liveness_options(result: ScanResult) -> str:
    return "".join(
        f'<option value="{_e(k)}">{_e(VER.LIVENESS_LABEL.get(k, k))} ({n})</option>'
        for k, n in result.by_liveness.items() if n
    )


def _rows(result: ScanResult, redact: bool, bases: list[str]) -> str:
    out: list[str] = []
    for i, f in enumerate(result.findings, 1):
        loc = f"{_rel(f.source, bases)}:{f.line}:{f.column}"
        search = " ".join([f.entity, f.risk.value, f.value, f.context, Path(f.source).name]).lower()
        reasons = "".join(f"<li>{_e(r)}</li>" for r in f.reasons)
        ctx = U.redact(f.context, 8) if redact else f.context
        # 列表/悬浮提示用纯文本，⟦⟧ 边界标记只在详情和 JSON/CSV 里保留
        ctx_plain = ctx.replace(U.HIT_OPEN, "").replace(U.HIT_CLOSE, "")
        trip_chip = '<span class="trip-chip">三元组</span>' if f.extra.get("iot_triplet") else ""
        v = f.extra.get("verification")
        vblock = ""
        if isinstance(v, dict):
            vblock = (
                f'<p class="dlabel">存活验证 · {_e(v.get("layer", ""))}</p>'
                f'<p>{_e(VER.LIVENESS_LABEL.get(v.get("status"), "未知"))}'
                f' · {_e(v.get("detail", ""))}</p>'
            )
        out.append(
            f'<tr data-prio="{f.priority}" data-risk="{f.risk.value}" data-cat="{_e(f.category)}"'
            f' data-entity="{_e(f.entity)}" data-live="{_e(VER.liveness_of(f))}"'
            f' data-conf="{f.confidence:.3f}"'
            f' data-loc="{_e(loc)}" data-text="{_e(search)}">'
            f'<td class="idx">{i}</td>'
            f'<td><span class="prio-tag {f.priority}">{f.priority}</span></td>'
            f'<td><span class="badge {f.risk.value}">{_RISK_LABEL[f.risk.value]}</span></td>'
            f'<td class="cat">{_e(CATEGORY_LABEL.get(f.category, f.category))}</td>'
            f'<td class="ent">{_e(f.entity)}{trip_chip}</td>'
            f'<td>{_validation_chip(f.validation)}</td>'
            f'<td>{_liveness_chip(f)}</td>'
            f'<td class="conf"><span class="conf-bar"><i style="width:{round(f.confidence * 100)}%"></i></span>'
            f'<b>{f.confidence:.2f}</b></td>'
            f'<td class="loc" title="{_e(f.source)}">{_e(loc)}'
            f'{" <em>×" + str(f.occurrences) + "</em>" if f.occurrences > 1 else ""}</td>'
            f'<td class="val"><code>{_e(_value_display(f, redact))}</code>'
            f'<details><summary>详情</summary>'
            f'<div class="dbody"><p class="dlabel">判定依据</p><ul class="reasons">{reasons}</ul>'
            + vblock +
            f'<p class="dlabel">建议</p><p>{_e(f.remediation or "确认是否属敏感数据")}</p>'
            f'<p class="dlabel">原文（高亮部分＝命中值）</p>'
            f'<p class="ctxfull">{_context_html(f, redact)}</p>'
            f'<p class="dim">规则 <span class="mono">{_e(f.rule_id)}</span> · 归一化值 '
            f'<code>{_e(_shorten(f.normalized or f.value, 64))}</code></p></div></details></td>'
            f'<td class="ctx ellip" title="{_e(ctx_plain)}">{_e(_shorten(ctx_plain, 240))}</td>'
            f"</tr>"
        )
    return "".join(out)


def _rule_source_stats() -> str:
    counts: dict[str, int] = {}
    for r in RULES:
        counts[r.source] = counts.get(r.source, 0) + 1
    order = ["gitleaks", "secrets-patterns-db", "detect-secrets", "senscan"]
    items = sorted(counts.items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order else 99, -kv[1]))
    return "　".join(f"{k} {v}" for k, v in items)


def _entity_options(result: ScanResult) -> str:
    return "".join(f'<option value="{_e(k)}">{_e(k)}</option>' for k in result.by_entity)


def _category_options(result: ScanResult) -> str:
    return "".join(
        f'<option value="{_e(k)}">{_e(CATEGORY_LABEL.get(k, k))}</option>' for k in result.by_category
    )


CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
  background:#f5f6f8;color:#1f2937;padding:0 0 60px}
.wrap{max-width:1560px;margin:0 auto;padding:0 28px}
header{background:#fff;border-bottom:1px solid #e5e7eb;padding:26px 0 20px;margin-bottom:24px}
h1{font-size:22px;font-weight:650;letter-spacing:-.2px}
h1 .ver{font-size:12px;color:#9ca3af;font-weight:400;margin-left:8px}
.sub{color:#6b7280;font-size:13px;margin-top:6px}
.sub b{color:#374151;font-weight:600}
.warn{margin-top:14px;background:#fffbeb;border:1px solid #fde68a;color:#92400e;
  padding:9px 14px;border-radius:6px;font-size:13px}
h2{font-size:14px;font-weight:650;color:#374151;margin:26px 0 12px;letter-spacing:.2px}
.verdict{background:#fff;border:1px solid #e5e7eb;border-left:4px solid #b91c1c;border-radius:8px;
  padding:14px 20px;font-size:14px;color:#374151}
.verdict b{color:#b91c1c}
.verdict.ok{border-left-color:#15803d}
.verdict.ok b{color:#15803d}
.verdict.trip{background:#fef2f2;border-color:#fecaca;border-left-color:#dc2626;
  color:#7f1d1d;margin-top:10px}
.verdict.trip b{color:#b91c1c}
.trip-chip{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;
  background:#fee2e2;color:#991b1b;margin-left:4px}
.prios{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px}
.prio{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 18px;position:relative}
.prio.zero{opacity:.5}
.prio .pkey{position:absolute;right:16px;top:14px;font-size:11px;letter-spacing:.6px;
  color:#9ca3af;font-family:ui-monospace,Consolas,monospace}
.prio .ptitle{font-size:13px;color:#6b7280}
.prio .pnum{font-size:30px;font-weight:700;line-height:1.15;margin:2px 0 4px}
.prio.p0 .pnum{color:#b91c1c}.prio.p1 .pnum{color:#d97706}.prio.p2 .pnum{color:#0284c7}
.prio .pdesc{font-size:12px;color:#9ca3af;margin-bottom:8px}
.prio ul{list-style:none}
.prio li{font-size:12px;color:#4b5563;margin:4px 0;padding-left:2px;overflow-wrap:anywhere}
.prio .mono{font-family:ui-monospace,Consolas,monospace;color:#111827}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 18px;position:relative}
.card.zero{opacity:.45}
.card .num{font-size:30px;font-weight:700;line-height:1.1}
.card .lbl{font-size:13px;color:#6b7280;margin-top:2px}
.card .tag{position:absolute;right:14px;top:16px;font-size:10px;letter-spacing:.8px;color:#9ca3af}
.card.critical .num{color:#b91c1c}.card.high .num{color:#dc2626}
.card.medium .num{color:#d97706}.card.low .num{color:#0284c7}
.panel{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px}
.bars{display:grid;gap:7px}
.bar-row{display:grid;grid-template-columns:130px 1fr 40px;align-items:center;gap:12px}
.bar-name{font-size:12.5px;color:#4b5563;text-align:right}
.bar-track{background:#f1f3f5;border-radius:3px;height:9px;overflow:hidden}
.bar-fill{display:block;height:100%;background:#93b4d8;border-radius:3px}
.bar-num{font-size:12px;color:#6b7280;text-align:right}
table.mini{width:100%;border-collapse:collapse;font-size:12.5px}
table.mini th{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;
  text-align:left;padding:6px 8px;border-bottom:1px solid #e5e7eb;font-weight:600}
table.mini td{padding:6px 8px;border-bottom:1px solid #f4f5f7}
table.mini tr:last-child td{border-bottom:none}
.num{text-align:right;font-variant-numeric:tabular-nums}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 12px}
.btn{border:1px solid #e5e7eb;background:#fff;color:#4b5563;padding:5px 13px;border-radius:16px;
  font-size:12.5px;cursor:pointer;transition:.15s}
.btn:hover{border-color:#cbd5e1}
.btn.on{background:#1f2937;border-color:#1f2937;color:#fff}
.spacer{flex:1}
input[type=search],select.btn{font-family:inherit}
input[type=search]{border:1px solid #e5e7eb;border-radius:16px;padding:6px 14px;font-size:13px;
  width:250px;outline:none;color:#1f2937}
input[type=search]:focus{border-color:#93c5fd;box-shadow:0 0 0 3px #eff6ff}
select.btn{padding:5px 10px;border-radius:8px}
.count{font-size:12.5px;color:#6b7280}
table.main{width:100%;min-width:1180px;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;
  border-radius:10px;overflow:hidden}
th{text-align:left;font-size:11.5px;letter-spacing:.5px;text-transform:uppercase;color:#9ca3af;
  font-weight:600;padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#fafbfc;white-space:nowrap}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:#4b5563}
th.sortable::after{content:"⇅";font-size:10px;margin-left:4px;opacity:.45}
th.asc::after{content:"↑";opacity:.9}th.desc::after{content:"↓";opacity:.9}
td{padding:10px 12px;border-bottom:1px solid #f1f3f5;vertical-align:top;font-size:13px}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:#fafcff}
.idx{color:#c3c9d2;font-variant-numeric:tabular-nums;width:44px}
.prio-tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10.5px;font-weight:700;
  font-family:ui-monospace,Consolas,monospace;letter-spacing:.3px}
.prio-tag.P0{background:#fee2e2;color:#991b1b}
.prio-tag.P1{background:#fef3c7;color:#92400e}
.prio-tag.P2{background:#eff6ff;color:#1d4ed8}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10.5px;font-weight:700;
  letter-spacing:.4px;white-space:nowrap}
.badge.critical{background:#fee2e2;color:#991b1b}
.badge.high{background:#fef2f2;color:#b91c1c}
.badge.medium{background:#fef3c7;color:#92400e}
.badge.low{background:#e0f2fe;color:#075985}
.badge.info{background:#f3f4f6;color:#4b5563}
.vchip{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10.5px;white-space:nowrap}
.vchip.ok{background:#dcfce7;color:#166534}
.vchip.ctx{background:#e0f2fe;color:#075985}
.vchip.fmt{background:#f3f4f6;color:#6b7280}
.lchip{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10.5px;white-space:nowrap;
  background:#f3f4f6;color:#6b7280}
.lchip b{font-variant-numeric:tabular-nums}
.lchip.active{background:#fee2e2;color:#991b1b}
.lchip.inactive,.lchip.expired{background:#dcfce7;color:#166534}
.lchip.structure{background:#e0f2fe;color:#075985}
.lchip.error{background:#fef3c7;color:#92400e}
.lchips{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.lchips .lchip{font-size:12px;padding:4px 11px}
.cat{color:#6b7280;font-size:12px;white-space:nowrap}
.ent{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#374151;white-space:nowrap}
.conf{white-space:nowrap;width:96px}
.conf-bar{display:inline-block;width:44px;height:5px;background:#eef1f4;border-radius:3px;
  overflow:hidden;vertical-align:middle;margin-right:6px}
.conf-bar i{display:block;height:100%;background:#5b8fc9}
.conf b{font-size:12px;font-weight:600;color:#4b5563;font-variant-numeric:tabular-nums}
.loc{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:#6b7280;
  white-space:nowrap;max-width:230px;overflow:hidden;text-overflow:ellipsis}
.loc em{color:#b45309;font-style:normal;font-weight:600}
.val code{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#111827;
  background:#f8f9fb;padding:1px 5px;border-radius:3px;overflow-wrap:anywhere;word-break:break-all}
td.val{max-width:400px}
.ellip{overflow:hidden;text-overflow:ellipsis}
td.ctx{max-width:360px;color:#6b7280;font-size:12px}
details{margin-top:5px}
details summary{font-size:11.5px;color:#2563eb;cursor:pointer;list-style:none}
details summary::-webkit-details-marker{display:none}
details summary::before{content:"▸ ";font-size:10px}
details[open] summary::before{content:"▾ "}
.dbody{margin-top:8px;padding:10px 12px;background:#fafbfc;border:1px solid #eef1f4;border-radius:6px}
.dlabel{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin-top:8px}
.dlabel:first-child{margin-top:0}
.reasons{margin:2px 0 0 16px}
.reasons li{font-size:12px;color:#4b5563}
.ctxfull{font-size:11.5px;color:#6b7280;overflow-wrap:anywhere;word-break:break-all}
mark.hit{background:#fff2b8;color:#7c4a03;padding:0 2px;border-radius:2px;
  box-shadow:inset 0 0 0 1px #f0d383}
.empty{color:#9ca3af;font-size:13px;padding:8px 0}
.hint{font-size:12px;color:#92400e;background:#fffbeb;border-radius:6px;padding:8px 12px;margin-top:10px}
.spread li{font-size:12.5px;color:#4b5563;margin:6px 0;overflow-wrap:anywhere}
ul.plain{list-style:none}
.dim{color:#9ca3af}
.mono{font-family:ui-monospace,Consolas,monospace}
.notes{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px 22px;margin-top:26px}
.notes summary{cursor:pointer;font-size:13px;font-weight:650;color:#374151;list-style:none}
.notes summary::-webkit-details-marker{display:none}
.notes summary::before{content:"▸ ";color:#9ca3af}
.notes[open] summary::before{content:"▾ "}
.notes li{color:#4b5563;font-size:12.5px;margin:6px 0 6px 18px}
details.inline{display:inline-block;margin-left:10px;font-size:12px}
details.inline summary{color:#2563eb;cursor:pointer;list-style:none;display:inline}
details.inline summary::-webkit-details-marker{display:none}
footer{color:#9ca3af;font-size:12px;margin-top:26px;text-align:center}
@media print{
  body{background:#fff;font-size:11px}
  .toolbar{display:none}
  tr[hidden]{display:table-row!important}
  .card,.panel,table,.notes,.prio{break-inside:avoid}
  table.main details{display:none}
}
"""

JS = """
(function(){
  var rows=[].slice.call(document.querySelectorAll('table.main tbody tr'));
  var prio='all', cat='all', ent='all', live='all', q='';
  var shown=document.getElementById('shown');
  var total=document.getElementById('total');
  function apply(){
    var n=0;
    rows.forEach(function(r){
      var ok=(prio==='all'||r.dataset.prio===prio)
        &&(cat==='all'||r.dataset.cat===cat)
        &&(ent==='all'||r.dataset.entity===ent)
        &&(live==='all'||r.dataset.live===live)
        &&(!q||r.dataset.text.indexOf(q)>-1);
      r.hidden=!ok; if(ok)n++;
    });
    shown.textContent=n; total.textContent=rows.length;
  }
  document.querySelectorAll('[data-prio-btn]').forEach(function(b){
    b.addEventListener('click',function(){
      document.querySelectorAll('[data-prio-btn]').forEach(function(x){x.classList.remove('on')});
      b.classList.add('on'); prio=b.dataset.prioBtn; apply();
    });
  });
  function bindSel(id,setter){
    var el=document.getElementById(id);
    if(!el)return;
    el.addEventListener('change',function(e){setter(e.target.value);apply()});
  }
  bindSel('catSel',function(v){cat=v});
  bindSel('entSel',function(v){ent=v});
  bindSel('liveSel',function(v){live=v});
  var qEl=document.getElementById('q');
  if(qEl)qEl.addEventListener('input',function(e){q=e.target.value.trim().toLowerCase();apply()});

  // 列排序：只在数值/字符串间切换，不重排隐藏行
  var tbody=document.querySelector('table.main tbody');
  document.querySelectorAll('th.sortable').forEach(function(th){
    th.addEventListener('click',function(){
      var key=th.dataset.key, num=th.dataset.num==='1';
      var dir=th.classList.contains('asc')?'desc':'asc';
      document.querySelectorAll('th.sortable').forEach(function(x){x.classList.remove('asc','desc')});
      th.classList.add(dir);
      var sorted=rows.slice().sort(function(a,b){
        var x=a.dataset[key]||'', y=b.dataset[key]||'';
        if(num){return (parseFloat(x)-parseFloat(y))*(dir==='asc'?1:-1);}
        return x.localeCompare(y,'zh')*(dir==='asc'?1:-1);
      });
      sorted.forEach(function(r){tbody.appendChild(r)});
      rows=sorted;
    });
  });
})();
"""


def write_html(result: ScanResult, path: Path, redact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    risk = result.by_risk
    s = result.stats
    prio = result.by_priority
    bases = [str(Path(t)) for t in result.targets]

    groups: dict[str, list[Finding]] = {"P0": [], "P1": [], "P2": []}
    for f in result.findings:
        groups[f.priority].append(f)

    title_target = Path(result.targets[0]).name if result.targets else "scan"
    total = len(result.findings)

    if total == 0:
        verdict = ('<div class="verdict ok"><b>未发现</b>敏感实体。若与预期不符：确认是明文载体'
                   '（TLS 密文无法扫描），或降低 <code>--min-confidence</code>。</div>')
    else:
        verdict = (
            f'<div class="verdict">共 <b>{total}</b> 条命中，'
            f'<b>{prio["P0"]}</b> 条 P0 需立即处置；'
            f'<b>{result.by_validation.get(VALID_CHECKSUM, 0)}</b> 条已通过校验，可直接进入处置。</div>'
        )

    trip_files = result.iot_triplet_files
    if trip_files:
        names = ", ".join(_e(Path(x).name) for x in trip_files[:3])
        more = f" 等 {len(trip_files)} 处" if len(trip_files) > 3 else ""
        verdict += (
            '<div class="verdict trip"><b>设备三元组完整泄露</b> — '
            f'{names}{more} 中 PK / DN / DS 齐备，可仿冒设备接入。'
            '<b>删日志无效，须在 IoT 平台作废并轮换密钥。</b></div>'
        )

    cats = {k: v for k, v in result.by_category.items()}
    cat_sorted = {k: cats[k] for k in CATEGORY_ORDER if k in cats}

    body = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>敏感实体审计报告 · {_e(title_target)}</title>
<style>{CSS}</style>
</head>
<body>
<header><div class="wrap">
  <h1>敏感实体审计报告<span class="ver">senscan {_e(__version__)}</span></h1>
  <div class="sub">
    目标 <b>{_e(", ".join(result.targets))}</b> ·
    <b>{s.files_scanned}</b> 文件（跳过 {s.files_skipped}）·
    <b>{s.bytes_read / 1024:.0f}</b> KB · <b>{result.duration_ms}</b> ms
  </div>
  <div class="sub">
    规则 <b>{len(RULES)}</b> · 阈值 <b>{result.min_confidence}</b> ·
    白名单 <b>{result.whitelist_size}</b> · {datetime.now().strftime("%Y-%m-%d %H:%M")}
    <details class="inline"><summary>降噪漏斗</summary>：候选 {s.candidates} → 淘汰 {s.rejected}
    → 缺上下文 {s.suppressed_context} → 低置信 {s.suppressed_threshold}
    → 白名单 {s.whitelisted} → 输出 {total}</details>
  </div>
  <div class="warn">含明文凭据，仅限授权人员查阅；外发请用 <code>--redact</code> 重新生成。</div>
</div></header>

<main class="wrap">
  <h2>结论</h2>
  {verdict}
  {_verify_panel(result)}
  <div class="prios" style="margin-top:16px">
    {_prio_block("P0", groups["P0"], bases)}
    {_prio_block("P1", groups["P1"], bases)}
    {_prio_block("P2", groups["P2"], bases)}
  </div>

  <h2>风险 · 类别</h2>
  <div class="cards">
    {_card("critical", risk["critical"])}
    {_card("high", risk["high"])}
    {_card("medium", risk["medium"])}
    {_card("low", risk["low"])}
  </div>
  <div class="grid2" style="margin-top:14px">
    <div class="panel">
      <p class="dim" style="font-size:12px;margin-bottom:10px">按类别</p>
      {_bars(cat_sorted, CATEGORY_LABEL)}
    </div>
    <div class="panel">
      <p class="dim" style="font-size:12px;margin-bottom:10px">按实体</p>
      {_bars(result.by_entity)}
    </div>
  </div>

  <h2>热点文件</h2>
  <div class="panel">{_hot_files(result, bases)}</div>

  {_spread(result, bases)}

  <h2>明细</h2>
  <div class="toolbar">
    <button class="btn on" data-prio-btn="all">全部</button>
    <button class="btn" data-prio-btn="P0">P0</button>
    <button class="btn" data-prio-btn="P1">P1</button>
    <button class="btn" data-prio-btn="P2">P2</button>
    <select class="btn" id="catSel"><option value="all">全部类别</option>{_category_options(result)}</select>
    <select class="btn" id="entSel"><option value="all">全部实体</option>{_entity_options(result)}</select>
    <select class="btn" id="liveSel"><option value="all">全部存活</option>{_liveness_options(result)}</select>
    <span class="spacer"></span>
    <span class="count"><b id="shown">{total}</b> / <b id="total">{total}</b> 条</span>
    <input type="search" id="q" placeholder="搜索值 / 路径 / 上下文">
  </div>
  <table class="main">
    <thead><tr>
      <th>#</th>
      <th class="sortable" data-key="prio">批次</th>
      <th class="sortable" data-key="risk">风险</th>
      <th>类别</th>
      <th class="sortable" data-key="entity">实体</th>
      <th title="证据：这条命中凭什么算真的（详见下方口径说明）">证据</th>
      <th title="存活：这凭据现在还能不能用（详见下方口径说明）">存活</th>
      <th class="sortable" data-key="conf" data-num="1">置信度</th>
      <th class="sortable" data-key="loc">位置</th>
      <th>命中值</th>
      <th>上下文</th>
    </tr></thead>
    <tbody>{_rows(result, redact, bases)}</tbody>
  </table>

  <details class="notes">
    <summary>口径说明</summary>
    <ul>
      <li><b>风险</b>=泄露后多严重，<b>置信度</b>=这条多可能是真的；P0/P1/P2 由两者合成。</li>
      <li><b>已校验</b>：校验和/结构解析通过（Luhn、GB 11643、JWT、PEM、Basic Auth）。<b>上下文</b>：有字段名佐证，建议抽查。<b>仅格式</b>：按 P1/P2 处理。手机号、IMEI/IMSI、MAC、LTK 没有校验位，最高「上下文」。</li>
      <li>数值字段、订单号、无字段名的裸数字默认不报，同行相邻字段不互相提权；官方示例凭据按占位符丢弃。调低阈值可捞回裸线索。</li>
      <li><b>证据</b>回答"是不是真的"，<b>存活</b>回答"还能不能用"。MAC、IMEI、序列号等身份标识不是凭据，没有"能否使用"的概念，存活列显示「—」；在线验证默认关闭，网络失败记「未验证」，<b>不等同「已失效」</b>。</li>
      <li><b>原文</b>栏中黄色高亮的即命中值，两侧是它在文件里的前后文；命中值过长时中间会写明省略字符数。纯文本报告（JSON / CSV）里用 <code>⟦ ⟧</code> 圈出同一段。</li>
      <li>「缺上下文」是主动挡掉的高误报类型（裸 UUID、裸 hash 等），数字大属正常。</li>
      <li>pcap 的「位置」为帧号；TLS 明文以外的正文不在扫描范围内。</li>
      <li>规则来源：{_rule_source_stats()}。gitleaks 为 MIT 许可，正则已做 Python 兼容化并补中文语境边界。</li>
    </ul>
  </details>

  <footer>senscan {_e(__version__)} · {_e(result.started_at)}</footer>
</main>
<script>{JS}</script>
</body>
</html>
"""
    path.write_text(body, encoding="utf-8")
