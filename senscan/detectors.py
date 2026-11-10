"""检测执行器：规则编译、硬校验、上下文提权、冲突消解。

设计要点：
1. 声明式规则（Rule）+ 统一执行器，新增实体类型只加一条规则，不改这里。
2. 三档打分：格式分(base) + 软校验加分 + 上下文提权 - 占位符降权。
3. 硬校验不通过直接丢弃（如 IMEI 的 Luhn），软校验只加分。
4. context_required 的规则（裸 UUID / 银行卡 / 指纹裸 hash）没有上下文关键词一律压制。
5. 每条命中带"验证状态"：已校验（有数学/结构证据）> 上下文 > 仅格式。
   这三档决定报告里的处置优先级，评审人不需要再自己判断可信度。
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Callable

from . import utils as U
from .models import (
    VALID_CHECKSUM,
    VALID_CONTEXT,
    VALID_FORMAT,
    CREDENTIAL,
    Finding,
    Rule,
)
from .rules import RULES

__all__ = ["detect", "RULES", "VALIDATORS"]

# ---------------------------------------------------------------- 校验器
#
# 命名约定：能给出"数学或结构证据"的进 STRONG，仅做形态约束的进 WEAK。

VALIDATORS: dict[str, Callable[[str], bool]] = {
    # 强校验
    "luhn": lambda v: v.isdigit() and U.luhn_valid(v),
    "mac": U.mac_is_usable,
    "mac_dot_not_version": U.mac_dot_not_version,
    "jwt": U.jwt_decodable,
    "pem_body": U.pem_has_body,
    "basic_auth": U.basic_auth_is_pair,
    "cn_id_card": U.cn_id_card_valid,
    "cn_mobile": U.cn_mobile_valid,
    "bank_card": U.bank_card_valid,
    "iccid": U.iccid_valid,
    "imsi": U.imsi_valid,
    "cred_uri": U.cred_uri_ok,
    "jdbc_cred": U.jdbc_cred_ok,
    "hex32": lambda v: len(U.normalize_hexlike(v)) == 32,
    "der_private": U.der_private_ok,
    "der_public": U.der_public_ok,
    "der_key": U.der_key_ok,
    # 弱校验
    "email": U.email_ok,
    "serial_no": U.serial_no_ok,
    "entropy": lambda v: U.high_entropy(v),
    "not_placeholder": lambda v: not U.looks_placeholder(v),
}

# 注意：mac / serial_no / email 只是"形态合理性"过滤，不是校验和或结构解析，
# 不能标成「已校验」。否则像版本号被误判成 MAC 时，报告还会显示绿色"已校验"，
# 反而给误报背书。它们归到弱校验：有关键词时显示「上下文」。
STRONG_VALIDATORS = frozenset({
    "luhn", "jwt", "pem_body", "basic_auth", "cn_id_card",
    "cn_mobile", "bank_card", "iccid", "imsi", "cred_uri", "jdbc_cred", "hex32",
    "der_private", "der_public", "der_key",
})


_ASCII_WORD_BOUNDARY = r"(?a:\b)"


@lru_cache(maxsize=256)
def _compiled(rule: Rule) -> re.Pattern[str]:
    # Python 的 \b 默认按 Unicode 判词，汉字也算"词字符"，于是
    # 「密钥ghp_xxx」「令牌AKIA...」这类中文紧邻的前缀型凭据整体漏报。
    # 用局部 ASCII 标志把 \b 限定为 ASCII 词边界：中文与 ASCII 之间成立，
    # 而英文标识符内部（keyghp_）仍不成立——既补漏报又不放宽误报。
    return re.compile(rule.pattern.replace(r"\b", _ASCII_WORD_BOUNDARY), rule.flags)


# ---------------------------------------------------------------- 归一化

_NORMALIZERS: dict[str, Callable[[str], str]] = {
    "MAC": U.normalize_hexlike,
    "CERT_FINGERPRINT": U.normalize_hexlike,
    "LTK": U.normalize_hexlike,
    "OAID": str.lower,
    "IDFA": str.lower,
    "EMAIL": str.lower,
    "IMSI": U.normalize_hexlike,
    "ICCID": U.normalize_hexlike,
    "BANK_CARD": lambda v: re.sub(r"[\s\-]", "", v),
    "ID_CARD": str.upper,
}


def _normalize(entity: str, value: str) -> str:
    fn = _NORMALIZERS.get(entity)
    return fn(value) if fn else U.normalize_plain(value)


# ---------------------------------------------------------------- 打分


def _score(rule: Rule, value: str, ctx_kw: str | None, bonus_hits: list[str]) -> tuple[float, list[str]]:
    reasons: list[str] = [f"规则 {rule.id}"]
    score = rule.base_confidence

    for name in bonus_hits:
        score += 0.08
        reasons.append(f"校验通过 {name}")

    if ctx_kw:
        score += 0.30 if rule.context_required else 0.24
        reasons.append(f"上下文命中「{ctx_kw}」")

    if U.looks_placeholder(value):
        score -= 0.55
        reasons.append("疑似占位/脱敏值（降权）")

    return max(0.0, min(0.97, score)), reasons


def _validation(rule: Rule, ctx_kw: str | None) -> str:
    if any(v in STRONG_VALIDATORS for v in rule.validators):
        return VALID_CHECKSUM
    if ctx_kw:
        return VALID_CONTEXT
    return VALID_FORMAT


# ---------------------------------------------------------------- 冲突消解


def _drop_subsumed(findings: list[Finding]) -> list[Finding]:
    """同一文件同一行上，若短值是长值的子串（典型：PEM 的 BEGIN 头 vs 完整私钥块、
    JDBC URL 里的 password=xxx vs 整条连接串），只保留信息量更大的那条。

    短值长度 <10 的不参与（避免误吞 OTP 等短凭据）。
    """
    by_site: dict[tuple[str, int], list[Finding]] = {}
    for f in findings:
        by_site.setdefault((f.source, f.line), []).append(f)

    drop: set[int] = set()
    for group in by_site.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda x: -len(x.value))
        for i, short in enumerate(group):
            if id(short) in drop or len(short.value) < 10:
                continue
            for longer in group[:i]:
                if longer.rule_id == short.rule_id:
                    continue
                if short.value in longer.value:
                    drop.add(id(short))
                    longer.occurrences += short.occurrences
                    break
    out = [f for f in findings if id(f) not in drop]

    # 私钥块跨多行：完整 PEM 块（含 BEGIN/END 头）与其中被单独认出的
    # 裸 DER body 不在同一行，上面的同行消解覆盖不到，会重复上报一次。
    # 只对同文件、同为 PRIVATE_KEY、位置接近且确为子串关系的两条做二次消解。
    privs = sorted((f for f in out if f.entity == "PRIVATE_KEY"), key=lambda x: -len(x.value))
    if len(privs) > 1:
        drop2: set[int] = set()
        for i, short in enumerate(privs):
            if len(short.value) < 10:
                continue
            for longer in privs[:i]:
                if (longer.source == short.source
                        and abs(longer.offset - short.offset) < 8192
                        and short.value in longer.value):
                    drop2.add(id(short))
                    longer.occurrences += short.occurrences
                    break
        out = [f for f in out if id(f) not in drop2]
    return out


def _collapse_same_value(findings: list[Finding]) -> list[Finding]:
    """同一串值被多条规则命中时（如 UUID 同时被判为 OAID / IDFA，或 15 位数字
    同时像 IMEI 与 IMSI），只保留最可信的一条。

    裁决顺序：风险等级低的优先 → 置信度高的优先 → 已校验的优先。
    一个具体的值只可能是一种实体，重复上报只会干扰评审。
    """
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.normalized or f.value
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        rank_new = (f.risk.order, -f.confidence, 0 if f.validation == VALID_CHECKSUM else 1)
        rank_cur = (cur.risk.order, -cur.confidence, 0 if cur.validation == VALID_CHECKSUM else 1)
        if rank_new < rank_cur:
            f.occurrences += cur.occurrences
            best[key] = f
        else:
            cur.occurrences += f.occurrences
    return list(best.values())


# ---------------------------------------------------------------- 执行


def _new_stats(stats: dict | None) -> dict:
    if stats is None:
        stats = {}
    for key in ("candidates", "rejected", "suppressed", "suppressed_context", "suppressed_threshold"):
        stats.setdefault(key, 0)
    return stats


def detect(
    text: str,
    source: str,
    min_confidence: float = 0.55,
    stats: dict | None = None,
    rules: tuple[Rule, ...] = RULES,
    line_offset: int = 0,
) -> list[Finding]:
    """对单个文本源执行全部规则，返回已去重、已排序的发现项。"""
    stats = _new_stats(stats)
    line_index = U.build_line_index(text)
    kept: dict[tuple[str, str], Finding] = {}

    for rule in rules:
        rx = _compiled(rule)
        for m in rx.finditer(text):
            try:
                raw = m.group(rule.group)
                span_start, span_end = m.span(rule.group)
            except IndexError:
                continue
            if not raw:
                continue
            value = raw.strip().strip("\"'")
            if rule.strip_whitespace:
                # 串口日志按列宽硬折行，值被拆到多行；去掉空白还原原值。
                value = re.sub(r"\s+", "", value)
            if not value or len(value) < 4:
                continue
            if len(value) > rule.max_value_len:
                value = value[: rule.max_value_len]

            stats["candidates"] += 1

            # 硬校验：任一不过即丢弃
            ok = True
            for name in rule.validators:
                fn = VALIDATORS.get(name)
                if fn is not None and not fn(value):
                    ok = False
                    break
            if not ok:
                stats["rejected"] += 1
                continue

            ctx_kw = U.context_hit(text, span_start, span_end, rule.context_keywords, rule.context_window)
            if rule.context_required and not ctx_kw:
                stats["suppressed"] += 1
                stats["suppressed_context"] += 1
                continue

            bonus_hits = [n for n in rule.bonus_validators if VALIDATORS.get(n) and VALIDATORS[n](value)]
            score, reasons = _score(rule, value, ctx_kw, bonus_hits)

            if score < min_confidence:
                stats["suppressed"] += 1
                stats["suppressed_threshold"] += 1
                continue

            key = f"{rule.entity}:{_normalize(rule.entity, value)}"
            existing = kept.get(key)
            if existing is not None:
                existing.occurrences += 1
                if score > existing.confidence:
                    existing.confidence = score
                    existing.rule_id = rule.id
                    existing.reasons = tuple(reasons)
                    existing.validation = _validation(rule, ctx_kw)
                continue

            line_no, col = U.offset_to_line(line_index, span_start)
            kept[key] = Finding(
                entity=rule.entity,
                value=value,
                risk=rule.risk,
                confidence=score,
                rule_id=rule.id,
                source=source,
                offset=span_start,
                line=line_no + line_offset,
                column=col,
                context=U.extract_context(text, span_start, span_end, rule.context_window),
                category=rule.category or CREDENTIAL,
                validation=_validation(rule, ctx_kw),
                remediation=rule.remediation,
                reasons=tuple(reasons),
                normalized=_normalize(rule.entity, value),
            )

    findings = _drop_subsumed(_collapse_same_value(list(kept.values())))
    findings.sort(key=lambda f: (-f.risk_score, -f.confidence, f.source, f.line))
    return findings
