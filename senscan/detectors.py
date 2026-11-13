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
    "not_markup_literal": U.not_markup_literal,
    "plausible_secret": U.plausible_secret_value,
    "key_material_shape": U.key_material_shape,
}

# 需要原文与命中位置的硬校验：纯数字类型靠字段语义反证，而不是靠值本身。
CONTEXT_VALIDATORS: dict[str, Callable[[str, str, int, int], bool]] = {
    "not_numeric_field": lambda v, text, start, end: not U.numeric_field_hit(text, start, end),
    "pem_head_body": lambda v, text, start, end: U.pem_head_has_body(text, end),
}

# 只有"数学/结构证据"才配称「已校验」。以下都只是形态过滤，一律不进这个集合：
#   mac（首字节/OUI）、serial_no、email、cn_mobile（号段白名单）、
#   imsi（长度 + MCC 前缀）、hex32（长度 == 32）。
# 它们没有校验位：把 MD5 当 LTK、把订单号当 IMSI、把 size 当手机号时，
# 绿色「已校验」只会给误报背书。有字段名时显示「上下文」，否则「仅格式」。
STRONG_VALIDATORS = frozenset({
    "luhn", "jwt", "pem_body", "basic_auth", "cn_id_card",
    "bank_card", "iccid", "cred_uri", "jdbc_cred",
    "der_private", "der_public", "der_key",
})


_ASCII_WORD_BOUNDARY = r"(?a:\b)"


@lru_cache(maxsize=256)
def _compiled(rule: Rule) -> re.Pattern[str]:
    # Python 的 \b 默认按 Unicode 判词，汉字也算"词字符"，于是
    # 「密钥ghp_xxx」「令牌AKIA...」这类中文紧邻的前缀型凭据整体漏报。
    # 用局部 ASCII 标志把 \b 限定为 ASCII 词边界：中文与 ASCII 之间成立，
    # 而英文标识符内部（keyghp_）仍不成立——既补漏报又不放宽误报。
    return re.compile(_ascii_boundary(rule.pattern), rule.flags)


def _ascii_boundary(pattern: str) -> str:
    return pattern.replace(r"\b", _ASCII_WORD_BOUNDARY)


# ---------------------------------------------------------------- 字面量预筛
#
# 瓶颈不是某条正则写得差，而是 83 条规则各扫一遍全文：17.8MB 日志 = 1.5G
# 次「位置 × 规则」。实测把规则合并成一条 alternation 反而更慢（Python 的
# re 在交替时仍逐个分支尝试，且同位置还要回退重试）。
#
# 真正有效的是「这条规则的关键字全文都不存在，就别扫了」：一次 text.lower()
# 之后用 memchr 级的子串查找，几百毫秒就能筛掉绝大部分规则——真实日志里
# 绝大多数类型的密钥一条都不出现。
#
# 安全性完全取决于字面量「必然出现」。所以这里用保守的语法推导：只在能证明
# 该片段必须出现在匹配结果里时才取用，遇到可选组、零宽断言、无法判定的结构
# 一律放弃（返回空集 = 不筛，照常全扫）。

_QUANT_AFTER = re.compile(r"[?*+]|\{\d+(?:,\d*)?\}")


def _skip_class(s: str, i: int) -> int:
    j = i + 1
    while j < len(s):
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == "]":
            return j + 1
        j += 1
    return len(s)


def _skip_quant(s: str, i: int) -> int:
    m = _QUANT_AFTER.match(s, i)
    return m.end() if m else i


def _group_body(s: str, i: int) -> tuple[str | None, int]:
    """i 指向 '('，返回 (组内表达式, 结束位置)。"""
    depth = 0
    j = i
    while j < len(s):
        ch = s[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "[":
            j = _skip_class(s, j)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                inner = s[i + 1:j]
                for pre in ("?:", "?P<", "?i:", "?s:", "?m:", "?a:", "?u:"):
                    if inner.startswith(pre):
                        inner = inner[len(pre):]
                        break
                return inner, j + 1
        j += 1
    return None, len(s)


def _split_top(s: str) -> list[str]:
    """按顶层 | 切分，括号与字符类内部的 | 不算。"""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            cur.append(s[i:i + 2])
            i += 2
            continue
        if ch == "[":
            j = _skip_class(s, i)
            cur.append(s[i:j])
            i = j
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


_LITERAL = re.compile(r"[A-Za-z0-9_]{3,}|[\u4e00-\u9fff]{2,}")
_OPT_SEP = re.compile(r"\[([^\]]{1,12})\]\?")
MAX_VARIANTS = 12
MAX_LITERAL_LEN = 40


def _is_literal_char(ch: str) -> bool:
    # 下划线在正则里就是字面量本身（api_key / device_sn），必须算进字面量串
    return ch.isalnum() or ch == "_" or "\u4e00" <= ch <= "\u9fff"


def _sep_options(s: str, i: int) -> tuple[tuple[str, ...], int] | None:
    """识别 `[_\\-]?` 这种「0 或 1 个字符」的分隔类，返回 (可选字符串, 结束位置)。

    只处理可枚举的类：字符数 ≤3、无范围。`{0,4}` 这类多字符分隔一律放弃，
    否则枚举不全，预筛会错杀。
    """
    m = _OPT_SEP.match(s, i)
    if not m:
        return None
    body = m.group(1)
    chars: list[str] = []
    j = 0
    while j < len(body):
        ch = body[j]
        if ch == "\\":
            esc = body[j + 1:j + 2]
            if not esc or esc.isalnum() or esc == "_":
                return None            # \s / \d 之类：可能是制表符换行，不猜
            chars.append(esc)
            j += 2
            continue
        if ch.isalnum() and ch != "_":
            return None                # a-z 这类范围不枚举
        chars.append(ch)
        j += 1
    if not chars or len(chars) > 3:
        return None
    return tuple([""] + chars), m.end()


def _expand(s: str, i: int, m: re.Match[str]) -> frozenset[str]:
    """把 `api` + `[_\\-]?` + `key` 展开成 api / api_key / api-key。

    单个 `api` 满日志都是（`/api/v1`），预筛等于没筛；展开成 `api_key` 之后
    才真正具备选择性。
    """
    variants = {m.group(0).lower()}
    end = m.end()
    while len(variants) <= MAX_VARIANTS:
        sep = _sep_options(s, end)
        if sep is None:
            break
        opts, nxt = sep
        tail = _LITERAL.match(s, nxt) if nxt < len(s) and _is_literal_char(s[nxt]) else None
        if tail is None:
            break
        word = tail.group(0).lower()
        variants = {v + sep_ch + word for v in variants for sep_ch in opts}
        if any(len(v) > MAX_LITERAL_LEN for v in variants):
            break
        end = tail.end()
    return frozenset(variants)


def _branch_literals(s: str) -> frozenset[str] | None:
    """单个分支里必然出现的一个字面量（找到就够，用于「任一命中则不跳过」）。"""
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(s, i)
            continue
        if ch == "(":
            look = s[i + 1:i + 4]
            body, end = _group_body(s, i)
            if look.startswith(("?=", "?!", "?<=", "?<!")):
                i = end                     # 零宽断言：内容不必然出现
                continue
            quant = _QUANT_AFTER.match(s, end)
            q = quant.group(0) if quant else ""
            optional = q[:1] in ("?", "*") or q.startswith("{0")
            if body is not None and not optional:
                got = _lits(body)
                if got:
                    return got
            i = _skip_quant(s, end)
            continue
        if _is_literal_char(ch):
            m = _LITERAL.match(s, i)
            if m:
                got = _expand(s, i, m)
                if got:
                    return got
            i += 1
            continue
        if ch in "?*+{":
            i = _skip_quant(s, i)
            continue
        i += 1
    return None


def _lits(fragment: str) -> frozenset[str] | None:
    acc: set[str] = set()
    for branch in _split_top(fragment):
        got = _branch_literals(branch)
        if got is None:
            return None
        acc |= got
    return frozenset(acc) if acc else None


@lru_cache(maxsize=512)
def _must_literals(rule: Rule) -> frozenset[str]:
    """规则命中时必然出现在原文里的字面量；空集表示无法预筛。"""
    try:
        got = _lits(rule.pattern)
    except Exception:            # 解析失败就退回全扫，绝不因为优化漏报
        return frozenset()
    return got or frozenset()


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
    elif rule.no_context_penalty:
        score -= rule.no_context_penalty
        reasons.append("无字段名佐证（降权）")

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


@lru_cache(maxsize=32768)
def _validate(name: str, value: str) -> bool:
    """校验器都是纯函数，同一值反复出现（同一 token 打满日志）时直接吃缓存。"""
    fn = VALIDATORS.get(name)
    return True if fn is None else fn(value)


def _new_stats(stats: dict | None) -> dict:
    if stats is None:
        stats = {}
    for key in ("candidates", "rejected", "rejected_context", "rejected_boundary",
                "suppressed", "suppressed_context", "suppressed_threshold", "skipped_rules"):
        stats.setdefault(key, 0)
    return stats


def _evaluate(rule: Rule, m: re.Match[str], text: str, stats: dict,
              min_confidence: float,
              strings_dump: bool = False) -> tuple[str, int, int, float, str | None, list[str]] | None:
    """单条候选进判定，返回 (值, 起, 止, 分数, 上下文词, 理由)；被丢弃返回 None。"""
    try:
        raw = m.group(rule.group)
        span_start, span_end = m.span(rule.group)
    except IndexError:
        return None
    if not raw:
        return None
    # 二进制抽出来的文本里，每行是一条独立字符串，彼此没有任何语法关系。
    # DEX 里 `SDCardRecordMonthQueryReq(productKey=` 正好是一条完整字符串，
    # 若允许「值从下一行开始」，它就会和池子里的下一条串拼成假字段。
    # 二进制抽出来的文本里，每行是一条独立字符串，彼此没有任何语法关系。
    # 一条命中只要跨了行，就说明它把两条无关字符串拼成了一个「字段=值」——
    # DEX 里 `SDCardRecordMonthQueryReq(productKey=` 是完整的一条串，
    # OpenSSL 的 `Session-ID:` 和 `Session-ID-ctx:` 也是各自独立的串。
    # 只有完整 PEM 块例外：它本身就可能作为一条带换行的字符串被编译进二进制。
    if strings_dump and "\n" in m.group(0) and not raw.lstrip().startswith("-----BEGIN"):
        stats["rejected"] += 1
        stats["rejected_boundary"] += 1
        return None
    value = raw.strip().strip("\"'")
    if rule.strip_whitespace:
        # 串口日志按列宽硬折行，值被拆到多行；去掉空白还原原值。
        value = re.sub(r"\s+", "", value)
    # XML/HTML 里值后面紧跟标签（<w:t>密码:x</w:t>），切到首个 "<"，
    # 否则标签名会被当成值的一部分写进报告。
    if "<" in value:
        value = value.split("<", 1)[0].rstrip()
    if not value or len(value) < 4:
        return None
    if len(value) > rule.max_value_len:
        value = value[: rule.max_value_len]

    stats["candidates"] += 1

    # 硬校验：任一不过即丢弃
    for name in rule.validators:
        if not _validate(name, value):
            stats["rejected"] += 1
            return None

    for name in rule.context_validators:
        fn = CONTEXT_VALIDATORS.get(name)
        if fn is not None and not fn(value, text, span_start, span_end):
            stats["rejected"] += 1
            stats["rejected_context"] += 1
            return None

    ctx_kw = U.context_hit(text, span_start, span_end, rule.context_keywords,
                           rule.context_window, word_boundary=rule.context_word)
    if rule.context_required and not ctx_kw:
        stats["suppressed"] += 1
        stats["suppressed_context"] += 1
        return None

    bonus_hits = [n for n in rule.bonus_validators if VALIDATORS.get(n) and _validate(n, value)]
    score, reasons = _score(rule, value, ctx_kw, bonus_hits)

    if score < min_confidence:
        stats["suppressed"] += 1
        stats["suppressed_threshold"] += 1
        return None

    return value, span_start, span_end, score, ctx_kw, reasons


def detect(
    text: str,
    source: str,
    min_confidence: float = 0.55,
    stats: dict | None = None,
    rules: tuple[Rule, ...] = RULES,
    line_offset: int = 0,
    strings_dump: bool = False,
) -> list[Finding]:
    """对单个文本源执行全部规则，返回已去重、已排序的发现项。

    strings_dump=True 用于「容器里抽出来的二进制串」：每行一条独立字符串，
    因此不允许键值跨行拼接（详见 _evaluate）。
    """
    stats = _new_stats(stats)
    line_index = U.build_line_index(text)
    kept: dict[tuple[str, str], Finding] = {}

    def emit(rule: Rule, m: re.Match[str]) -> bool:
        """评估并收下一条候选；返回 False 表示这条候选没结论。"""
        got = _evaluate(rule, m, text, stats, min_confidence, strings_dump)
        if got is None:
            return False
        value, span_start, span_end, score, ctx_kw, reasons = got

        key = f"{rule.entity}:{_normalize(rule.entity, value)}"
        existing = kept.get(key)
        if existing is not None:
            existing.occurrences += 1
            if score > existing.confidence:
                existing.confidence = score
                existing.rule_id = rule.id
                existing.reasons = tuple(reasons)
                existing.validation = _validation(rule, ctx_kw)
            return True

        line_no, col = U.offset_to_line(line_index, span_start)
        parts = U.context_parts(text, span_start, span_end, rule.context_window)
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
            context=U.join_context(parts),
            context_parts=parts,
            category=rule.category or CREDENTIAL,
            validation=_validation(rule, ctx_kw),
            remediation=rule.remediation,
            reasons=tuple(reasons),
            normalized=_normalize(rule.entity, value),
        )
        return True

    # 关键字全文都不存在的规则直接跳过：真实日志里绝大多数类型一条都不出现，
    # 一次 lower() + 若干次子串查找就能省掉大部分全量扫描。
    low: str | None = None
    for rule in rules:
        must = _must_literals(rule)
        if must:
            if low is None:
                low = text.lower()
            if not any(lit in low for lit in must):
                stats["skipped_rules"] += 1
                continue
        for m in _compiled(rule).finditer(text):
            emit(rule, m)

    findings = _drop_subsumed(_collapse_same_value(list(kept.values())))
    findings.sort(key=lambda f: (-f.risk_score, -f.confidence, f.source, f.line))
    return findings
