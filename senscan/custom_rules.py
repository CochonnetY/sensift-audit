"""外部规则文件：零依赖加载企业自定义检测规则（JSON）。

设计目标是让业务方扩规则不发版，同时不把任意输入变成可执行逻辑：
  - pattern 只做正则编译校验，不 eval、不导入模块；
  - validators / flags 全部走白名单，引用不存在的校验器直接拒绝；
  - id 不允许覆盖内置规则，避免同名规则悄悄改变既有判定；
  - 字段类型、范围、数量都设上限，坏文件在启动期报错而不是扫到一半炸。

文件格式（数组或 {"rules": [...]}）：
[
  {
    "id": "corp-internal-token",
    "entity": "TOKEN",
    "pattern": "corp[_-]tok[_-]([A-Za-z0-9]{24,})",
    "risk": "high",
    "base_confidence": 0.85,
    "category": "credential",
    "context_keywords": ["corp", "token"],
    "validators": ["not_placeholder"],
    "note": "内部令牌",
    "remediation": "到内部平台轮换"
  }
]
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import CREDENTIAL, Risk, Rule

MAX_RULES = 200
MAX_PATTERN_LEN = 4096
MAX_TEXT_LEN = 512
MAX_RULES_FILE_BYTES = 512 * 1024
_VALID_RISKS = frozenset(r.value for r in Risk)
_VALID_FLAGS = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "ASCII": re.ASCII,
}
_ENTITY_RX = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
_ID_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")

_INT_FIELDS = {
    "group": (0, 20),
    "context_window": (16, 4096),
    "max_value_len": (16, 32768),
}
_FLOAT_FIELDS = {
    "base_confidence": (0.0, 1.0),
    "no_context_penalty": (0.0, 1.0),
}
_TEXT_FIELDS = ("source", "remediation", "note")
_TUPLE_STR_FIELDS = ("validators", "context_validators", "bonus_validators",
                     "context_keywords")
_BOOL_FIELDS = ("context_required", "context_word", "strip_whitespace")


class RuleFileError(ValueError):
    """规则文件不可用或含非法规则。"""


def _known_validators() -> tuple[frozenset[str], frozenset[str]]:
    """普通校验器与上下文校验器是两张表，分开校验，别把合法名字误拒。"""
    from .detectors import CONTEXT_VALIDATORS, VALIDATORS
    return frozenset(VALIDATORS), frozenset(CONTEXT_VALIDATORS)


def _as_str_list(value: Any, field: str, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise RuleFileError(f"{where}.{field} 必须是字符串数组")
    if len(value) > 64:
        raise RuleFileError(f"{where}.{field} 最多 64 项")
    out = []
    for x in value:
        x = x.strip()
        if len(x) > 128:
            raise RuleFileError(f"{where}.{field} 单项过长")
        out.append(x)
    return tuple(out)


def _one(raw: Any, idx: int, known_ids: set[str],
         validators: frozenset[str], context_validators: frozenset[str]) -> Rule:
    where = f"rules[{idx}]"
    if not isinstance(raw, dict):
        raise RuleFileError(f"{where} 必须是对象")

    rid = raw.get("id")
    entity = raw.get("entity")
    pattern = raw.get("pattern")
    risk = raw.get("risk")
    conf = raw.get("base_confidence")

    if not isinstance(rid, str) or not _ID_RX.fullmatch(rid):
        raise RuleFileError(f"{where}.id 缺失或格式非法（字母数字开头，仅 ._-，2-64 字符）")
    if rid in known_ids:
        raise RuleFileError(f"{where}.id 与内置规则重复: {rid}（不允许覆盖内置规则）")
    if not isinstance(entity, str) or not _ENTITY_RX.fullmatch(entity):
        raise RuleFileError(f"{where}.entity 缺失或格式非法（大写字母/数字/下划线，2-32 字符）")
    if not isinstance(pattern, str) or not pattern:
        raise RuleFileError(f"{where}.pattern 缺失")
    if len(pattern) > MAX_PATTERN_LEN:
        raise RuleFileError(f"{where}.pattern 超过 {MAX_PATTERN_LEN} 字符上限")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RuleFileError(f"{where}.pattern 不是合法正则: {exc}") from exc
    if risk not in _VALID_RISKS:
        raise RuleFileError(f"{where}.risk 非法，可选 {sorted(_VALID_RISKS)}")
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not 0.0 <= float(conf) <= 1.0:
        raise RuleFileError(f"{where}.base_confidence 必须是 0-1 的数值")

    category = raw.get("category", CREDENTIAL)
    if not isinstance(category, str) or not re.fullmatch(r"[a-z_]{2,32}", category):
        raise RuleFileError(f"{where}.category 非法（小写字母/下划线，2-32 字符）")

    flags = 0
    raw_flags = raw.get("flags", [])
    if not isinstance(raw_flags, list) or not all(isinstance(x, str) for x in raw_flags):
        raise RuleFileError(f"{where}.flags 必须是字符串数组")
    for name in raw_flags:
        if name.upper() not in _VALID_FLAGS:
            raise RuleFileError(f"{where}.flags 含未知标志 {name}，可选 {sorted(_VALID_FLAGS)}")
        flags |= _VALID_FLAGS[name.upper()]

    kwargs: dict[str, Any] = {
        "id": rid,
        "entity": entity,
        "pattern": pattern,
        "risk": Risk(risk),
        "base_confidence": float(conf),
        "category": category,
        "flags": flags,
    }
    for f in _TEXT_FIELDS:
        v = raw.get(f)
        if v is not None:
            if not isinstance(v, str):
                raise RuleFileError(f"{where}.{f} 必须是字符串")
            if len(v) > MAX_TEXT_LEN:
                raise RuleFileError(f"{where}.{f} 超过 {MAX_TEXT_LEN} 字符上限")
            kwargs[f] = v
    for f, (lo, hi) in _INT_FIELDS.items():
        v = raw.get(f)
        if v is not None:
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise RuleFileError(f"{where}.{f} 必须是 {lo}-{hi} 的整数")
            kwargs[f] = v
    for f, (lo, hi) in _FLOAT_FIELDS.items():
        v = raw.get(f)
        if v is not None:
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= float(v) <= hi:
                raise RuleFileError(f"{where}.{f} 必须是 {lo}-{hi} 的数值")
            kwargs[f] = float(v)
    for f in _BOOL_FIELDS:
        v = raw.get(f)
        if v is not None:
            if not isinstance(v, bool):
                raise RuleFileError(f"{where}.{f} 必须是布尔值")
            kwargs[f] = v
    for f in _TUPLE_STR_FIELDS:
        kwargs[f] = _as_str_list(raw.get(f), f, where)

    for f, allowed in (("validators", validators),
                       ("bonus_validators", validators),
                       ("context_validators", context_validators)):
        bad = set(kwargs.get(f, ())) - allowed
        if bad:
            raise RuleFileError(f"{where}.{f} 含未知校验器 {sorted(bad)}")

    return Rule(**kwargs)


def load_text(text: str, base_rules: tuple[Rule, ...] | None = None) -> tuple[Rule, ...]:
    """解析规则文本，返回「内置 + 自定义」合并后的规则集。"""
    if len(text) > MAX_RULES_FILE_BYTES:
        raise RuleFileError(f"规则文件超过 {MAX_RULES_FILE_BYTES // 1024} KB 上限")
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise RuleFileError(f"规则文件不是合法 JSON: {exc}") from exc
    raws = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(raws, list):
        raise RuleFileError("规则文件必须是数组或含 rules 数组的对象")
    if not raws:
        raise RuleFileError("规则文件为空")
    if len(raws) > MAX_RULES:
        raise RuleFileError(f"自定义规则最多 {MAX_RULES} 条，当前 {len(raws)}")

    from .rules import RULES
    base = base_rules if base_rules is not None else RULES
    known_ids = {r.id for r in base}
    validators, context_validators = _known_validators()

    out: list[Rule] = []
    for i, raw in enumerate(raws):
        r = _one(raw, i, known_ids, validators, context_validators)
        known_ids.add(r.id)   # 文件内部也不允许重复
        out.append(r)
    return base + tuple(out)


def load(path: str | Path, base_rules: tuple[Rule, ...] | None = None) -> tuple[Rule, ...]:
    p = Path(path)
    if not p.is_file():
        raise RuleFileError(f"规则文件不存在: {p}")
    try:
        text = p.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise RuleFileError(f"规则文件读取失败: {exc}") from exc
    return load_text(text, base_rules)


__all__ = ["RuleFileError", "load", "load_text", "MAX_RULES"]
