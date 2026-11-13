"""数据模型：风险等级、类别、规则定义、发现项。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Risk(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def order(self) -> int:
        return _RISK_ORDER[self]

    @property
    def sarif_level(self) -> str:
        return _SARIF_LEVEL[self]

    @property
    def score(self) -> int:
        """报告用的 0-100 风险分，便于排序和看板配色。"""
        return _RISK_SCORE[self]

    @property
    def security_severity(self) -> str:
        """GitHub Code Scanning 口径的 0-10 严重度，SARIF 走这个字段自动分级。"""
        return _SECURITY_SEVERITY[self]


_RISK_ORDER = {Risk.CRITICAL: 0, Risk.HIGH: 1, Risk.MEDIUM: 2, Risk.LOW: 3, Risk.INFO: 4}
_RISK_SCORE = {Risk.CRITICAL: 95, Risk.HIGH: 75, Risk.MEDIUM: 50, Risk.LOW: 25, Risk.INFO: 5}
_SARIF_LEVEL = {
    Risk.CRITICAL: "error",
    Risk.HIGH: "error",
    Risk.MEDIUM: "warning",
    Risk.LOW: "note",
    Risk.INFO: "note",
}
_SECURITY_SEVERITY = {
    Risk.CRITICAL: "9.5",
    Risk.HIGH: "8.0",
    Risk.MEDIUM: "5.5",
    Risk.LOW: "3.0",
    Risk.INFO: "0.0",
}


# ---------------------------------------------------------------- 类别

CREDENTIAL = "credential"
PKI = "pki"
PII = "pii"
DEVICE = "device"
INFRA = "infra"
SESSION = "session"

CATEGORY_LABEL = {
    CREDENTIAL: "凭据",
    PKI: "密钥/证书",
    PII: "个人信息",
    DEVICE: "设备标识",
    INFRA: "基础设施",
    SESSION: "会话",
}

CATEGORY_ORDER = (PKI, CREDENTIAL, SESSION, INFRA, PII, DEVICE)


# ---------------------------------------------------------------- 验证状态

VALID_CHECKSUM = "checksum"   # 通过校验和 / 结构解析，可判定为真
VALID_CONTEXT = "context"     # 格式 + 字段名上下文，高可信但无数学验证
VALID_FORMAT = "format"       # 仅格式匹配

VALIDATION_LABEL = {
    VALID_CHECKSUM: "已校验",
    VALID_CONTEXT: "上下文",
    VALID_FORMAT: "仅格式",
}


@dataclass(slots=True, frozen=True)
class Rule:
    """一条检测规则。声明式定义，避免为每个实体写一个类。"""

    id: str
    entity: str
    pattern: str
    risk: Risk
    base_confidence: float
    category: str = CREDENTIAL
    source: str = "senscan"                   # gitleaks / secrets-patterns-db / detect-secrets / senscan
    group: int = 0
    flags: int = 0
    validators: tuple[str, ...] = ()          # 硬校验：不通过则丢弃
    context_validators: tuple[str, ...] = ()  # 需要原文+位置的硬校验（反证类），不通过则丢弃
    bonus_validators: tuple[str, ...] = ()    # 软校验：通过则加分
    context_keywords: tuple[str, ...] = ()    # 上下文关键词，命中提权
    context_required: bool = False            # 无上下文直接压制（用于高误报类型）
    context_word: bool = False                # 关键词按词边界匹配，避免 hotel 里的 tel 误提权
    no_context_penalty: float = 0.0           # 无上下文时的扣分，把裸格式压到阈值下
    context_window: int = 96
    max_value_len: int = 2048
    # 串口/终端日志按宽度硬折行时，值会被拆到两行（如 JDUNn8\n==）。
    # 开启后 detect 会把捕获值里的空白去掉再做校验与归一化。
    strip_whitespace: bool = False
    remediation: str = ""
    note: str = ""


@dataclass(slots=True)
class Finding:
    entity: str
    value: str
    risk: Risk
    confidence: float
    rule_id: str
    source: str
    offset: int
    line: int
    column: int
    context: str
    # (命中前原文, 命中值原文, 命中后原文)，供报告层高亮命中值；纯文本 context
    # 里的 ⟦⟧ 标记是给 JSON/CSV 用的降级展示。旧报告没有这个字段时按 context 渲染。
    context_parts: tuple[str, str, str] | None = None
    category: str = CREDENTIAL
    validation: str = VALID_FORMAT
    remediation: str = ""
    reasons: tuple[str, ...] = ()
    normalized: str = ""
    occurrences: int = 1
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        return f"{self.entity}:{self.normalized or self.value.strip()}"

    @property
    def risk_score(self) -> int:
        """风险分 × 置信度，用于最终排序：高置信的高危项排最前。"""
        return int(self.risk.score * (0.5 + 0.5 * self.confidence))

    @property
    def priority(self) -> str:
        """处置优先级：把"多严重"和"多确定"合成一个可执行的批次。

        在线验证确认"仍有效"的凭据强制 P0——它已从线索变成确认在用的泄露。
        """
        v = self.extra.get("verification")
        if isinstance(v, dict) and v.get("layer") == "online" and v.get("status") == "active":
            return "P0"
        if self.risk is Risk.CRITICAL or (self.risk is Risk.HIGH and self.confidence >= 0.85):
            return "P0"
        if self.risk is Risk.HIGH or (self.risk is Risk.MEDIUM and self.confidence >= 0.85):
            return "P1"
        return "P2"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "value": self.value,
            "risk": self.risk.value,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "category": self.category,
            "validation": self.validation,
            "confidence": round(self.confidence, 3),
            "rule_id": self.rule_id,
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "offset": self.offset,
            "occurrences": self.occurrences,
            "remediation": self.remediation,
            "reasons": list(self.reasons),
            "context": self.context,
            **({"context_parts": {
                "before": self.context_parts[0],
                "hit": self.context_parts[1],
                "after": self.context_parts[2],
            }} if self.context_parts else {}),
            **({"extra": self.extra} if self.extra else {}),
        }
