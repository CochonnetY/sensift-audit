"""规则集合：按类别拆包，便于维护与按需裁剪。

新增实体类型时只需在对应文件加一条 Rule，不需要改执行器。
"""

from __future__ import annotations

from ..models import Rule
from .credentials import CREDENTIAL_RULES
from .devices import DEVICE_RULES
from .infra import INFRA_RULES
from .iot import IOT_RULES
from .keys import KEY_RULES
from .pii import PII_RULES

# 顺序只影响同一位置多条规则的命中先后，不影响最终去重结果
# （跨规则冲突由 detectors._collapse_same_value 按 风险 > 置信度 统一裁决）
RULES: tuple[Rule, ...] = (
    CREDENTIAL_RULES + KEY_RULES + IOT_RULES + INFRA_RULES + PII_RULES + DEVICE_RULES
)

__all__ = [
    "RULES", "CREDENTIAL_RULES", "KEY_RULES", "IOT_RULES",
    "INFRA_RULES", "PII_RULES", "DEVICE_RULES",
]
