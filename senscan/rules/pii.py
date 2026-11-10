"""个人信息（PII）规则：中国手机号、身份证、银行卡、邮箱。

这一类的定位与凭据不同——它不是"泄露了就得轮换"，而是"日志/埋点里不该有的字段"。
所以风险等级按《个人信息保护法》口径给：身份证、银行卡属敏感个人信息为 HIGH，
手机号和邮箱为 MEDIUM/LOW，但都配了可执行的处置建议。

误报控制策略：
- 手机号：号段白名单 + 假号黑名单（13800138000 这类日志里遍地都是）
- 身份证：GB 11643 加权模 11 校验 + 出生日期合法性，随机串通过率约 1/11 × 日期合法率
- 银行卡：Luhn + 长度 + 15 位仅认 AMEX 前缀（否则与 IMEI 全面互撞）
- 全部要求字段名或自然语言上下文，裸数字串不进报告（银行卡强制要求）
"""

from __future__ import annotations

from ..models import PII, Risk, Rule

R = Risk

_PII_REMEDIATION = "该字段不应出现在日志/埋点中；在采集侧增加脱敏，并对已落库数据按最小必要清理"

PII_RULES: tuple[Rule, ...] = (
    Rule(
        id="cn-id-card",
        entity="ID_CARD",
        pattern=r"(?<![0-9A-Za-z])(\d{17}[\dXx])(?![0-9A-Za-z])",
        risk=R.HIGH,
        base_confidence=0.66,
        category=PII,
        group=1,
        validators=("cn_id_card",),
        context_keywords=("idcard", "id_card", "idno", "id_no", "身份证", "证件号", "cert_no", "certno", "identity"),
        remediation="身份证号属敏感个人信息，需立即从日志清除并评估是否已发生对外传输",
        note="18 位居民身份证，GB 11643 校验通过",
    ),
    Rule(
        id="cn-mobile",
        entity="PHONE",
        pattern=r"(?<!\d)(1[3-9]\d{9})(?!\d)",
        risk=R.MEDIUM,
        base_confidence=0.58,
        category=PII,
        group=1,
        validators=("cn_mobile",),
        context_keywords=("phone", "mobile", "tel", "msisdn", "手机", "电话", "手机号", "联系方式", "contact"),
        remediation=_PII_REMEDIATION,
        note="中国大陆手机号，号段校验通过",
    ),
    Rule(
        id="bank-card",
        entity="BANK_CARD",
        pattern=r"(?<!\d)(\d{16,19}|\d{15})(?!\d)",
        risk=R.HIGH,
        base_confidence=0.6,
        category=PII,
        group=1,
        validators=("bank_card",),
        context_keywords=("card", "cardno", "card_no", "pan", "银行卡", "卡号", "账号", "account"),
        context_required=True,
        remediation="银行卡号属敏感个人信息，需按金融数据留存要求处置并核查传输链路",
        note="银行卡号：Luhn 通过且存在卡号字段名",
    ),
    Rule(
        id="email",
        entity="EMAIL",
        pattern=r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}(?![A-Za-z0-9\-])",
        risk=R.LOW,
        base_confidence=0.52,
        category=PII,
        validators=("email",),
        context_keywords=("email", "mail", "邮箱", "收件人", "user", "account", "to", "from"),
        remediation=_PII_REMEDIATION,
        note="邮箱地址；TLD 必须为字母，排除 IP/端口等伪邮箱",
    ),
)
