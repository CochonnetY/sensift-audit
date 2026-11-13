"""密钥材料规则：无 PEM 头的裸 ASN.1 DER 密钥 与 JSON 密钥字段。

起因：嵌入式设备把「密钥分区」整块 base64 dump 到串口日志，或直接在 JSON 里
打印 `"PrivateKey":"..."`, `"PublicKey":"MEkwEwYHKoZIzj0CAQYI..."`。
这类日志有四个特点，通用 secret 扫描器一个都接不住：

1. **没有 PEM 头**，所以 `-----BEGIN PRIVATE KEY-----` 规则完全失效；
2. **值是 ASN.1 DER 的 base64**，有固定结构前缀（EC P-256 SPKI 以
   `MFkwEwYHKoZIzj0CAQYI...` 开头、PKCS#8 EC 私钥以 `MIGHAgEAMBMGByqGSM49...` 开头）；
   前缀 + base64 解码后首字节为 0x30（SEQUENCE）可作为「已校验」级证据；
3. **字段名是驼峰 JSON**（PrivateKey / PublicKey / productKey / devSecret），
   且混在一段被加密的分区 dump 里，不是规整的 JSON 文档；
4. **串口日志按列宽硬折行**：键名 `dev` / `Secret":` 被拆到两行，
   值 `JDUNn8` / `==` 也被拆开。所以键名分隔符允许软换行，
   值捕获允许跨行并用 Rule.strip_whitespace 还原。

风险口径：私钥 CRITICAL；公钥本身不涉密，定 LOW——但它出现在日志里通常
意味着「整个密钥分区被打印了」，是同批存在私钥的强线索，note 里写清楚。
"""

from __future__ import annotations

from ..models import PKI, Risk, Rule

R = Risk

# 允许跨软换行的 base64 值：折行只在换行处发生，行首缩进被吃掉。
# 不含空格，所以遇到 JSON 的 `"` / `,` / 普通文本会自然停止。
_B64_VALUE = (
    r"""["']?\s*[:：=＝]\s*["']?"""
    r"([A-Za-z0-9+/=_\-]+(?:[ \t]*[\r\n]+[ \t]*[A-Za-z0-9+/=_\-]+)*)"
)

# 键名允许下划线 / 空格 / 连字符 / 软换行，也覆盖驼峰（0 个分隔符）
_KEY_SEP = r"[\s_\-]{0,4}"

_PRIV_FIELDS = (
    r"(?:private" + _KEY_SEP + r"key|priv" + _KEY_SEP + r"key|"
    r"pri" + _KEY_SEP + r"key|device" + _KEY_SEP + r"private" + _KEY_SEP + r"key"
    r"|私钥|设备私钥|签名私钥)"
)
_PUB_FIELDS = (
    r"(?:public" + _KEY_SEP + r"key|pub" + _KEY_SEP + r"key"
    r"|公钥|设备公钥|签名公钥)"
)

# 裸 DER：所有 ASN.1 SEQUENCE 的 base64 都以 M 开头（0x30 → 'M'）。
# 用宽松捕获 + der_private/der_public 硬校验，比把十几个前缀塞进正则更好维护，
# 也能吃下折行的密钥串。
_BARE_DER = (
    r"(?<![A-Za-z0-9+/=_\-])(M[A-Za-z0-9+/=_\-]+"
    r"(?:[ \t]*[\r\n]+[ \t]*[A-Za-z0-9+/=_\-]+)*)(?![A-Za-z0-9+/=_\-])"
)

_ROTATE_KEY = (
    "立即作废该密钥对并重新签发；设备侧需同步更新信任配置，"
    "并排查该密钥是否还用于固件签名、设备认证或 OTA 校验"
)

KEY_RULES: tuple[Rule, ...] = (
    # ============ 私钥 ============
    Rule(
        id="json-private-key-field",
        entity="PRIVATE_KEY",
        pattern=r"(?i)" + _PRIV_FIELDS + _B64_VALUE,
        risk=R.CRITICAL,
        base_confidence=0.85,
        category=PKI,
        group=1,
        validators=("not_placeholder", "key_material_shape"),
        bonus_validators=("der_key", "entropy"),
        context_keywords=("privatekey", "private_key", "privkey", "密钥", "pem", "cert"),
        context_window=96,
        strip_whitespace=True,
        max_value_len=4096,
        remediation=_ROTATE_KEY,
        note="JSON/配置里的 PrivateKey 字段；值可以是 DER base64、加密密钥或短密钥材料",
    ),
    Rule(
        id="der-private-key-bare",
        entity="PRIVATE_KEY",
        pattern=_BARE_DER,
        risk=R.CRITICAL,
        base_confidence=0.94,
        category=PKI,
        group=1,
        validators=("der_private",),
        strip_whitespace=True,
        max_value_len=4096,
        remediation=_ROTATE_KEY,
        note="无 PEM 头的 ASN.1 DER 私钥（PKCS#1/PKCS#8/SEC1/Ed25519），靠结构前缀 + base64 解码校验",
    ),

    # ============ 公钥 ============
    Rule(
        id="json-public-key-field",
        entity="PUBLIC_KEY",
        pattern=r"(?i)" + _PUB_FIELDS + _B64_VALUE,
        risk=R.LOW,
        base_confidence=0.8,
        category=PKI,
        group=1,
        validators=("not_placeholder", "plausible_secret"),
        bonus_validators=("der_key",),
        context_keywords=("publickey", "public_key", "pubkey", "公钥"),
        context_window=96,
        strip_whitespace=True,
        max_value_len=4096,
        remediation=(
            "公钥本身不涉密，但它说明日志正在 dump 密钥分区；"
            "确认同批日志是否含 PrivateKey / DeviceSecret，若有按私钥泄露处置"
        ),
        note="PublicKey 字段；通常是 EC P-256 SubjectPublicKeyInfo 的 DER base64",
    ),
    Rule(
        id="der-public-key-bare",
        entity="PUBLIC_KEY",
        pattern=_BARE_DER,
        risk=R.LOW,
        base_confidence=0.9,
        category=PKI,
        group=1,
        validators=("der_public",),
        strip_whitespace=True,
        max_value_len=4096,
        remediation="确认同批日志是否含私钥材料；公钥可用于证书固定与设备身份关联",
        note="无 PEM 头的 ASN.1 DER 公钥（EC / RSA / Ed25519 SPKI）",
    ),
)
