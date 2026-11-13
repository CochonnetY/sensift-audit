"""设备标识类规则：MAC、IMEI/IMSI/ICCID、OAID/IDFA、蓝牙 LTK、证书指纹、设备序列号。

这是本工具相对通用 secret 扫描器的差异化部分——gitleaks / trufflehog / Nosey Parker
的关注点都在代码仓库里的凭据，对"设备日志里的标识符"基本空白。
国内合规场景下这些恰恰是判定"是否构成个人信息"的关键证据。

冲突处理是这一类的核心难点：
- IMEI 与 IMSI 同为 15 位数字。区分手段是 IMSI 的 MCC 前缀（中国 460）与字段名；
- IMEI 与 15 位银行卡都过 Luhn。银行卡规则因此只接受 AMEX 前缀的 15 位；
- 裸 UUID 与 OAID/IDFA 不可区分，所以裸 UUID 规则强制要求上下文。
"""

from __future__ import annotations

from ..models import DEVICE, PKI, Risk, Rule
from .keyword import key_re

R = Risk

DEVICE_RULES: tuple[Rule, ...] = (
    Rule(
        id="imei",
        entity="IMEI",
        pattern=r"(?<!\d)(\d{15})(?!\d)",
        risk=R.MEDIUM,
        base_confidence=0.55,
        category=DEVICE,
        group=1,
        validators=("luhn", "not_placeholder"),
        bonus_validators=("luhn",),
        context_keywords=("imei", "meid", "device_id", "deviceid", "device_sn", "序列号", "设备号"),
        no_context_penalty=0.12,
        remediation="IMEI 属设备标识符（个人信息），日志中应做哈希化或脱敏后再留存",
        note="15 位数字 + Luhn 校验通过",
    ),
    Rule(
        id="imeisv",
        entity="IMEI",
        pattern=r"""(?i)\b(?:imeisv|imei[_\-]?sv)\b[^0-9\n]{0,12}(\d{16})(?!\d)""",
        risk=R.MEDIUM,
        base_confidence=0.62,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        remediation="同 IMEI，按设备标识符脱敏处理",
        note="IMEISV：14 位 IMEI + 2 位软件版本，无校验位，依赖字段名",
    ),
    Rule(
        id="imsi",
        entity="IMSI",
        pattern=r"(?<!\d)((?:460|461|454|455|466)\d{12})(?!\d)",
        risk=R.MEDIUM,
        base_confidence=0.7,
        category=DEVICE,
        group=1,
        validators=("imsi",),
        context_validators=("not_numeric_field",),
        context_keywords=("imsi", "subscriber", "sim", "运营商", "用户标识"),
        context_word=True,
        no_context_penalty=0.25,
        remediation="IMSI 可定位到 SIM 卡持有人，属敏感标识，应立即从日志清除",
        note="IMSI：15 位且以中国 MCC 开头；无校验位，需字段名佐证，裸 15 位不上报",
    ),
    Rule(
        id="iccid",
        entity="ICCID",
        pattern=r"(?<!\d)(89\d{18})(?!\d)",
        risk=R.MEDIUM,
        base_confidence=0.72,
        category=DEVICE,
        group=1,
        validators=("iccid",),
        context_keywords=("iccid", "sim", "卡号"),
        remediation="ICCID 可映射到 SIM 卡，按设备标识符脱敏处理",
        note="SIM 卡序列号：20 位、89 开头、末位 Luhn",
    ),
    Rule(
        id="oaid",
        entity="OAID",
        pattern=key_re(
            r"oaid|openudid|android[_\-]?id|device[_\-]?uuid|guid",
            r"设备标识|安卓ID|匿名标识|设备ID",
            prefix=12,
        ) + r"""([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{64}|[0-9a-fA-F]{16,32})""",
        risk=R.MEDIUM,
        base_confidence=0.88,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        remediation="OAID/AndroidID 属个人信息，埋点中应改为可重置的匿名标识或不上报",
        note="匿名设备标识符，属个人信息（个保法口径）",
    ),
    Rule(
        id="idfa",
        entity="IDFA",
        pattern=key_re(
            r"idfa|idfv|advertising[_\-]?id|ad_id",
            r"广告标识|广告ID",
            prefix=12,
        ) + r"""([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})""",
        risk=R.MEDIUM,
        base_confidence=0.88,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        remediation="IDFA/IDFV 属个人信息，需确认是否取得用户授权（ATT）",
    ),
    Rule(
        id="device-uuid-bare",
        entity="OAID",
        # `urn:uuid:edef8ba9-...` 是 RFC 4122 的命名空间 URN（Tika / MP4 元数据里
        # 到处都是），不是设备标识。加固定长度回顾挡掉，不影响普通裸 UUID。
        pattern=r"(?<!urn:uuid:)\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b",
        risk=R.MEDIUM,
        base_confidence=0.3,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        context_keywords=("oaid", "udid", "device", "设备", "guid", "uuid"),
        context_required=True,
        remediation="确认该 UUID 是否为设备标识；若是，按设备标识符脱敏处理",
        note="裸 UUID：必须有关键词才报，否则与请求 ID 无法区分",
    ),
    Rule(
        id="device-serial",
        entity="DEVICE_SN",
        pattern=key_re(
            r"serial[_\-]?no|serialnumber|serial_number|device[_\-]?serial|device[_\-]?sn|sn",
            r"序列号|设备序列号|设备号|机身码|SN码",
        ) + r"""([A-Za-z0-9]{8,32})(?![A-Za-z0-9])""",
        risk=R.MEDIUM,
        base_confidence=0.65,
        category=DEVICE,
        group=1,
        validators=("serial_no",),
        remediation="设备序列号可唯一识别设备，日志中应脱敏",
        note="设备序列号，可与厂商售后系统反查到具体设备",
    ),
    Rule(
        id="mac-address",
        entity="MAC",
        # 冒号/连字符六段式：误报率低，裸格式即可上报。
        # 左右边界要挡住下划线与字母，避免匹配到更长标识符的中段。
        pattern=r"(?<![0-9A-Za-z_.:\-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z_.:\-])",
        risk=R.LOW,
        base_confidence=0.62,
        category=DEVICE,
        validators=("mac",),
        context_keywords=("mac", "bssid", "hwaddr", "wifi", "ether", "devicemac", "物理地址"),
        remediation="MAC 可用于设备追踪，外发日志前建议做前缀保留式脱敏",
    ),
    Rule(
        id="mac-address-dot",
        entity="MAC",
        # Cisco 点分三段式（0011.2233.4455）与版本号/日期批次形状完全相同，
        # 实测会把 `2026.1029.0000` 这类固件构建号报成 MAC。
        # 因此：① 必须有设备地址上下文；② 硬校验剔除年份开头的纯十进制串。
        pattern=r"(?<![0-9A-Za-z_.:\-])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Za-z_.:\-])",
        risk=R.LOW,
        base_confidence=0.60,
        category=DEVICE,
        validators=("mac", "mac_dot_not_version"),
        context_required=True,
        context_keywords=("mac", "bssid", "hwaddr", "ether", "devicemac", "物理地址", "硬件地址"),
        remediation="MAC 可用于设备追踪，外发日志前建议做前缀保留式脱敏",
        note="Cisco 点分格式：无设备地址上下文不上报，避免误伤版本号",
    ),
    Rule(
        id="ltk",
        entity="LTK",
        pattern=key_re(
            r"ltk|long[_\-]?term[_\-]?key|ble[_\-]?ltk",
            r"蓝牙密钥|长期密钥",
        ) + r"""([0-9a-fA-F]{32})(?![0-9a-fA-F])""",
        risk=R.MEDIUM,
        base_confidence=0.85,
        category=DEVICE,
        group=1,
        validators=("hex32",),
        context_keywords=("ltk", "long_term_key", "long-term-key", "longtermkey", "ble_ltk"),
        remediation="LTK 可解密已配对的蓝牙链路，需重新配对以生成新密钥",
        note="蓝牙长期密钥，可解密已配对链路",
    ),
    Rule(
        id="cert-fingerprint-colon",
        entity="CERT_FINGERPRINT",
        pattern=r"\b(?:[0-9A-Fa-f]{2}:){19,31}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])",
        risk=R.LOW,
        base_confidence=0.72,
        category=PKI,
        remediation="证书指纹本身不涉密，但可暴露内网服务与固定证书策略",
        note="冒号分隔的证书指纹（SHA-1 / SHA-256）",
    ),
    Rule(
        id="cert-fingerprint-hex",
        entity="CERT_FINGERPRINT",
        pattern=r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40})(?![0-9A-Fa-f])",
        risk=R.LOW,
        base_confidence=0.32,
        category=PKI,
        group=1,
        context_keywords=("fingerprint", "thumbprint", "cert", "pin-sha256", "指纹", "证书", "公钥"),
        context_required=True,
        remediation="同证书指纹；确认是否使用了证书固定（pinning）",
        note="裸 hash：仅在证书语境下报，避免与 commit sha / 文件校验和混淆",
    ),
)
