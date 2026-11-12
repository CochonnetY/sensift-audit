"""IoT / 嵌入式设备凭据规则：设备三元组（PK / DN / DS）与模组日志写法。

适用场景：阿里云 IoT / 涂鸦 / 华为 OceanConnect / 小米 / 自研 SDK 的
「一机一密」设备三元组，以及 C 语言 SDK 打出来的设备信息日志。

这一类为什么必须单独成包：

1. **值本身没有任何格式特征。** ProductKey / DeviceName / DeviceSecret 都是
   无前缀、无校验和、无固定长度的随机字母数字串，通用 secret 扫描器
   （gitleaks / trufflehog / Nosey Parker）一律扫不出来——它们的规则全部
   依赖厂商前缀（AKIA、ghp_、sk-）或 PEM 头。这里**只能靠字段名定位**。

2. **字段名变体极多，且带嵌入式日志特有的噪声**（以下是实测样例）：
   - `config_managerproduct_key: xxx`   —— 模块名与字段名粘连，没有分隔符
   - `device_msg->device_secret: xxx`   —— C 结构体指针箭头写法
   - `device name:xxx`                  —— 空格分隔、冒号后无空格
   - `PK=xxx, DN=xxx, DS=xxx`          —— 两字母缩写，同行逗号分隔
   所以完整字段名规则**不加左边界**（允许任意标识符粘连前缀），赋值符统一
   允许 `:` / `=` / 可选引号与空白。

3. **缩写规则靠语境，不靠格式。** `PK` / `DN` / `DS` / `AK` / `SK` 在通用日志里
   也可能是 primary key、distinguished name、data source、access key 的缩写。
   做法：base_confidence 压到阈值以下（0.45），只有同行出现 IoT 语境关键词
   （`triplet` / `pk=` / `dn=` / `device_secret` / `iot` / `mqtt` …）才提权过线。
   这样既不需要改执行器，又让用户调低 `-m` 时仍能看到弱线索。

风险分级的依据：DeviceSecret 可让攻击者完整仿冒设备接入 MQTT/OTA 通道，
定 CRITICAL；DeviceName 是可关联到具体设备的标识，定 MEDIUM；
ProductKey 通常是产品级公开标识，单条定 LOW——但三者齐备时结论会升级，
由 scanner 在合并阶段打 iot_triplet 标记。
"""

from __future__ import annotations

from ..models import CREDENTIAL, DEVICE, Risk, Rule
from .keyword import _NOT_POLICY

R = Risk

# 强语境词：只有同行出现这些词，缩写规则才提权过线。
#
# 【踩过的坑】不要把 `pk=` / `dn=` / `ds=` / `ak=` / `sk=` 这类缩写键名放进语境词。
# context_hit 取的是命中位置前后的一段原文，里面天然包含命中自身的键名，
# 于是 `DS=xxx` 会因为文本里含 "ds=" 而给自己提权——实测导致孤立缩写、
# 数据库主键（PK/DN/DS）、LDAP DN 全部误报。也不要放 "iot" 这类短词，
# 它会命中 riot / idiot / pilot。
_TRIPLET_CTX = (
    "triplet", "三元组", "一机一密", "设备密钥", "设备三元组",
    "device_secret", "devicesecret", "product_key", "productkey",
    "device_name", "devicename", "device info", "device_msg",
    "setmasterdeviceinfo", "xos_iot", "iot_sdk", "iot sdk", "iot平台",
    "mqtt", "alink", "tuya", "oceanconnect",
)

# 云 SDK 缩写（AK/SK/AS/CS/TK）额外认可的语境，同样不含缩写键名自身
_CLOUD_CTX = _TRIPLET_CTX + (
    "aliyun", "accesskey", "secretkey", "secret_id", "云凭据", "云 sdk",
    "huaweicloud", "tencentcloud", "qcloud", "oss-cn", "cos.ap-",
)

_SECRET_REMEDIATION = (
    "立即在 IoT 平台轮换该设备密钥（DeviceSecret），并排查该设备近期的连接、"
    "影子与 OTA 升级记录；若日志中同时出现 PK/DN/DS，按设备身份完整仿冒处置"
)
_DEVICE_REMEDIATION = "设备标识可与账号、位置关联，日志留存前应做哈希化或脱敏"
_KEY_REMEDIATION = "产品标识通常公开，但与 DeviceName/DeviceSecret 同时出现即构成完整设备身份"

# 键名分隔符：下划线 / 空格 / 连字符 / 软换行。
# 串口日志按列宽硬折行时会把 `dev` 和 `Secret":` 拆到两行，[\s_\-] 里的
# \s 能吃下这个换行；{0,4} 又限制不能跨太多行造成误匹配。
_KSEP = r"[\s_\-]{0,4}"

# 值：8~64 位字母数字。允许 8 位是因为部分平台 ProductKey 只有 11 位。
_VAL = r"""["']?\s*[:：=＝]\s*["']?([A-Za-z0-9_\-]{8,64})(?![A-Za-z0-9_\-])"""

IOT_RULES: tuple[Rule, ...] = (
    # ==================== 完整字段名（不需要额外语境）====================
    Rule(
        id="iot-device-secret",
        entity="IOT_DEVICE_SECRET",
        pattern=r"(?i)(?:device" + _KSEP + r"secret|device" + _KSEP + r"key|device" + _KSEP + r"token|dev" + _KSEP + r"secret"
                r"|设备密钥" + _NOT_POLICY + r"|设备秘钥" + _NOT_POLICY + r"|设备私有密钥)" + _VAL,
        risk=R.CRITICAL,
        base_confidence=0.9,
        category=CREDENTIAL,
        group=1,
        validators=("not_placeholder",),
        bonus_validators=("entropy",),
        context_keywords=_TRIPLET_CTX,
        context_window=160,
        remediation=_SECRET_REMEDIATION,
        note="IoT 设备密钥 DeviceSecret：可仿冒设备接入，无任何格式特征，靠字段名定位",
    ),
    Rule(
        id="iot-product-key",
        entity="IOT_PRODUCT_KEY",
        pattern=r"(?i)(?:product" + _KSEP + r"key|prod" + _KSEP + r"key"
                r"|产品密钥" + _NOT_POLICY + r"|产品标识)" + _VAL,
        risk=R.LOW,
        base_confidence=0.86,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        context_keywords=_TRIPLET_CTX,
        context_window=160,
        remediation=_KEY_REMEDIATION,
        note="IoT ProductKey：允许前面粘连模块名（config_managerproduct_key）",
    ),
    Rule(
        id="iot-device-name",
        entity="IOT_DEVICE_NAME",
        pattern=r"(?i)(?:device" + _KSEP + r"name|dev" + _KSEP + r"name|client" + _KSEP + r"id)" + _VAL,
        risk=R.MEDIUM,
        base_confidence=0.84,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        context_keywords=_TRIPLET_CTX,
        context_window=160,
        remediation=_DEVICE_REMEDIATION,
        note="IoT DeviceName：支持 `device name:xxx` 空格写法与指针箭头前缀",
    ),

    # ==================== 两字母缩写（必须有同行 IoT 语境）====================
    # base 0.45 < 默认阈值 0.55；命中 context 后 +0.30 = 0.75 过线。
    # 用打分阈值代替 context_required，是为了让 -m 0.4 时弱线索仍可见。
    Rule(
        id="iot-device-secret-abbrev",
        entity="IOT_DEVICE_SECRET",
        pattern=r"(?i)(?<![A-Za-z0-9_])DS" + _VAL,
        risk=R.CRITICAL,
        base_confidence=0.45,
        category=CREDENTIAL,
        group=1,
        validators=("not_placeholder",),
        bonus_validators=("entropy",),
        context_keywords=_TRIPLET_CTX,
        context_window=200,
        remediation=_SECRET_REMEDIATION,
        note="DeviceSecret 缩写 DS=；同行需有三元组语境，否则被阈值压制",
    ),
    Rule(
        id="iot-product-key-abbrev",
        entity="IOT_PRODUCT_KEY",
        pattern=r"(?i)(?<![A-Za-z0-9_])PK" + _VAL,
        risk=R.LOW,
        base_confidence=0.45,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        context_keywords=_TRIPLET_CTX,
        context_window=200,
        remediation=_KEY_REMEDIATION,
        note="ProductKey 缩写 PK=；同行需有三元组语境",
    ),
    Rule(
        id="iot-device-name-abbrev",
        entity="IOT_DEVICE_NAME",
        pattern=r"(?i)(?<![A-Za-z0-9_])DN" + _VAL,
        risk=R.MEDIUM,
        base_confidence=0.45,
        category=DEVICE,
        group=1,
        validators=("not_placeholder",),
        context_keywords=_TRIPLET_CTX,
        context_window=200,
        remediation=_DEVICE_REMEDIATION,
        note="DeviceName 缩写 DN=；同行需有三元组语境（避免与 LDAP DN 混淆）",
    ),
    Rule(
        id="iot-cloud-ak-sk-abbrev",
        entity="API_KEY",
        pattern=r"(?i)(?<![A-Za-z0-9_])(?:AK|SK|AS|CS|TK)" + _VAL,
        risk=R.HIGH,
        base_confidence=0.44,
        group=1,
        validators=("not_placeholder",),
        bonus_validators=("entropy",),
        context_keywords=_CLOUD_CTX,
        context_window=200,
        remediation="确认该缩写对应的云凭据类型，按对应平台流程轮换；AK/SK 成对泄露等同于账号接管",
        note="云 SDK 日志里的 AK/SK/AS/CS/TK 缩写；强依赖同行 IoT/云语境，避免与主键等缩写混淆",
    ),

    # ==================== 三元组整行（兜底，保证成套出现时不漏）====================
    Rule(
        id="iot-triplet-inline",
        entity="IOT_DEVICE_SECRET",
        pattern=r"(?i)\b(?:device" + _KSEP + r"triplet|triplet|三元组)\b[^A-Za-z0-9\n]{0,40}"
                r"PK[=:][A-Za-z0-9_\-]{8,64}\s*[,，;]\s*DN[=:][A-Za-z0-9_\-]{8,64}\s*[,，;]\s*"
                r"DS[=:]([A-Za-z0-9_\-]{8,64})(?![A-Za-z0-9_\-])",
        risk=R.CRITICAL,
        base_confidence=0.94,
        category=CREDENTIAL,
        group=1,
        validators=("not_placeholder",),
        context_keywords=("triplet", "三元组"),
        context_window=200,
        remediation=_SECRET_REMEDIATION,
        note="`Using device triplet: PK=…, DN=…, DS=…` 整行结构；三元组齐备，置信度最高",
    ),
)
