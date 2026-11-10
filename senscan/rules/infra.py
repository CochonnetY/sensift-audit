"""基础设施类规则：数据库/中间件连接串、对象存储签名 URL、远程服务凭据。

这一类的价值在于"组合信号"：单看 `user:pass@` 不成规则，但配上协议前缀就是
一条可直接利用的入口。误报控制靠 `cred_uri` 校验器——它会把文档示例里的
`mysql://user:password@host` 全部挡掉。
"""

from __future__ import annotations

from ..models import INFRA, Risk, Rule

R = Risk

_SIGNED_URL_TAIL = r"""[^\s"'<>，。]{0,512}"""

INFRA_RULES: tuple[Rule, ...] = (
    # ============================== 连接串 ==============================
    Rule(
        id="db-uri-credential",
        entity="DB_CREDENTIAL",
        pattern=r"\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|clickhouse|oracle|ftp|sftp|smtp|ldap|ldaps)://[^\s:@/]{1,64}:[^\s@/]{1,128}@",
        risk=R.HIGH,
        base_confidence=0.85,
        category=INFRA,
        flags=0,
        validators=("cred_uri",),
        max_value_len=512,
        remediation="更换该数据源口令，检查账号权限是否可横向移动，确认网络访问控制",
        note="连接串内嵌明文账号口令",
    ),
    Rule(
        id="jdbc-credential",
        entity="DB_CREDENTIAL",
        pattern=r"jdbc:[a-z0-9]+://[^\s\"'<>]{6,400}",
        risk=R.HIGH,
        base_confidence=0.72,
        category=INFRA,
        validators=("jdbc_cred",),
        max_value_len=400,
        remediation="更换该数据源口令，并把口令移出配置文件到密钥管理服务",
        note="JDBC 连接串（含 password= 参数）",
    ),
    Rule(
        id="http-basic-uri",
        entity="DB_CREDENTIAL",
        pattern=r"""\bhttps?://[^\s:@/]{1,64}:[^\s@/]{1,128}@[^\s"'<>]{1,200}""",
        risk=R.HIGH,
        base_confidence=0.78,
        category=INFRA,
        validators=("cred_uri",),
        max_value_len=384,
        remediation="URL 内嵌口令会随请求日志扩散，改用 Header 鉴权并更换口令",
        note="URL 内嵌 Basic 凭据（ES 控制台、管理后台、WebDAV 常见）",
    ),

    # ============================== 对象存储签名 URL ==============================
    Rule(
        id="signed-url-aliyun-oss",
        entity="OSS_SIGNED_URL",
        pattern=r"""(?:https?:)?//[^\s"'<>]{0,512}[?&]OSSAccessKeyId=[A-Za-z0-9]{8,32}""" + _SIGNED_URL_TAIL,
        risk=R.HIGH,
        base_confidence=0.9,
        category=INFRA,
        max_value_len=512,
        remediation="缩短签名有效期，并把生成的签名 URL 从日志中剔除",
        note="阿里云 OSS 预签名 URL，有效期内可越权读写",
    ),
    Rule(
        id="signed-url-aws-s3",
        entity="OSS_SIGNED_URL",
        pattern=r"""(?:https?:)?//[^\s"'<>]{0,512}[?&]X-Amz-(?:Signature|Credential)=[A-Za-z0-9%_\-]{8,}""" + _SIGNED_URL_TAIL,
        risk=R.HIGH,
        base_confidence=0.9,
        category=INFRA,
        max_value_len=512,
        remediation="缩短签名有效期，撤销对应临时凭据",
        note="AWS S3 预签名 URL",
    ),
    Rule(
        id="signed-url-tencent-cos",
        entity="OSS_SIGNED_URL",
        pattern=r"""(?:https?:)?//[^\s"'<>]{0,512}[?&]q-(?:sign-algorithm|ak)=[A-Za-z0-9%_\-]{3,}""" + _SIGNED_URL_TAIL,
        risk=R.HIGH,
        base_confidence=0.88,
        category=INFRA,
        max_value_len=512,
        remediation="缩短签名有效期，轮换对应 SecretId",
        note="腾讯云 COS 签名 URL",
    ),
    Rule(
        id="signed-url-qiniu",
        entity="OSS_SIGNED_URL",
        pattern=r"""(?:https?:)?//[^\s"'<>]{0,512}[?&]token=[0-9A-Za-z_\-]{16,}:[0-9A-Za-z_\-+/=]{16,}""" + _SIGNED_URL_TAIL,
        risk=R.HIGH,
        base_confidence=0.88,
        category=INFRA,
        max_value_len=512,
        remediation="缩短下载凭证有效期，轮换 AK/SK",
        note="七牛云下载凭证",
    ),
    Rule(
        id="signed-url-azure-sas",
        entity="OSS_SIGNED_URL",
        pattern=r"\bsv=\d{4}-\d{2}-\d{2}&s[src]=[a-z]&sig=[A-Za-z0-9%+/=]{40,}",
        risk=R.HIGH,
        base_confidence=0.88,
        category=INFRA,
        max_value_len=512,
        remediation="在存储账户中轮换密钥或撤销 SAS 策略",
        note="Azure Blob SAS Token",
    ),

    # ============================== 云账号 / 存储密钥 ==============================
    Rule(
        id="azure-storage-account-key",
        entity="API_KEY",
        pattern=r"\bAccountKey=[A-Za-z0-9+/=]{86,90}",
        risk=R.CRITICAL,
        base_confidence=0.93,
        category=INFRA,
        remediation="在存储账户中轮换密钥，并检查访问日志",
        note="Azure Storage 连接串中的账户密钥",
    ),
    Rule(
        id="aws-session-token",
        entity="TOKEN",
        pattern=r"""(?i)\b(?:aws[_\-]?session[_\-]?token|x-amz-security-token)\b["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,2048})""",
        risk=R.HIGH,
        base_confidence=0.85,
        category=INFRA,
        group=1,
        remediation="临时凭据在有效期内仍可用，需确认 STS 会话已失效",
        note="AWS STS 临时会话令牌",
    ),

    # ============================== 远程服务 ==============================
    Rule(
        id="rtsp-credential",
        entity="RTSP_CRED",
        pattern=r"""\brtsp://([^:/@\s"'<>]{1,64}):([^@/\s"'<>]{1,64})@[^\s"'<>]{1,255}""",
        risk=R.HIGH,
        base_confidence=0.9,
        category=INFRA,
        validators=("cred_uri", "not_placeholder"),
        max_value_len=384,
        remediation="摄像头/RSP 服务改用强口令并限制来源 IP，检查 NVR 是否对外暴露",
        note="RTSP 地址内嵌明文账号口令（摄像头常见）",
    ),
)
