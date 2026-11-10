"""验证层：把「像不像凭据」推进到「这凭据还能不能用」。

三层，风险与能力严格分开：

1. **本地结构验证**（无网络、无副作用）——JWT 有效期与 alg、PEM/DER 结构、
   签名 URL 过期时间、AWS 临时/长期凭据、Stripe 测试/生产密钥、身份证与卡组织解析。
   结果是可解释的证据，不产生"确定在用"的断言。
2. **在线存活验证**（默认关闭，必须显式授权）——只调厂商**只读**端点判断凭据是否
   仍被接受。webhook 类端点一律不做：调用会投递消息，属于对第三方产生副作用。
3. **自定义内网代理**——国内云 AK/SK、微信 AppSecret 等需要构造签名请求的场景，
   无法用单个 token 验证，交给用户自建的验证服务，凭据不出内网。

在线层的安全约束（合规要点）：
- 端点必须显式列白名单，公网内置端点还需 allow_public=True；
- URL host 二次校验，禁止重定向（防 302 把凭据带到别的域）；
- 值只替换进模板指定位置，审计日志只记 SHA-256 前 16 位，不记原值；
- 超时、QPS 限速、单次上限，避免把扫描变成对厂商 API 的压测；
- 网络失败一律记为 unknown，绝不记为 inactive——"查不到"不等于"已失效"。
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import utils as U
from .models import Finding

# ---------------------------------------------------------------- 状态

ACTIVE = "active"        # 确认有效 / 仍在用
INACTIVE = "inactive"    # 确认已失效
EXPIRED = "expired"      # 已过期（本地可判定）
STRUCTURE = "structure"  # 本地结构有效，无法证明在用
UNKNOWN = "unknown"      # 未验证 / 无法判定
ERROR = "error"          # 验证过程出错
NA = "n/a"               # 该类实体不适用

LIVENESS_LABEL = {
    ACTIVE: "仍有效",
    INACTIVE: "已失效",
    EXPIRED: "已过期",
    STRUCTURE: "结构有效",
    UNKNOWN: "未验证",
    ERROR: "验证出错",
    NA: "不适用",
}

LIVENESS_ORDER = (ACTIVE, INACTIVE, EXPIRED, STRUCTURE, ERROR, UNKNOWN, NA)


@dataclass(slots=True)
class CheckResult:
    layer: str                 # local | online | none
    status: str
    detail: str
    endpoint: str = ""
    http_status: int | None = None
    checked_at: str = ""
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "status": self.status,
            "detail": self.detail,
            "endpoint": self.endpoint,
            "http_status": self.http_status,
            "checked_at": self.checked_at,
            "elapsed_ms": self.elapsed_ms,
        }


def liveness_of(f: Finding) -> str:
    v = f.extra.get("verification")
    return v.get("status", UNKNOWN) if isinstance(v, dict) else UNKNOWN


def value_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------- 本地验证

_JWT_EXP = re.compile(r"\bexp\b")


def _normalize_ts(ts: float) -> float:
    """Unix 时间参数可能是秒、毫秒或越界垃圾值，先归一再交给 datetime。"""
    if not isinstance(ts, (int, float)) or ts <= 0:
        return 0.0
    ts = float(ts)
    if ts > 1e12:                 # 13 位毫秒时间戳
        ts /= 1000.0
    if ts > 4102444800:           # 2100-01-01，超出视为无效参数
        return 0.0
    return ts


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return "时间不可解析"


def _jwt_check(v: str) -> CheckResult:
    parts = v.split(".")
    try:
        header = json.loads(U.b64url_decode(parts[0]))
        payload = json.loads(U.b64url_decode(parts[1]))
    except Exception:
        return CheckResult("local", STRUCTURE, "JWT 三段结构合法，payload 无法解析")
    alg = str(header.get("alg", "?"))
    exp = payload.get("exp")
    now = time.time()
    if alg.lower() == "none":
        return CheckResult("local", ACTIVE, "alg=none：该 JWT 未签名，任何人都可伪造，需按高危处置")
    exp = _normalize_ts(exp) if isinstance(exp, (int, float)) else 0.0
    if exp:
        if exp < now:
            when = _fmt_ts(exp)
            return CheckResult("local", EXPIRED, f"已过期（exp={when}）；签名密钥仍需评估是否轮换")
        when = _fmt_ts(exp)
        iss = str(payload.get("iss", ""))[:40]
        return CheckResult(
            "local", UNKNOWN,
            f"未过期（exp={when}，alg={alg}{'，iss=' + iss if iss else ''}）；有效性需签名校验或在线验证",
        )
    return CheckResult("local", UNKNOWN, f"无 exp 声明（alg={alg}），可能是长期有效令牌，建议优先处置")


def _asn1_tlv_length(der: bytes, pos: int) -> tuple[int, int] | None:
    """最小 ASN.1 长度解析，只用于验证 DER 结构自洽，不解析密钥内容。"""
    if pos >= len(der):
        return None
    first = der[pos]
    if first < 0x80:
        return first, pos + 1
    n = first & 0x7F
    if n == 0 or n > 4 or pos + 1 + n > len(der):
        return None
    return int.from_bytes(der[pos + 1:pos + 1 + n], "big"), pos + 1 + n


def _pem_check(v: str) -> CheckResult:
    if "ENCRYPTED" in v.upper():
        return CheckResult("local", STRUCTURE, "私钥已加密（有口令保护），但口令常与私钥同处泄露，仍需处置")
    m = re.search(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)[^-]*-----([\s\S]*?)-----END", v)
    if not m:
        return CheckResult("local", UNKNOWN, "仅发现 BEGIN 头，未取得完整密钥体；需回源文件确认")
    body = re.sub(r"[^A-Za-z0-9+/=]", "", m.group(2))
    try:
        der = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except Exception:
        return CheckResult("local", UNKNOWN, "PEM 块存在但 base64 体不完整")
    if not der or der[0] != 0x30:
        return CheckResult("local", UNKNOWN, "PEM 体不是合法 DER SEQUENCE")
    parsed = _asn1_tlv_length(der, 1)
    if parsed is None:
        return CheckResult("local", UNKNOWN, "DER 长度字段异常")
    length, content_start = parsed
    if content_start + length > len(der) + 2:
        return CheckResult("local", UNKNOWN, "DER 声明长度超出实际字节数，疑似截断")
    kind = m.group(1).strip()
    return CheckResult(
        "local", STRUCTURE,
        f"{kind}：DER 结构自洽（{len(der)} 字节，未加密）；请核对对应公钥是否仍在信任列表",
    )


def _signed_url_check(v: str) -> CheckResult:
    """签名 URL 的处置优先级完全取决于是否还在有效期内——这条能直接排除大量历史日志。"""
    # 腾讯云 COS q-sign-time=start;end（必须先于通用的 Expires 判断）
    m = re.search(r"(?i)q-sign-time=(\d{9,13});(\d{9,13})", v)
    if m:
        return _expiry_result(_normalize_ts(int(m.group(2))), "腾讯云 COS 预签名")
    # 阿里云 OSS / 七牛：Unix 秒
    m = re.search(r"(?i)[?&](?:Expires|e)=(\d{9,13})(?!\d)", v)
    if m:
        return _expiry_result(_normalize_ts(int(m.group(1))))
    # Azure SAS：se=2026-11-09T10%3A00%3A00Z
    m = re.search(r"(?i)[?&]se=([0-9T:\-%Z.]+)", v)
    if m:
        raw = urllib.parse.unquote(m.group(1))
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return _expiry_result(dt.timestamp(), source="Azure SAS se")
        except ValueError:
            pass
    # AWS S3：X-Amz-Date + X-Amz-Expires
    m = re.search(r"(?i)X-Amz-Date=(\d{8}T\d{6}Z)", v)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            ttl = re.search(r"(?i)X-Amz-Expires=(\d+)", v)
            return _expiry_result(start.timestamp() + int(ttl.group(1)) if ttl else 0, "AWS S3 预签名")
        except ValueError:
            pass
    return CheckResult("local", UNKNOWN, "未能解析出有效期参数，按未过期处理并人工复核")


def _expiry_result(ts: float, source: str = "签名 URL") -> CheckResult:
    ts = _normalize_ts(ts)
    if ts <= 0:
        return CheckResult("local", UNKNOWN, "有效期参数缺失或越界，按未过期处理并人工复核")
    when = _fmt_ts(ts)
    if ts < time.time():
        return CheckResult("local", EXPIRED, f"{source} 已于 {when} 过期，链接不再可访问，可降级处置")
    return CheckResult("local", ACTIVE, f"{source} 有效期至 {when}，当前仍可访问，需优先处置")


_CARD_BRANDS = (
    ("34", "AMEX"), ("37", "AMEX"), ("4", "VISA"),
    ("51", "Mastercard"), ("52", "Mastercard"), ("53", "Mastercard"),
    ("54", "Mastercard"), ("55", "Mastercard"), ("62", "银联 UnionPay"),
)


def local_check(f: Finding) -> CheckResult | None:
    """纯本地证据。返回 None 表示该类实体没有可离线判定的维度。"""
    v = f.value
    rid = f.rule_id

    if rid == "jwt" or (f.entity == "TOKEN" and v.startswith("eyJ") and v.count(".") == 2):
        return _jwt_check(v)
    if f.entity == "PRIVATE_KEY" and "-----BEGIN" in v:
        return _pem_check(v)
    if f.entity == "OSS_SIGNED_URL":
        return _signed_url_check(v)
    if rid == "aws-access-key-id":
        if v.startswith("ASIA"):
            return CheckResult("local", EXPIRED, "ASIA = STS 临时凭据，通常 1–12 小时自动失效；仍需核查是否可续期")
        return CheckResult("local", STRUCTURE, "AKIA/长期 AccessKeyId：不会自动失效，需在线验证或直接在 IAM 侧吊销")
    if rid == "aws-session-token":
        return CheckResult("local", EXPIRED, "AWS STS 会话令牌，随临时凭据一并到期；仍需核查是否可续期")
    if rid == "stripe-key" and "_test_" in v:
        return CheckResult("local", EXPIRED, "Stripe 测试密钥（sk_test_），不影响生产资金，但仍是有效凭据，需轮换")
    if rid == "stripe-key" and "_live_" in v:
        return CheckResult("local", STRUCTURE, "Stripe 生产密钥（sk_live_），可访问真实资金，属于最高处置优先级")
    if rid == "basic-auth-header":
        try:
            raw = base64.b64decode(v + "=" * (-len(v) % 4)).decode("utf-8")
            user = raw.split(":", 1)[0]
            return CheckResult("local", STRUCTURE, f"Basic 已解码，账号名长度 {len(user)}；需确认该账号是否仍启用（不输出口令）")
        except Exception:
            return CheckResult("local", UNKNOWN, "Basic 串无法解码")
    if f.entity == "ID_CARD":
        y = v[6:10]
        return CheckResult("local", STRUCTURE, f"GB 11643 校验通过（出生年份 {y}）；属敏感个人信息，按数据删除流程处置")
    if f.entity == "BANK_CARD":
        d = re.sub(r"\D", "", v)
        brand = next((b for p, b in _CARD_BRANDS if d.startswith(p)), "未知卡组织")
        return CheckResult("local", STRUCTURE, f"Luhn 校验通过（{brand}，{len(d)} 位）；属金融账户信息")
    if f.entity == "IMSI":
        return CheckResult("local", STRUCTURE, f"MCC={v[:3]}（中国），HLR 归属 {v[3:5]}；属网络身份标识")
    if f.entity == "ICCID":
        return CheckResult("local", STRUCTURE, f"ICCID 校验通过，发行方识别码 {v[:6]}；关联 SIM 卡身份")
    if f.entity in ("OTP", "SESSION_ID"):
        return CheckResult("local", UNKNOWN, "短时效凭据：本地无法判定，需结合采集时间与服务端 TTL 人工确认")
    if f.entity in ("CERT_FINGERPRINT", "MAC", "IMEI", "OAID", "IDFA", "LTK", "DEVICE_SN"):
        return CheckResult("local", NA, "设备/证书标识无「失效」概念，只能评估是否被采集与留存")
    return None


# ---------------------------------------------------------------- 在线端点

@dataclass(frozen=True, slots=True)
class Endpoint:
    id: str
    provider: str
    url: str
    method: str = "GET"
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None
    match_rules: tuple[str, ...] = ()
    match_entities: tuple[str, ...] = ()
    success_codes: tuple[int, ...] = (200, 204)
    invalid_codes: tuple[int, ...] = (401, 403, 404)
    success_json: tuple[str, Any] | None = None   # Slack / Telegram 的 {"ok": true}
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "provider": self.provider,
            "host": urllib.parse.urlsplit(self.url).hostname,
            "method": self.method,
            "match_rules": list(self.match_rules),
            "note": self.note,
            "public": True,
        }


# 只登记「只读、无副作用」的官方端点。
# 明确不做的：Slack/Discord webhook（POST 会真的发消息）、需要构造厂商签名的国内云
# API（无法用单 token 调）、任何写操作端点。
PUBLIC_ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint(
        id="github-user", provider="GitHub", url="https://api.github.com/user",
        headers=(("Authorization", "Bearer {{SECRET}}"), ("Accept", "application/vnd.github+json"),
                 ("X-GitHub-Api-Version", "2022-11-28")),
        match_rules=("github-pat", "github-fine-grained-pat"),
        note="GET /user，仅返回当前 token 归属账号信息",
    ),
    Endpoint(
        id="gitlab-user", provider="GitLab", url="https://gitlab.com/api/v4/user",
        headers=(("Authorization", "Bearer {{SECRET}}"),),
        match_rules=("gitlab-pat",),
        note="GET /api/v4/user，只读",
    ),
    Endpoint(
        id="slack-auth-test", provider="Slack", url="https://slack.com/api/auth.test",
        method="POST", headers=(("Authorization", "Bearer {{SECRET}}"),),
        match_rules=("slack-bot-token", "slack-app-token"),
        success_json=("ok", True),
        note="auth.test 是官方无副作用探测；webhook 类 token 不做验证",
    ),
    Endpoint(
        id="openai-models", provider="OpenAI", url="https://api.openai.com/v1/models",
        headers=(("Authorization", "Bearer {{SECRET}}"),),
        match_rules=("openai-key",),
        note="GET /v1/models，只读，不消耗额度",
    ),
    Endpoint(
        id="huggingface-whoami", provider="Hugging Face", url="https://api.huggingface.co/whoami-v2",
        headers=(("Authorization", "Bearer {{SECRET}}"),),
        match_rules=("huggingface-token",),
        note="GET /whoami-v2，只读",
    ),
    Endpoint(
        id="stripe-balance", provider="Stripe", url="https://api.stripe.com/v1/balance",
        headers=(("Authorization", "Bearer {{SECRET}}"),),
        match_rules=("stripe-key",),
        note="GET /v1/balance，只读账户余额对象",
    ),
    Endpoint(
        id="npm-whoami", provider="npm", url="https://registry.npmjs.org/-/whoami",
        headers=(("Authorization", "Bearer {{SECRET}}"),),
        match_rules=("npm-token",),
        note="GET /-/whoami，只读",
    ),
    Endpoint(
        id="telegram-getme", provider="Telegram", url="https://api.telegram.org/bot{{SECRET}}/getMe",
        match_rules=("telegram-bot-token",),
        success_json=("ok", True),
        note="getMe 只读；不会向任何会话发消息",
    ),
    Endpoint(
        id="notion-users", provider="Notion", url="https://api.notion.com/v1/users",
        headers=(("Authorization", "Bearer {{SECRET}}"), ("Notion-Version", "2022-06-28")),
        match_rules=("notion-token",),
        note="GET /v1/users，只读",
    ),
)

ENDPOINT_BY_ID = {e.id: e for e in PUBLIC_ENDPOINTS}


def endpoint_catalog() -> list[dict[str, Any]]:
    """给 UI 与文档用：同时列出「明确不支持在线验证」的类型及原因。"""
    items = [e.to_dict() for e in PUBLIC_ENDPOINTS]
    items.append({
        "id": "-", "provider": "Webhook 类（Slack / Discord）", "host": "-", "method": "-",
        "match_rules": ["slack-webhook", "discord-webhook"], "public": False,
        "note": "不提供在线验证：调用会向第三方频道投递消息，属于有副作用的动作",
    })
    items.append({
        "id": "-", "provider": "国内云 AK/SK / 微信 AppSecret", "host": "自建", "method": "-",
        "match_rules": ["aliyun-*", "tencent-*", "huawei-*", "wechat-*"], "public": False,
        "note": "厂商 API 需构造签名请求，单 token 无法验证；请配置内网验证代理（custom endpoint）",
    })
    return items


class VerifyPolicyError(ValueError):
    """策略校验失败：宁可拒绝，也不悄悄把凭据发出去。"""


_PRIVATE_HOST_SUFFIXES = (".internal", ".local", ".localhost", ".lan",
                          ".corp", ".test", ".invalid")


def _host_is_internal(host: str) -> bool:
    """自定义验证代理只允许本机 / 内网；公网目标必须显式列入 custom_hosts。"""
    h = host.lower().rstrip(".")
    if h in ("localhost", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local)
    except ValueError:
        pass
    return h.endswith(_PRIVATE_HOST_SUFFIXES) or "." not in h


@dataclass(slots=True)
class VerifyConfig:
    local: bool = True
    online: bool = False
    endpoint_ids: tuple[str, ...] = ()
    allow_public: bool = False
    custom: tuple[dict[str, Any], ...] = ()
    custom_hosts: tuple[str, ...] = ()
    timeout: float = 3.0
    max_checks: int = 50
    qps: float = 2.0
    audit_path: Path | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "VerifyConfig":
        d = d or {}
        ap = d.get("audit_path")
        return cls(
            local=bool(d.get("local", True)),
            online=bool(d.get("online", False)),
            endpoint_ids=tuple(d.get("endpoint_ids") or d.get("endpoints") or ()),
            allow_public=bool(d.get("allow_public", False)),
            custom=tuple(d.get("custom") or ()),
            custom_hosts=tuple(str(x).lower() for x in (d.get("custom_hosts") or ())),
            timeout=float(d.get("timeout", 3.0)),
            max_checks=int(d.get("max_checks", 50)),
            qps=float(d.get("qps", 2.0)),
            audit_path=Path(ap) if ap else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "local": self.local, "online": self.online,
            "endpoint_ids": list(self.endpoint_ids), "allow_public": self.allow_public,
            "custom_count": len(self.custom), "custom_hosts": list(self.custom_hosts),
            "timeout": self.timeout,
            "max_checks": self.max_checks, "qps": self.qps,
            "audit_path": str(self.audit_path) if self.audit_path else "",
        }

    def validate(self) -> None:
        if self.online and not (self.endpoint_ids or self.custom):
            raise VerifyPolicyError("在线验证已开启但未配置任何端点（endpoint_ids / custom 均为空）")
        if self.online and self.endpoint_ids and not self.allow_public:
            raise VerifyPolicyError("使用公网只读端点需显式设置 allow_public=true，并确认已获得授权")
        unknown = [x for x in self.endpoint_ids if x not in ENDPOINT_BY_ID]
        if unknown:
            raise VerifyPolicyError(f"未知端点 id: {unknown}")
        if self.online and self.max_checks <= 0:
            raise VerifyPolicyError("max_checks 必须大于 0")
        for c in self.custom:
            url = str(c.get("url", ""))
            u = urllib.parse.urlsplit(url)
            host = u.hostname or ""
            local_host = host in ("127.0.0.1", "localhost", "::1")
            if u.scheme != "https" and not (u.scheme == "http" and local_host):
                raise VerifyPolicyError(f"自定义端点必须使用 https（或本机 http）: {url}")
            if not host:
                raise VerifyPolicyError(f"自定义端点 URL 缺少 host: {url}")
            if not _host_is_internal(host) and host.lower() not in self.custom_hosts:
                raise VerifyPolicyError(
                    f"自定义端点 {host} 是公网地址，须在 custom_hosts 中显式列出"
                )

    def resolved_endpoints(self) -> tuple[Endpoint, ...]:
        out = [ENDPOINT_BY_ID[i] for i in self.endpoint_ids]
        for c in self.custom:
            out.append(Endpoint(
                id=str(c.get("id", "custom")),
                provider=str(c.get("provider", "自定义验证代理")),
                url=str(c.get("url", "")),
                method=str(c.get("method", "POST")).upper(),
                headers=tuple((str(k), str(v)) for k, v in (c.get("headers") or {}).items()),
                body=c.get("body"),
                match_rules=tuple(c.get("match_rules") or ()),
                match_entities=tuple(c.get("match_entities") or ()),
                success_codes=tuple(c.get("success_codes") or (200, 204)),
                invalid_codes=tuple(c.get("invalid_codes") or (401, 403, 404)),
                success_json=tuple(c["success_json"]) if c.get("success_json") else None,
                note=str(c.get("note", "用户自定义端点")),
            ))
        return tuple(out)

    def allowed_hosts(self) -> set[str]:
        return {urllib.parse.urlsplit(e.url).hostname or "" for e in self.resolved_endpoints()}


# ---------------------------------------------------------------- 传输

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise VerifyPolicyError(f"拒绝重定向到 {urllib.parse.urlsplit(newurl).hostname}（防凭据外带）")


_AUDIT_LOCK = threading.Lock()


def _audit(cfg: VerifyConfig, record: dict[str, Any]) -> None:
    if cfg.audit_path is None:
        return
    record = {"ts": datetime.now().isoformat(timespec="seconds"), **record}
    with _AUDIT_LOCK:
        try:
            cfg.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with cfg.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


def _render(template: str, secret: str, *, url: bool = False, body: bool = False) -> str:
    if body:
        esc = json.dumps(secret, ensure_ascii=False)[1:-1]
        return template.replace("{{SECRET}}", esc).replace("{{SECRET_JSON}}", esc)
    if url:
        return template.replace("{{SECRET}}", urllib.parse.quote(secret, safe=""))
    return template.replace("{{SECRET}}", secret)


def _call_endpoint(ep: Endpoint, secret: str, cfg: VerifyConfig) -> CheckResult:
    url = _render(ep.url, secret, url=True)
    u = urllib.parse.urlsplit(url)
    if (u.hostname or "") not in cfg.allowed_hosts():
        raise VerifyPolicyError(f"目标 host 不在允许列表: {u.hostname}")
    # 头值禁止 CRLF，防止命中值本身携带换行造成请求头注入
    headers = {k: _render(v, secret).replace("\r", "").replace("\n", "") for k, v in ep.headers}
    data = None
    if ep.body:
        data = _render(ep.body, secret, body=True).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")

    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, data=data, headers=headers, method=ep.method)
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=cfg.timeout) as resp:
            code, raw = resp.status, resp.read(8192)
    except urllib.error.HTTPError as exc:
        code, raw = exc.code, exc.read(8192)
    except VerifyPolicyError:
        raise
    except (urllib.error.URLError, OSError, TimeoutError, ssl.SSLError) as exc:
        return CheckResult("online", UNKNOWN, f"网络不可达或超时（{type(exc).__name__}）；不能据此判定已失效",
                           endpoint=ep.id, elapsed_ms=int((time.perf_counter() - t0) * 1000))
    elapsed = int((time.perf_counter() - t0) * 1000)

    status = UNKNOWN
    detail = f"HTTP {code}，无法据此判定；请人工复核"
    if code in ep.invalid_codes:
        status, detail = INACTIVE, f"HTTP {code}：服务端明确拒绝，凭据已失效或被吊销"
    elif code in ep.success_codes:
        if ep.success_json:
            try:
                payload = json.loads(raw.decode("utf-8", "replace"))
                ok = payload.get(ep.success_json[0]) == ep.success_json[1]
                status = ACTIVE if ok else INACTIVE
                detail = "服务端确认凭据有效" if ok else "服务端返回 ok=false，凭据无效"
            except (ValueError, AttributeError):
                detail = "HTTP 200 但响应体无法解析，需人工复核"
        else:
            status, detail = ACTIVE, f"HTTP {code}：服务端接受该凭据，确认仍有效"
    elif code == 429:
        detail = "HTTP 429：触发限流，本次不判定（请降低 qps 后重试）"
    elif code >= 500:
        detail = f"HTTP {code}：服务端错误，本次不判定"
    return CheckResult("online", status, detail, endpoint=ep.id, http_status=code,
                       checked_at=datetime.now().isoformat(timespec="seconds"), elapsed_ms=elapsed)


# ---------------------------------------------------------------- 编排

@dataclass(slots=True)
class VerifySummary:
    enabled_local: bool = False
    enabled_online: bool = False
    local_checked: int = 0
    online_checked: int = 0
    active: int = 0
    inactive: int = 0
    expired: int = 0
    structure: int = 0
    unknown: int = 0
    errors: int = 0
    skipped_limit: int = 0
    endpoints: list[str] = field(default_factory=list)
    audit_path: str = ""
    policy_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled_local": self.enabled_local,
            "enabled_online": self.enabled_online,
            "local_checked": self.local_checked,
            "online_checked": self.online_checked,
            "active": self.active,
            "inactive": self.inactive,
            "expired": self.expired,
            "structure": self.structure,
            "unknown": self.unknown,
            "errors": self.errors,
            "skipped_limit": self.skipped_limit,
            "endpoints": self.endpoints,
            "audit_path": self.audit_path,
            "policy_note": self.policy_note,
        }


def _pick_endpoint(f: Finding, endpoints: Iterable[Endpoint]) -> Endpoint | None:
    for ep in endpoints:
        if f.rule_id in ep.match_rules or f.entity in ep.match_entities:
            return ep
        if any(r.endswith("*") and f.rule_id.startswith(r[:-1]) for r in ep.match_rules):
            return ep
    return None


_THROTTLE_LOCK = threading.Lock()
_THROTTLE = {"last": 0.0, "window": 0.0, "count": 0}
GLOBAL_MAX_ONLINE_PER_MIN = 120


def _throttle(interval: float) -> bool:
    """进程级节流：QPS 与每分钟硬上限跨所有 run()/HTTP 请求生效。

    单次 run() 的 max_checks 挡不住"反复 POST /api/verify"，必须提到进程级。
    """
    with _THROTTLE_LOCK:
        now = time.time()
        if now - _THROTTLE["window"] >= 60:
            _THROTTLE["window"], _THROTTLE["count"] = now, 0
        if _THROTTLE["count"] >= GLOBAL_MAX_ONLINE_PER_MIN:
            return False
        wait = interval - (time.perf_counter() - _THROTTLE["last"])
        if wait > 0:
            time.sleep(wait)
        _THROTTLE["last"] = time.perf_counter()
        _THROTTLE["count"] += 1
        return True


def run(findings: list[Finding], cfg: VerifyConfig | None) -> VerifySummary:
    """就地给每条 Finding 写入 extra['verification']，返回汇总。"""
    if cfg is None or (not cfg.local and not cfg.online):
        return VerifySummary()
    cfg.validate()
    summary = VerifySummary(enabled_local=cfg.local, enabled_online=cfg.online)
    summary.policy_note = (
        "在线验证仅调用只读端点；webhook 与需签名请求的凭据不做验证；unknown 不等于已失效"
    )

    if cfg.local:
        for f in findings:
            try:
                c = local_check(f)
            except Exception as exc:  # 单条畸形值不能让整次扫描结果丢失
                c = CheckResult("local", UNKNOWN, f"本地结构验证异常：{type(exc).__name__}")
            if c is None:
                continue
            c.checked_at = datetime.now().isoformat(timespec="seconds")
            f.extra["verification"] = c.to_dict()
            summary.local_checked += 1
            _bump(summary, c.status)

    if cfg.online:
        if cfg.audit_path is None:
            cfg.audit_path = Path("senscan-verify-audit.jsonl")
        summary.audit_path = str(cfg.audit_path)
        endpoints = cfg.resolved_endpoints()
        summary.endpoints = [e.id for e in endpoints]
        seen: dict[str, CheckResult] = {}
        interval = 1.0 / max(cfg.qps, 0.1)

        for f in findings:
            ep = _pick_endpoint(f, endpoints)
            if ep is None:
                continue
            # 已由本地层确定为已过期的，不再外发（避免无意义的网络请求）
            if liveness_of(f) == EXPIRED:
                continue
            digest = value_fingerprint(f.value)
            if digest in seen:
                c = CheckResult(**seen[digest].to_dict())
                c.detail = seen[digest].detail + "（同值复用结果）"
            else:
                if summary.online_checked >= cfg.max_checks:
                    summary.skipped_limit += 1
                    c = CheckResult("online", UNKNOWN, f"超过单次验证上限 {cfg.max_checks}，未发起请求")
                elif not _throttle(interval):
                    summary.skipped_limit += 1
                    c = CheckResult("online", UNKNOWN, "超过进程级在线验证上限，未发起请求")
                else:
                    try:
                        c = _call_endpoint(ep, f.value, cfg)
                    except VerifyPolicyError as exc:
                        c = CheckResult("online", ERROR, f"策略拒绝：{exc}", endpoint=ep.id)
                    except Exception as exc:  # 端点实现异常不应中断整次扫描
                        c = CheckResult("online", ERROR, f"验证异常：{type(exc).__name__}", endpoint=ep.id)
                    summary.online_checked += 1
                    seen[digest] = c
                    _audit(cfg, {
                        "layer": "online", "endpoint": ep.id, "entity": f.entity,
                        "rule_id": f.rule_id, "value_sha256": digest,
                        "status": c.status, "http_status": c.http_status,
                        "elapsed_ms": c.elapsed_ms,
                        "host": urllib.parse.urlsplit(ep.url).hostname,
                    })
            f.extra["verification"] = c.to_dict()
            _bump(summary, c.status)

    return summary


def _bump(s: VerifySummary, status: str) -> None:
    attr = {
        ACTIVE: "active", INACTIVE: "inactive", EXPIRED: "expired",
        STRUCTURE: "structure", UNKNOWN: "unknown", ERROR: "errors",
    }.get(status)
    if attr:
        setattr(s, attr, getattr(s, attr) + 1)


def by_liveness(findings: list[Finding]) -> dict[str, int]:
    out = {k: 0 for k in LIVENESS_ORDER}
    for f in findings:
        out[liveness_of(f)] = out.get(liveness_of(f), 0) + 1
    return out
