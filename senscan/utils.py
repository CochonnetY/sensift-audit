"""通用工具：校验算法、熵、占位符识别、上下文提取、文本解码。"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from bisect import bisect_right
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- 校验算法


def luhn_valid(num: str) -> bool:
    """Luhn 校验。IMEI 第 15 位、银行卡号等均适用。"""
    if not num.isdigit() or len(num) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(prefix: str) -> str:
    """给定前 n 位，算出 Luhn 校验位（生成测试样本用）。"""
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = ord(ch) - 48
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def shannon_entropy(s: str) -> float:
    """字符级香农熵（bit/字符）。随机 base64 通常 > 3.8，自然语言 < 3.2。"""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_diversity(s: str) -> float:
    """不同字符数 / 长度。用于识别 aaaaaa、000000 这类退化串。"""
    return len(set(s)) / len(s) if s else 0.0


def mac_is_usable(s: str) -> bool:
    """排除全零、广播、组播地址——这类 MAC 不携带设备身份信息。"""
    hexs = re.sub(r"[^0-9A-Fa-f]", "", s).lower()
    if len(hexs) != 12:
        return False
    if hexs in ("000000000000", "ffffffffffff"):
        return False
    if int(hexs[0:2], 16) & 0x01:  # 组播/广播位
        return False
    return True


_DOTTED_DECIMAL = re.compile(r"^(\d{4})\.(\d{4})\.(\d{4})$")


def mac_dot_not_version(v: str) -> bool:
    """Cisco 点分格式（xxxx.xxxx.xxxx）专用反误报闸。

    纯十进制且首段是年份的字符串，在设备日志里几乎一定是构建号 / 日期批次，
    例如 `2026.1029.0000`、`2025.1124.0000`。它们按十六进制完全"合法"
    （首字节 0x20 甚至是单播），校验和与 OUI 都判不出来，只能靠语义挡掉。
    含 a-f 的真 MAC 不受影响；`0011.2233.4455` 这类全数字但非年份开头也放行。
    """
    m = _DOTTED_DECIMAL.fullmatch(v.strip())
    if not m:
        return True
    first, second, third = m.groups()
    if 1900 <= int(first) <= 2100:  # YYYY.MMDD.NNNN
        return False
    if third == "0000" and 1 <= int(second[:2]) <= 12 and 1 <= int(second[2:]) <= 31:
        return False  # MMDD.0000 批次号
    return True


def jwt_shape_ok(v: str) -> bool:
    parts = v.split(".")
    if len(parts) != 3:
        return False
    return all(len(p) >= 4 for p in parts) and parts[0].startswith("eyJ")


# ---------------------------------------------------------------- 结构解析类校验
#
# 这一组是"能离线证明"的校验：不调外部 API，仅靠算法或结构自洽。
# 通过它们命中的可以标记为「已校验」，报告里与"仅格式匹配"严格区分。


def b64url_decode(s: str) -> bytes:
    """base64url 解码，容忍缺失的 padding。"""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jwt_decodable(v: str) -> bool:
    """JWT 的 header 必须能解出 JSON 且含 alg —— 比前缀匹配硬得多。"""
    parts = v.split(".")
    if len(parts) != 3 or not parts[0].startswith("eyJ"):
        return False
    try:
        header = json.loads(b64url_decode(parts[0]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    return isinstance(header, dict) and ("alg" in header or "typ" in header)


def b64_payload_decodable(v: str) -> bool:
    """判断一段 base64 是否能解成可打印文本（用于 Basic Auth）。"""
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4), validate=False)
    except (ValueError, binascii.Error):
        return False
    if len(raw) < 4:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for ch in text if ch.isprintable())
    return printable / len(text) > 0.95


def basic_auth_is_pair(v: str) -> bool:
    """Basic Auth 解出来必须是 user:pass 形式，且不是示例值，否则只是普通 base64。"""
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4), validate=False).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    if ":" not in raw:
        return False
    user, pwd = raw.split(":", 1)
    if not user or not pwd:
        return False
    return not (user.lower() in _WEAK_PASSWORDS or pwd.lower() in _WEAK_PASSWORDS)


# ---------------------------------------------------------------- 中国个人信息校验


_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CODE = "10X98765432"


def cn_id_check_digit(body17: str) -> str:
    """给定身份证前 17 位，算出 GB 11643 校验位（生成测试样本用）。"""
    total = sum(int(c) * w for c, w in zip(body17, _ID_WEIGHTS))
    return _ID_CHECK_CODE[total % 11]


def cn_id_card_valid(s: str) -> bool:
    """18 位居民身份证：GB 11643 加权模 11 + 出生日期合法性。

    这就是「已校验」级别——随机 18 位数字通过率约 1/11 × 日期合法率，误报极低。
    """
    s = s.strip().upper()
    if len(s) != 18:
        return False
    body, check = s[:17], s[17]
    if not body.isdigit() or check not in _ID_CHECK_CODE:
        return False
    total = sum(int(c) * w for c, w in zip(body, _ID_WEIGHTS))
    if _ID_CHECK_CODE[total % 11] != check:
        return False
    try:
        datetime.strptime(s[6:14], "%Y%m%d")
    except ValueError:
        return False
    return 1900 <= int(s[6:10]) <= 2100


_CN_MOBILE = re.compile(r"1(?:3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8}")

# 文档与测试里最常出现的假号，必须挡掉，否则每条日志都会命中
_FAKE_MOBILE = frozenset({
    "13800138000", "13000000000", "13100000000", "13200000000", "13300000000",
    "13500000000", "13600000000", "13700000000", "13800000000", "13900000000",
    "15000000000", "15100000000", "15500000000", "15600000000", "15800000000",
    "15900000000", "17000000000", "17600000000", "17700000000", "17800000000",
    "18000000000", "18100000000", "18200000000", "18300000000", "18500000000",
    "18600000000", "18700000000", "18800000000", "18900000000", "19900000000",
})


def cn_mobile_valid(s: str) -> bool:
    """大陆手机号号段合法性过滤（非校验和）：白名单 + 排除假号与长连号。

    手机号没有校验位，11 位数字与 size/计数/时间戳在语法上不可区分；
    这一步只证明「可能是号段」，真假要靠字段名语义，报告不应标「已校验」。
    """
    if not _CN_MOBILE.fullmatch(s):
        return False
    if s in _FAKE_MOBILE:
        return False
    if re.search(r"(\d)\1{4,}", s):  # 5 位以上连号
        return False
    return True


def bank_card_valid(s: str) -> bool:
    """银行卡：Luhn + 长度区间。

    关键取舍：15 位只接受 AMEX 前缀（34/37）。否则 15 位数字会与 IMEI 全面互撞，
    两个 Luhn 都通过，无法区分——这是实测中最难解的一类冲突。
    """
    d = re.sub(r"[\s\-]", "", s)
    if not d.isdigit():
        return False
    if not 12 <= len(d) <= 19:
        return False
    if len(set(d)) < 5:
        return False
    if len(d) == 15 and not d.startswith(("34", "37")):
        return False
    return luhn_valid(d)


def iccid_valid(s: str) -> bool:
    """ICCID（SIM 卡序列号）：20 位、89 开头，末位 Luhn。"""
    d = re.sub(r"\s", "", s)
    if not d.isdigit() or len(d) != 20 or not d.startswith("89"):
        return False
    return luhn_valid(d)


_IMSI_PREFIXES = ("460", "461", "454", "455", "466")  # 中国内地及港澳台 MCC


def imsi_valid(s: str) -> bool:
    """IMSI：15 位且以中国 MCC 开头。与 IMEI 同为 15 位，靠前缀和上下文区分。"""
    return s.isdigit() and len(s) == 15 and s.startswith(_IMSI_PREFIXES)


def high_entropy(v: str, threshold: float = 3.4) -> bool:
    """凭据类的高熵判定。自然语言、路径、base64 图片头都会被挡在外面。"""
    return shannon_entropy(v) >= threshold


# ---------------------------------------------------------------- PEM 结构


_PEM_HEADER = re.compile(r"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?)-----")


def pem_has_body(block: str) -> bool:
    """BEGIN 与 END 之间必须真有 base64 内容，否则只是文档里的占位说明。"""
    m = _PEM_HEADER.search(block)
    if not m:
        return False
    tail = block[m.end():]
    if "-----END" in tail:
        inner = tail.split("-----END", 1)[0]
    else:
        inner = tail
    compact = re.sub(r"[\s\-]", "", inner)
    return len(compact) >= 64


def pem_kind(block: str) -> str:
    m = _PEM_HEADER.search(block)
    return m.group(1) if m else "PRIVATE KEY"


# ---------------------------------------------------------------- 连接串


_URI_CRED = re.compile(r"^[a-z0-9+.\-]+://([^:@/\s]{1,64}):([^@/\s]{1,128})@", re.I)

_WEAK_PASSWORDS = frozenset({
    "pass", "passwd", "password", "pwd", "secret", "123456", "1234567",
    "12345678", "admin", "root", "test", "changeit", "changeme", "xxx",
})


def cred_uri_ok(v: str) -> bool:
    """连接串里必须真的带"非占位"口令。

    这一步挡掉的是文档与示例里最常见的 `mysql://user:password@host`，
    它们在日志里出现的频率比真实凭据高得多。
    """
    m = _URI_CRED.match(v)
    if not m:
        return False
    user, pwd = m.group(1), m.group(2)
    if looks_placeholder(user) or looks_placeholder(pwd):
        return False
    if pwd.lower() in _WEAK_PASSWORDS:
        return False
    # 口令被 URL 编码过也算真实（%40 之类），不额外处理
    return len(pwd) >= 3


_JDBC_PASSWORD = re.compile(r"""(?i)[?;&]?(?:password|pwd)=([^;&"'\s]{3,128})""")


def jdbc_cred_ok(v: str) -> bool:
    m = _JDBC_PASSWORD.search(v)
    if not m:
        return False
    pwd = m.group(1)
    return not looks_placeholder(pwd) and pwd.lower() not in _WEAK_PASSWORDS


# ---------------------------------------------------------------- 隐私号 / 邮箱


def email_ok(v: str) -> bool:
    """邮箱校验：挡掉示例域、静态资源文件名、脱敏值、连接串里的 user@host 片段。"""
    low = v.lower()
    if "@" not in low:
        return False
    local, _, domain = low.rpartition("@")
    if not local or not domain or "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if not tld.isalpha() or len(tld) < 2:
        return False  # 排除 3@10.20.30.40 这类连接串片段
    if not any(ch.isalpha() for ch in local):
        return False  # 纯数字 local 只出现在 URI 凭据里
    if domain.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
        return False
    if domain in ("example.com", "example.org", "example.net", "test.com", "domain.com"):
        return False
    if low.startswith(("your", "xxx", "user@", "email@", "name@")):
        return False
    if set(local) <= {"x", "*", "."}:
        return False
    if len(local) > 64 or len(domain) > 255:
        return False
    return True


def serial_no_ok(v: str) -> bool:
    """设备序列号：排除全数字、纯字母、以及 xxx/0000 这类占位。"""
    if len(v) < 8 or len(set(v)) < 4:
        return False
    if v.isdigit() or v.isalpha():
        return False
    return not looks_placeholder(v)


# ---------------------------------------------------------------- 占位符 / 假阳性


_PLACEHOLDER_WORDS = {
    "example", "examples", "sample", "dummy", "placeholder", "changeme",
    "none", "null", "undefined", "redacted", "todo", "fixme", "test",
    "testing", "fake", "mock", "secret", "password", "token", "apikey",
    "api_key", "your_key", "yourkey", "xxxxxxxx",
}

_TEMPLATE_PATTERNS = (
    re.compile(r"\$\{[^}]{0,64}\}"),        # ${API_KEY}
    re.compile(r"\{\{[^}]{0,64}\}\}"),      # {{token}}
    re.compile(r"<[A-Za-z_][A-Za-z0-9_\-]{0,40}>"),  # <YOUR_KEY>
    re.compile(r"%[sdv]"),                  # %s 占位
    re.compile(r"\{\d{1,3}\}"),             # {0}
    re.compile(r"\*{3,}"),                  # ******
)


def looks_placeholder(v: str) -> bool:
    """识别文档示例值、脱敏值、模板变量——这是降噪的第一道闸。

    注意：不要用单个 `%` `$` 判模板，URL 编码（%2B）和 base64 会大量误伤。
    """
    low = v.strip().lower()
    if not low:
        return True
    if low in _PLACEHOLDER_WORDS:
        return True
    if low.startswith(("your_", "your-", "xxx", "redacted", "****",
                       "example", "sample", "dummy", "fake", "mock",
                       "test-", "test_", "changeme")):
        return True
    if "example.com" in low or "yourdomain" in low:
        return True
    # 官方文档示例凭据（AKIAIOSFODNN7EXAMPLE / wJalr...EXAMPLEKEY）在日志里遍地都是，
    # 且长得和真 key 一模一样；随机真凭据以 example 结尾的概率可忽略。
    if len(low) >= 12 and low.endswith(("example", "examplekey", "examplesecret")):
        return True
    if any(p.search(v) for p in _TEMPLATE_PATTERNS):
        return True
    if char_diversity(v) < 0.15:  # aaaaaa / 000000
        return True
    if re.fullmatch(r"(.{1,4})\1{2,}", low):  # abcabcabc
        return True
    return False


# ---------------------------------------------------------------- 上下文


def extract_context(text: str, start: int, end: int, window: int = 96, max_len: int = 240) -> str:
    """截取命中位置前后的原文，压成一行，供人工复核。"""
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right]
    snippet = snippet.replace("\r", "").replace("\n", " ⏎ ").replace("\t", " ")
    snippet = re.sub(r"\s{2,}", " ", snippet).strip()
    if len(snippet) > max_len:
        # 保证命中值本身留在片段里
        head = max_len // 2
        tail = max_len - head - 1
        snippet = f"{snippet[:head]}…{snippet[-tail:]}"
    return snippet


_FIELD_SEP_RE = re.compile(r"[,;{}\[\]]")
_JSON_KEY_IN_TEXT_RE = re.compile(r"""["'][A-Za-z_][\w.\-]{0,48}["']\s*:""")


def context_hit(text: str, start: int, end: int, keywords: tuple[str, ...], window: int = 96,
                word_boundary: bool = False, field_scoped: bool = True) -> str | None:
    """在命中所在行内、前后 window 字符范围查找关键词。

    严格限制在同一行：跨行取上下文会让相邻行的 device/oaid 字样污染判定。
    默认还收窄到"当前字段"：一行里挤着多个 JSON/logfmt 字段时，
    {"trace":"139...","phone":"..."} 里的 phone 属于下一个字段，不能给 trace 提权。
    """
    if not keywords:
        return None
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    lo = max(line_start, start - window)
    hi = min(line_end, end + window)
    # 必须把命中值本身排除，只看左右两侧的原文。
    # 否则值里恰好含关键词就会自我提权——实测踩过两次：
    #   `DS=xxx` 的键名 "ds=" 落在窗口内；假值 `..._triplet_context` 里的
    #   "triplet" 落在值内。两者都会让本该被阈值压制的缩写规则过线。
    left, right = text[lo:start], text[end:hi]
    # 只在结构化 JSON（"key": value）里收窄到当前字段。自由文本如
    # `Using device triplet: PK=..., DN=..., DS=...` 的三元组语境本来就跨好几个
    # 逗号片段，一刀切会把真实召回砍掉——所以按是否出现引号键名来区分。
    if field_scoped and _JSON_KEY_IN_TEXT_RE.search(text[lo:hi]):
        left = _FIELD_SEP_RE.split(left)[-1]
        right = _FIELD_SEP_RE.split(right)[0]
    # 用空格拼接左右两段，避免左段末尾与右段开头意外连成一个假词。
    piece = (left + " " + right).lower()
    for kw in keywords:
        # 短词（tel / to / id）用子串匹配会命中 hotel / into / device_id，
        # 这种假提权比漏报更难在报告里发现。开启 context_word 的规则改走词边界。
        if word_boundary and kw.isascii() and kw.isalpha():
            if re.search(rf"(?<![a-z0-9_]){re.escape(kw)}(?![a-z0-9_])", piece):
                return kw
        elif kw in piece:
            return kw
    return None


# ---------------------------------------------------------------- 数值字段反证
#
# 11 位 1 开头数字既是合法手机号段，也是一个普通整数（size / 字节数 / 计数器）。
# 手机号没有校验位，不像身份证(GB11643) 或银行卡(Luhn) 能靠数学区分——
# 语法层面永远分不开，只能靠字段语义反证。这里做成通用能力，纯数字规则都能挂。

_NUMERIC_FIELD_TERMS = frozenset({
    "size", "sizes", "byte", "bytes", "kb", "mb", "gb", "length", "len",
    "count", "cnt", "total", "sum", "ts", "timestamp", "time", "duration",
    "elapsed", "latency", "ms", "offset", "port", "seq", "index", "idx",
    "num", "number", "core", "breadth", "width", "height", "depth",
    "temperature", "temp", "limit", "capacity", "volume", "usage", "score",
    "price", "amount", "quantity", "qty", "version", "epoch", "uptime",
    "free", "used", "id", "uid", "pid", "tid", "start", "end", "status",
    "code", "max", "min", "block", "chunk", "rows", "cols",
})

_PHONE_HINT_RE = re.compile(
    r"phone|mobile|(?<![a-z])tel(?:ephone)?(?![a-z])|(?<![a-z])cell(?![a-z])"
    r"|msisdn|手机|电话|联系|联系方式|联系人|contact|caller|callee",
    re.I,
)

_FIELD_KEY_RE = re.compile(r"""["']?([A-Za-z_][\w.\-]{0,48})["']?\s*[:=]\s*$""")
# 裸数字反证只在 JSON 的 "key": 形式生效；logfmt 的 imsi=460... 不带引号也是真值。
_JSON_KEY_RE = re.compile(r"""["']?[A-Za-z_][\w.\-]{0,48}["']?\s*:\s*$""")
_NUMERIC_ZH_RE = re.compile(r"数|量|大小|字节|长度|计数|总数|时间|戳|尺寸|容量|耗时|毫秒")


def field_key(text: str, start: int, window: int = 64) -> str | None:
    """取命中值左侧最近的字段键名，JSON / logfmt / YAML 都认。

    只看同一行、最近一个分隔符之后的片段，避免前一个字段的键名串味。
    """
    line_start = text.rfind("\n", 0, start) + 1
    left = text[max(line_start, start - window):start]
    seg = re.split(r"[,;{}\[\]\n]", left)[-1]
    m = _FIELD_KEY_RE.search(seg)
    return m.group(1) if m else None


def numeric_field_hit(text: str, start: int, end: int, window: int = 96) -> bool:
    """判断这个数字是尺寸/计数/时间之类的数值字段，而非手机号。

    反证成立的条件（任一）：
    1. 键名带数值语义词：size / bytes / count / timestamp / core / temperature …
    2. 中文键名里的数值语义：用户数、字节数、耗时 …
    3. 值是 JSON 里的裸数字（"key": 139...，未加引号）——手机号几乎总是字符串。
    有 phone / 手机 / 联系 等正向字段名佐证时一律放行，优先保召回。
    """
    line_start = text.rfind("\n", 0, start) + 1
    left = text[max(line_start, start - window):start]
    seg = re.split(r"[,;{}\[\]\n]", left)[-1]
    if _PHONE_HINT_RE.search(seg):
        return False
    if _NUMERIC_ZH_RE.search(seg):
        return True

    key = field_key(text, start, window)
    if key:
        words = re.split(r"[_\-.]|(?<=[a-z0-9])(?=[A-Z])", key)
        if {w.lower() for w in words if w} & _NUMERIC_FIELD_TERMS:
            return True

    quoted = (start > 0 and end < len(text)
              and text[start - 1] in "\"'" and text[end] in "\"'")
    if not quoted and _JSON_KEY_RE.search(seg):
        return True
    return False


# ---------------------------------------------------------------- 位置换算


def build_line_index(text: str) -> list[int]:
    """每行起始 offset 列表，配合 offset_to_line 做 O(log n) 换算。"""
    idx = [0]
    pos = text.find("\n")
    while pos != -1:
        idx.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return idx


def offset_to_line(index: list[int], offset: int) -> tuple[int, int]:
    i = max(0, bisect_right(index, offset) - 1)
    return i + 1, offset - index[i] + 1


# ---------------------------------------------------------------- 归一化


def normalize_hexlike(v: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", v).lower()


def normalize_plain(v: str) -> str:
    return v.strip()


# ---------------------------------------------------------------- 脱敏（可选）


def redact(v: str, keep: int = 4) -> str:
    if len(v) <= keep * 2:
        return v[:2] + "***"
    return f"{v[:keep]}***{v[-keep:]}"


# ---------------------------------------------------------------- 裸 DER 密钥
#
# 嵌入式设备日志不会写 PEM 头：密钥分区被整块 base64 dump 出来，或直接以
# JSON 字段 "PrivateKey"/"PublicKey" 打印 ASN.1 DER 的 base64。
# 这类值靠 DER 结构的固定前缀识别，比"看起来像 base64"可靠得多。
# 前缀取自常见密钥编码：
#   PKCS#8 RSA / PKCS#1 RSA / PKCS#8 EC / SEC1 EC / PKCS#8 Ed25519
#   EC SubjectPublicKeyInfo (P-256) / RSA SPKI / Ed25519 SPKI

_DER_PRIVATE_PREFIXES = (
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",   # PKCS#8 RSA-2048
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC",
    "MIIEvwIBADANBgkqhkiG9w0BAQEFAASC",
    "MIIEowIBAAKCAQEA",                   # PKCS#1 RSA
    "MIIEpAIBAAKCAQEA",
    "MIIEogIBAAKCAQEA",
    "MIIBOgIBAAJBAK",                     # PKCS#1 RSA-512（测试/老设备常见）
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",  # PKCS#8 EC P-256
    "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwbwIBAQQg",
    "MHcCAQEEI",                          # SEC1 EC private key
    "MHQCAQEEI",
    "MC4CAQAwBQYDK2VwBCIEIA",             # PKCS#8 Ed25519
    "MFECAQEwBQYDK2VwBCIEIA",
)

_DER_PUBLIC_PREFIXES = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",  # EC P-256 SPKI
    "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",  # 同结构的短长度变体（实测设备日志）
    "MF4wEAYHKoZIzj0CAQYFK4EEACIDAAMAA",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",  # RSA SPKI
    "MCowBQYDK2VwAyEA",                     # Ed25519 SPKI
)


def der_key_kind(v: str) -> str | None:
    """判断是否是无 PEM 头的 ASN.1 DER 密钥（base64 编码）。

    返回 "private" / "public" / None。除了前缀，还要求：
    - 长度足够（短串只是普通 base64，不是密钥）；
    - base64 能解码，且首字节是 0x30（ASN.1 SEQUENCE），排除纯文本巧合。
    """
    import base64
    import binascii

    s = re.sub(r"\s+", "", v.strip().strip("\"'"))
    if len(s) < 24:
        return None
    kind = None
    for p in _DER_PRIVATE_PREFIXES:
        if s.startswith(p):
            kind = "private"
            break
    if kind is None:
        for p in _DER_PUBLIC_PREFIXES:
            if s.startswith(p):
                kind = "public"
                break
    if kind is None:
        return None
    try:
        # 先去掉原有 padding 再补齐：DER base64 常以 = 或 == 结尾，
        # 直接补会导致 "Invalid base64-encoded string" 而漏判。
        core = s.rstrip("=")
        der = base64.b64decode(core + "=" * (-len(core) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    if len(der) < 20 or der[0] != 0x30:
        return None
    return kind


def der_private_ok(v: str) -> bool:
    return der_key_kind(v) == "private"


def der_public_ok(v: str) -> bool:
    return der_key_kind(v) == "public"


def der_key_ok(v: str) -> bool:
    return der_key_kind(v) is not None


# ---------------------------------------------------------------- 文本读取

_TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "gb18030", "utf-16", "latin-1")


def read_text(path: Path) -> tuple[str, str]:
    """按优先级尝试常见编码，返回 (文本, 实际编码)。日志常是 GBK，必须回退。"""
    raw = path.read_bytes()
    for enc in _TEXT_ENCODINGS:
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1"


_BINARY_MAGIC = (
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"PK\x03\x04", b"\x1f\x8b",
    b"BZh", b"\xfd7zXZ", b"7z\xbc\xaf", b"\x7fELF", b"MZ", b"%PDF",
    b"\xd0\xcf\x11\xe0", b"SQLite format 3", b"\x00\x00\x00\x18ftyp",
    b"\xa1\xb2\xc3\xd4",  # pcap
    b"\xd4\xc3\xb2\xa1",  # pcap 小端
    b"\x0a\x0d\x0d\x0a",  # pcapng
)


def looks_binary(raw: bytes) -> bool:
    if raw[:16].startswith(_BINARY_MAGIC):
        return True
    head = raw[:8192]
    if not head:
        return False
    if b"\x00" in head:
        return True
    # 控制字符占比过高视为二进制
    ctrl = sum(1 for b in head if b < 9 or (13 < b < 32))
    return ctrl / len(head) > 0.10
