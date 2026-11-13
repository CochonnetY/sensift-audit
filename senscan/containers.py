"""容器扫描：APK / JAR / IPA / Office / 压缩包 / SQLite。

设计原则：容器只负责「把内容取出来」，判定一律复用 detect() 的规则集。
否则同一份凭据在 zip 内外会得出两种结论，审计时无法解释。

二进制条目（dex / so / arsc / Mach-O）走 strings 提取：DEX 的字符串池按
「长度前缀 + 内容」存储，可打印串天然连续，切出来的噪声远低于整段解码。
"""

from __future__ import annotations

import gzip
import io
import re
import sqlite3
import struct
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

MB = 1024 * 1024

MAX_DEPTH = 2                 # 嵌套压缩包最多拆两层，防递归炸弹
MAX_ENTRY_MB = 64             # 单条目上限
MAX_TOTAL_MB = 512            # 单容器解压总量上限
MAX_ENTRIES = 20000           # 条目数上限
MAX_RATIO = 200.0             # 压缩比上限（超过且体积不小则视为炸弹）
MAX_TEXT_CHARS = 8 * MB       # 单条目交给检测层的字符上限
STRINGS_MIN_LEN = 4

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
GZIP_MAGIC = b"\x1f\x8b"
SQLITE_MAGIC = b"SQLite format 3\x00"
DEX_MAGIC = b"dex\n"

KIND_LABEL = {
    "apk": "APK",
    "ipa": "IPA",
    "jar": "JAR",
    "office": "Office 文档",
    "zip": "压缩包",
    "tar": "tar 包",
    "gzip": "gzip",
    "sqlite": "SQLite 库",
}

# 直接按文本处理的扩展名（APK/IPA/JAR/ZIP 通用）
TEXT_EXTS = frozenset({
    "json", "json5", "txt", "xml", "yml", "yaml", "ini", "conf", "cfg", "config",
    "properties", "prop", "env", "js", "mjs", "cjs", "ts", "jsx", "tsx", "vue",
    "html", "htm", "css", "csv", "tsv", "sql", "md", "log", "pem", "key", "crt",
    "cer", "csr", "p12", "pfx", "sh", "bash", "zsh", "bat", "ps1", "py", "java",
    "kt", "gradle", "pro", "plist", "strings", "map", "toml", "lua", "rb", "php",
    "db", "sqlite", "sqlite3", "pb", "proto", "graphql", "lock", "sum",
    "mf",              # JAR 的 META-INF/MANIFEST.MF
})

# 二进制但值得抽字符串的扩展名
STRINGS_EXTS = frozenset({
    "dex", "so", "dylib", "class", "arsc", "a", "o", "bin", "dat", "pak", "bundle",
})


@dataclass(slots=True)
class Blob:
    """容器里取出的一段文本，label 为条目路径（如 assets/config.json）。

    binary=True 表示这段文本是从二进制里抽出来的（dex / so / class / arsc），
    每行是一条独立字符串、彼此没有语法关系——检测层据此关掉「键值跨行」的假设。
    """

    label: str
    kind: str
    text: str
    binary: bool = False
    low_signal: bool = False      # 翻译资源：值按定义是 UI 文案，不是凭据


@dataclass(slots=True)
class Budget:
    limit: int = MAX_TOTAL_MB * MB
    used: int = 0
    entries: int = 0
    truncated: bool = False

    def take(self, size: int) -> bool:
        if self.entries >= MAX_ENTRIES:
            self.truncated = True
            return False
        if self.used + size > self.limit:
            self.truncated = True
            return False
        self.used += size
        self.entries += 1
        return True


_PRINTABLE_RUN = re.compile(
    # 只收「确定是文字」的码位：ASCII 可见字符 + 拉丁扩展 + 中日韩 + 全角。
    # 早先的实现把 0x80 以上字节一律当可打印，UTF-8 解码后变成一片乱码，
    # 而乱码里恰好挤满 `=` `:` 和 `private key` 这类词，会把相邻两条无关字符串
    # 粘成一个「PrivateKey=xxxx」的假字段——APK 里的 CRITICAL 误报就是这么来的。
    r"[\x20-\x7e\u00a0-\u024f\u3000-\u303f\u3040-\u30ff\u3400-\u4dbf"
    r"\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]+"
)


def strings_of(raw: bytes, min_len: int = STRINGS_MIN_LEN) -> str:
    """从二进制里抽可打印串，一行一串，保证行号可定位。"""
    # errors="ignore"：非法 UTF-8 字节直接消失，成为天然分隔符，
    # 不会像 "replace" 那样留下 U+FFFD 把两侧字节流焊在一起。
    text = raw.decode("utf-8", errors="ignore")
    out: list[str] = []
    for m in _PRINTABLE_RUN.finditer(text):
        s = m.group(0)
        if len(s) >= min_len:
            out.append(s)
    return "\n".join(out)


def _uleb128(raw: bytes, i: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while i < len(raw):
        b = raw[i]
        i += 1
        val |= (b & 0x7F) << shift
        if b < 0x80:
            return val, i
        shift += 7
        if shift > 28:
            break
    raise ValueError("bad uleb128")


DEX_HEADER_SIZE = 0x70
DEX_MAX_STRINGS = 4_000_000
# 串表开头常有一批控制字符「字符串」（字符集表、混淆器产物）。
# 它们没有语义，留着只会撑大文本量，直接跳过。
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def dex_strings(raw: bytes) -> str | None:
    """按 DEX 字符串池结构取字符串；结构不成立返回 None（交回抽串兜底）。

    DEX 的串表是「uleb128 长度 + MUTF-8 内容 + \\0」密排，用通用 strings 抽取会
    把长度前缀（0x20-0x7f 里的小整数）粘到串首，例如 `&PrivateKey=...`。
    直接读 string_ids 偏移表，一条字符串一行，行号与串序号一一对应：
    既没有粘黏噪声，文本量也只有抽串的 1/3 左右。
    """
    if not raw.startswith(DEX_MAGIC) or len(raw) < DEX_HEADER_SIZE:
        return None
    try:
        size, off = struct.unpack_from("<II", raw, 56)   # string_ids_size / _off
    except struct.error:
        return None
    if not 0 < size <= DEX_MAX_STRINGS or off < DEX_HEADER_SIZE:
        return None
    if off + size * 4 > len(raw):
        return None

    out: list[str] = []
    for k in range(size):
        try:
            (soff,) = struct.unpack_from("<I", raw, off + k * 4)
        except struct.error:
            break
        if not 0 < soff < len(raw):
            continue
        try:
            _, pos = _uleb128(raw, soff)
        except ValueError:
            continue
        end = raw.find(b"\x00", pos)
        if end < 0:
            continue
        s = raw[pos:end].decode("utf-8", "ignore").strip()
        if s and not _CTRL_CHARS.search(s):
            out.append(s)
    return "\n".join(out) if out else None


def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gb18030", "utf-16"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("latin-1", errors="replace")


def is_container(head: bytes) -> str | None:
    """按魔数判断容器类型；zip 需要打开后再细分。"""
    if head.startswith(ZIP_MAGIC):
        return "zip"
    if head.startswith(GZIP_MAGIC):
        return "gzip"
    if head.startswith(SQLITE_MAGIC):
        return "sqlite"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    return None


# ---------------------------------------------------------------- zip 细分


def _zip_kind(names: list[str]) -> str:
    low = {n.lower() for n in names}
    if "androidmanifest.xml" in low and any(
        n.startswith("classes") and n.endswith(".dex") for n in low
    ):
        return "apk"
    if any(n.startswith("payload/") and ".app/" in n for n in low):
        return "ipa"
    if "meta-inf/manifest.mf" in low and any(n.endswith(".class") for n in low):
        return "jar"
    if (
        "word/document.xml" in low
        or "xl/workbook.xml" in low
        or "ppt/presentation.xml" in low
    ):
        return "office"
    return "zip"


_LOCALE_PARTS = ("/locale/", "/i18n/", "/l10n/", "/translations/")
_LOCALE_FILE = re.compile(
    r"(?i)^(?:i18n[_a-z]*|messages?[_a-z]*|strings?|translations?|localizations?)\."
    r"(?:json|xml|arb|ya?ml|properties)$"
)


def is_locale_blob(label: str) -> bool:
    """是否翻译资源条目。

    这类文件的值按定义是 UI 文案，但键名常含 `password` / `token` /
    `device_name`，键值规则会把整本词典报成凭据。实测一个 Flutter debug
    APK 里光 i18n_*.json 就贡献了 250+ 条误报，把 3 条真私钥完全淹没。
    这里只打标记，由 scanner 决定降权多少——不做整文件跳过，避免漏掉
    真有人把密钥塞进资源文件的场景。
    """
    low = label.lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    if base == "resources.arsc" or base.endswith(".arb"):
        return True
    if any(part in low for part in _LOCALE_PARTS):
        return True
    return bool(_LOCALE_FILE.match(base))


def _entry_mode(name: str, kind: str) -> str | None:
    """决定单个条目怎么处理：text / strings / auto / None（跳过）。"""
    low = name.lower()
    base = low.rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1] if "." in base else ""

    if kind == "office":
        # 只取内容 XML / 嵌入文本，样式与主题文件体积大且不可能藏凭据
        if low.endswith((".xml", ".txt", ".rels", ".vml")):
            return "text"
        return None

    if base in ("androidmanifest.xml", "resources.arsc"):
        return "strings"          # 二进制 XML / 资源表
    if ext == "dex":
        return "dex"              # 走字符串池解析，比抽串干净
    if ext in STRINGS_EXTS:
        return "strings"
    if ext in TEXT_EXTS:
        return "text"
    if kind == "ipa" and ext == "":
        return "strings"          # Mach-O 主二进制
    if ext == "" and ("assets/" in low or "res/raw/" in low or "meta-inf/" in low):
        return "auto"
    return None


def _blob_text(mode: str, raw: bytes) -> tuple[str, bool] | None:
    """返回 (文本, 是否来自二进制抽串)；无内容返回 None。"""
    if mode == "text":
        text = _decode(raw)
        return (text, False) if text.strip() else None
    if mode == "dex":
        # 结构解析失败（外加壳 / 被截断）时退回抽串，绝不因优化漏报
        text = dex_strings(raw) or strings_of(raw)
        return (text[:MAX_TEXT_CHARS], True) if text.strip() else None
    if mode == "strings":
        text = strings_of(raw)
        return (text, True) if text.strip() else None
    # auto：先按文本解，含 NUL 或控制字符占比高再退回 strings
    if b"\x00" not in raw[:8192]:
        text = _decode(raw)
        if text.strip():
            return (text, False)
    text = strings_of(raw)
    return (text, True) if text.strip() else None


def _walk_zip(zf: zipfile.ZipFile, kind: str, prefix: str, depth: int,
              budget: Budget) -> Iterator[Blob]:
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        if name.startswith("__MACOSX/"):
            continue
        label = prefix + name
        # 嵌套压缩包先于扩展名判断：zip 自身不在文本扩展名里，
        # 若先按 mode 过滤，打包进来的 zip 会被整包丢掉。
        if depth < MAX_DEPTH and info.file_size <= MAX_ENTRY_MB * MB:
            try:
                with zf.open(info) as fh:
                    magic = fh.read(4)
            except (RuntimeError, zipfile.BadZipFile, OSError):
                magic = b""
            if magic in ZIP_MAGIC:
                if not budget.take(info.file_size):
                    return
                try:
                    with zf.open(info) as fh:
                        raw = fh.read(MAX_ENTRY_MB * MB)
                    with zipfile.ZipFile(io.BytesIO(raw)) as inner:
                        inner_kind = _zip_kind(inner.namelist())
                        yield from _walk_zip(inner, inner_kind, f"{label}!/", depth + 1, budget)
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    pass
                continue

        mode = _entry_mode(name, kind)
        if mode is None:
            continue
        if info.file_size > MAX_ENTRY_MB * MB:
            budget.truncated = True
            continue
        # 压缩比异常 + 体积不小 → 视为 zip 炸弹，跳过该条目
        if (
            info.compress_size > 0
            and info.file_size > 8 * MB
            and info.file_size / info.compress_size > MAX_RATIO
        ):
            budget.truncated = True
            continue
        if not budget.take(info.file_size):
            return
        try:
            with zf.open(info) as fh:
                raw = fh.read(MAX_ENTRY_MB * MB)
        except (RuntimeError, zipfile.BadZipFile, OSError):
            continue          # 加密条目 / 损坏条目：跳过，不影响其余

        got = _blob_text(mode, raw)
        if got:
            text, binary = got
            yield Blob(label=label, kind=kind, text=text[:MAX_TEXT_CHARS], binary=binary)


def _iter_zip(path: Path, budget: Budget) -> Iterator[Blob]:
    with zipfile.ZipFile(path) as zf:
        kind = _zip_kind(zf.namelist())
        yield from _walk_zip(zf, kind, "", 0, budget)


def _iter_tar(path: Path, budget: Budget) -> Iterator[Blob]:
    with tarfile.open(path, "r:*") as tf:
        for member in tf:
            if not member.isfile():
                continue
            label = member.name
            mode = _entry_mode(label, "tar")
            if mode is None:
                continue
            if member.size > MAX_ENTRY_MB * MB or not budget.take(member.size):
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            raw = fh.read(MAX_ENTRY_MB * MB)
            got = _blob_text(mode, raw)
            if got:
                text, binary = got
                yield Blob(label=label, kind="tar", text=text[:MAX_TEXT_CHARS], binary=binary)


def _iter_gzip(path: Path, budget: Budget) -> Iterator[Blob]:
    with gzip.open(path, "rb") as fh:
        raw = fh.read(MAX_ENTRY_MB * MB)
    if not budget.take(len(raw)):
        return
    label = path.name[:-3] if path.name.lower().endswith(".gz") else path.name

    # .tar.gz：解出来的就是 tar 流，按包内条目逐个扫，别当成一坨文本
    if len(raw) > 262 and raw[257:262] == b"ustar":
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
                for member in tf:
                    if not member.isfile():
                        continue
                    mode = _entry_mode(member.name, "tar")
                    if mode is None or member.size > MAX_ENTRY_MB * MB:
                        continue
                    if not budget.take(member.size):
                        return
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    got = _blob_text(mode, fh.read(MAX_ENTRY_MB * MB))
                    if got:
                        text, binary = got
                        yield Blob(label=member.name, kind="tar",
                                   text=text[:MAX_TEXT_CHARS], binary=binary)
            return
        except tarfile.TarError:
            pass

    got = _blob_text("auto", raw)
    if got:
        text, binary = got
        yield Blob(label=label, kind="gzip", text=text[:MAX_TEXT_CHARS], binary=binary)


def _iter_sqlite(path: Path, budget: Budget) -> Iterator[Blob]:
    """按表取值，逐列输出 `表.列=值`。

    直接抽串会把相邻记录粘成一串（SQLite 记录体按列密排，列间无分隔符），
    实测 `13912345678` 会紧贴下一个 `sk_live_…`，导致两边都识别不出。
    走 sqlite3 只读打开还能顺带恢复列名，给上下文判定提供依据。
    """
    rows = _sqlite_rows(path)
    if rows is not None:
        if rows:
            yield Blob(label=path.name, kind="sqlite", text=rows[:MAX_TEXT_CHARS])
        return

    # 打不开（加密 / 损坏 / 非标准页）时退回抽串，至少不漏掉明文
    size = path.stat().st_size
    if not budget.take(min(size, MAX_ENTRY_MB * MB)):
        return
    with path.open("rb") as fh:
        raw = fh.read(MAX_ENTRY_MB * MB)
    text = strings_of(raw, min_len=6)
    if text:
        yield Blob(label=path.name, kind="sqlite", text=text[:MAX_TEXT_CHARS], binary=True)


SQLITE_MAX_ROWS = 5000       # 单表取样行数
SQLITE_MAX_TABLES = 200


def _sqlite_rows(path: Path) -> str | None:
    """只读打开并导出单元格；返回 None 表示打不开（交回抽串兜底）。"""
    try:
        uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=2.0)
    except sqlite3.Error:
        return None

    out: list[str] = []
    size = 0
    try:
        con.text_factory = bytes          # 保留原始字节，自行按 UTF-8 解码
        tables = con.execute(
            "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
        ).fetchmany(SQLITE_MAX_TABLES)
        for (raw_name,) in tables:
            name = raw_name.decode("utf-8", "replace") if isinstance(raw_name, bytes) else str(raw_name)
            quoted = '"' + name.replace('"', '""') + '"'
            try:
                cur = con.execute(f"select * from {quoted} limit {SQLITE_MAX_ROWS}")
            except sqlite3.Error:
                continue
            cols = [d[0] for d in (cur.description or ())]
            for row in cur:
                for col, val in zip(cols, row):
                    cell = _cell_text(val)
                    if cell is None:
                        continue
                    line = f"{name}.{col}={cell}"
                    out.append(line)
                    size += len(line) + 1
                    if size >= MAX_TEXT_CHARS:
                        return "\n".join(out)
    except sqlite3.Error:
        return None
    finally:
        con.close()
    return "\n".join(out)


def _cell_text(val: object) -> str | None:
    if val is None:
        return None
    if isinstance(val, bytes):
        text = val.decode("utf-8", "replace")
    else:
        text = str(val)
    if not text.strip():
        return None
    return text[:2048]


def iter_blobs(path: Path, kind: str, budget: Budget | None = None) -> Iterator[Blob]:
    """按容器类型产出文本条目。调用方负责捕获解析异常。

    budget 可外部传入：调用方据此判断「是没东西可扫」还是「预算用尽被截断」，
    这两种情况下扫描结果都是空的，但处置建议完全不同。
    """
    budget = budget or Budget()
    if kind == "zip":
        gen = _iter_zip(path, budget)
    elif kind == "tar":
        gen = _iter_tar(path, budget)
    elif kind == "gzip":
        gen = _iter_gzip(path, budget)
    elif kind == "sqlite":
        gen = _iter_sqlite(path, budget)
    else:
        gen = iter(())
    for blob in gen:
        blob.low_signal = is_locale_blob(blob.label)
        yield blob
