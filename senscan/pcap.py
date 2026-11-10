"""pcap / pcapng 接入：调用 tshark 抽取可读载荷，再走统一的检测引擎。

定位说明：旁路镜像只能提供元数据（SNI / DNS / 证书）与**明文**载荷。
TLS 正文字段在 pcap 里就是密文，解码后控制字符占比极高，会被本模块丢弃——
这不是实现缺陷，是协议本身的边界。
"""

from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
from pathlib import Path

from . import detectors
from .models import Finding

_FIELDS = (
    "frame.number",
    "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport",
    "http.request.method", "http.request.full_uri",
    "http.host", "http.user_agent", "http.cookie", "http.authorization",
    "http.file_data", "http.content_type",
    "tls.handshake.extensions_server_name",
    "dns.qry.name",
    "ftp.request.arg", "telnet.data",
    "tcp.payload",
)

_PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",  # 纳秒精度
    b"\x0a\x0d\x0d\x0a",                       # pcapng
)

# _FIELDS 中的 hex 字段下标（parts 索引）：http.file_data=11, tcp.payload=17
_HEX_FIELD_IDX = {11, 17}

DEFAULT_TIMEOUT = 900


def is_pcap(head: bytes) -> bool:
    return head[:4] in _PCAP_MAGICS


def tshark_path() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    for cand in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
    ):
        if Path(cand).exists():
            return cand
    return None


def _hex_to_text(hexstr: str) -> str:
    """把 tshark 输出的 hex 载荷还原为文本；密文与二进制会被判定为空。"""
    if not hexstr:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", hexstr)
    if len(cleaned) < 8 or len(cleaned) % 2:
        return ""
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return ""

    text: str | None = None
    for enc in ("utf-8", "gb18030"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return ""

    bad = sum(1 for ch in text if ord(ch) < 9 or 13 < ord(ch) < 32)
    if not text or bad / len(text) > 0.10:
        return ""  # 密文/二进制
    return text


def _frame_text(parts: list[str]) -> tuple[int, str]:
    """把一帧的字段拼成可扫描的一行文本，返回 (帧号, 文本)。"""
    frame = int(parts[0]) if parts[0].isdigit() else 0
    uniq: list[str] = []
    seen: set[str] = set()

    for idx, cell in enumerate(parts[1:], start=1):
        if not cell:
            continue
        # http.file_data / tcp.payload 是 hex，必须解码后再扫，
        # 否则 15 位纯数字的 hex 片段会被误判成 IMEI 之类
        if idx in _HEX_FIELD_IDX:
            text = _hex_to_text(cell)
            if text and text not in seen:
                seen.add(text)
                uniq.append(text)
            continue
        for piece in cell.split(","):
            piece = piece.strip()
            if not piece or piece in seen:
                continue
            seen.add(piece)
            uniq.append(piece)
    return frame, " ".join(uniq)


def iter_frames(path: Path, timeout: int = DEFAULT_TIMEOUT):
    exe = tshark_path()
    if exe is None:
        raise RuntimeError("未找到 tshark，请先安装 Wireshark 或 tshark")

    cmd = [exe, "-r", str(path), "-T", "fields", "-E", "separator=\t", "-E", "quote=d"]
    for f in _FIELDS:
        cmd += ["-e", f]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    completed = False
    try:
        for line in proc.stdout:
            parts = line.rstrip("\n").rstrip("\r").split("\t")
            if not parts or not parts[0]:
                continue
            parts = [p.strip('"') for p in parts]
            frame, text = _frame_text(parts)
            if frame and text:
                yield frame, text
        completed = True
    finally:
        # 先关 stdout 让 tshark 感知管道断开，避免 stderr 缓冲写满造成 wait 死锁
        proc.stdout.close()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1)
        err = ""
        if proc.stderr is not None:
            try:
                err = proc.stderr.read(2048)
            except (OSError, ValueError):
                pass
            proc.stderr.close()
        # 正常读完但 tshark 非零退出 = 文件损坏/字段不支持，必须显式报错，
        # 否则会静默返回空帧，让损坏的 pcap 看起来像"没有敏感数据"。
        if completed and proc.returncode not in (0, None):
            raise RuntimeError(
                f"tshark 解析失败（exit {proc.returncode}）：{(err or '').strip()[:300] or '无错误输出'}"
            )


def scan_pcap(path: Path, min_confidence: float, stats: dict) -> list[Finding]:
    findings: list[Finding] = []
    # contextlib.closing 保证提前退出时 tshark 管道也被关闭
    with contextlib.closing(iter_frames(path)) as frames:
        for frame, text in frames:
            got = detectors.detect(text, str(path.resolve()), min_confidence, stats)
            for f in got:
                f.line = frame          # pcap 场景下"行号"即帧号
                f.column = 1
                f.extra["frame"] = frame
            findings.extend(got)
    return findings
