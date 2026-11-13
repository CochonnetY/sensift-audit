"""扫描编排：目录遍历、二进制跳过、编码回退、大文件分块、白名单过滤。"""

from __future__ import annotations

import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import containers
from . import detectors
from . import pcap as pcapmod
from . import utils as U
from . import verify as VER
from .models import Finding
from .verify import VerifyConfig
from .whitelist import Whitelist

DEFAULT_MAX_FILE_MB = 512
CHUNK_CHARS = 8 * 1024 * 1024
OVERLAP_LINES = 20
OVERLAP_CHARS = 8192

# 翻译资源条目（i18n_*.json / resources.arsc / *.arb）的值按定义是 UI 文案。
# 不整文件跳过，只把置信度门槛抬高：0.62~0.70 的「词典条目」被压掉，
# 0.90 的真私钥仍会保留。0.25 是实测值，能覆盖这批噪声的最大置信度。
LOCALE_PENALTY = 0.25


class ScanCancelled(RuntimeError):
    """用户主动中止扫描（由进度回调返回 False 触发）。"""


# (已完成数, 总数, 当前文件) -> 返回 False 立即中止
ProgressCallback = Callable[[int, int, Path], bool | None]


@dataclass(slots=True)
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_read: int = 0
    candidates: int = 0
    rejected: int = 0
    suppressed: int = 0
    suppressed_context: int = 0     # 因缺少上下文关键词被压制
    suppressed_threshold: int = 0   # 因置信度低于阈值被压制
    whitelisted: int = 0
    container_entries: int = 0
    locale_entries: int = 0        # 按翻译资源降权处理的条目数
    container_truncated: bool = False   # 解包预算/条目数用尽，容器只扫了一部分
    skipped: list[str] = field(default_factory=list)

    def absorb(self, sub: dict) -> None:
        """把单文件/单数据源的子统计并进总量。"""
        self.candidates += sub.get("candidates", 0)
        self.rejected += sub.get("rejected", 0)
        self.suppressed += sub.get("suppressed", 0)
        self.suppressed_context += sub.get("suppressed_context", 0)
        self.suppressed_threshold += sub.get("suppressed_threshold", 0)


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    stats: ScanStats
    targets: list[str]
    started_at: str
    duration_ms: int
    min_confidence: float
    whitelist_size: int = 0
    verification: dict = field(default_factory=dict)

    @property
    def by_entity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.entity] = out.get(f.entity, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    @property
    def by_risk(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.risk.value] += 1
        return out

    @property
    def by_category(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    @property
    def by_priority(self) -> dict[str, int]:
        out = {"P0": 0, "P1": 0, "P2": 0}
        for f in self.findings:
            out[f.priority] += 1
        return out

    @property
    def by_validation(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.validation] = out.get(f.validation, 0) + 1
        return out

    @property
    def by_liveness(self) -> dict[str, int]:
        # 存活状态分布：未启用验证时全部落在 unknown
        return VER.by_liveness(self.findings)

    @property
    def iot_triplet_files(self) -> list[str]:
        """PK/DN/DS 三类齐备的来源文件：设备身份可被完整仿冒，结论比单条密钥更严重。"""
        return sorted({f.source for f in self.findings if f.extra.get("iot_triplet")})

    @property
    def by_file(self) -> list[tuple[str, int, str, int]]:
        """(文件, 命中数, 最高风险, 最高风险分)，按命中数降序。"""
        agg: dict[str, list] = {}
        for f in self.findings:
            row = agg.setdefault(f.source, [0, f.risk, f.risk_score])
            row[0] += 1
            if f.risk.order < row[1].order:
                row[1] = f.risk
            if f.risk_score > row[2]:
                row[2] = f.risk_score
        rows = [(k, v[0], v[1].value, v[2]) for k, v in agg.items()]
        rows.sort(key=lambda r: (-r[1], r[2]))
        return rows

    @property
    def spread_values(self) -> list[tuple[str, str, list[str]]]:
        """同一实体同一值出现在多个文件 = 泄露面已扩散，处置优先级要上调。"""
        agg: dict[tuple[str, str], list[str]] = {}
        for f in self.findings:
            agg.setdefault((f.entity, f.value), []).append(f.source)
        out = [(e, v, srcs) for (e, v), srcs in agg.items() if len(set(srcs)) > 1]
        out.sort(key=lambda r: -len(set(r[2])))
        return out


_IOT_TRIPLET_ENTITIES = frozenset({
    "IOT_PRODUCT_KEY", "IOT_DEVICE_NAME", "IOT_DEVICE_SECRET",
})


def _mark_iot_triplets(findings: list[Finding]) -> None:
    """同一来源同时出现 PK / DN / DS 时，把结论从「泄露了一条密钥」升级为
    「设备身份可被完整仿冒」。

    IoT 平台的一机一密认证只要三元组齐备，攻击者就能以该设备身份连上 MQTT、
    订阅下行指令、伪造上行数据、触发 OTA。此时只删日志没有意义，必须作废凭据。
    这个结论对合规评审比单条命中更重要，所以写进 reasons / remediation / extra，
    让四种报告都能带出去。
    """
    by_src: dict[str, set[str]] = {}
    for f in findings:
        if f.entity in _IOT_TRIPLET_ENTITIES:
            # 容器内条目按外层文件归组：三元组分散在同一个 apk 的两个 json 里，
            # 依然等价于设备身份可被完整仿冒。
            by_src.setdefault(str(f.extra.get("container_file") or f.source), set()).add(f.entity)
    complete = {src for src, ents in by_src.items() if ents == _IOT_TRIPLET_ENTITIES}
    if not complete:
        return
    for f in findings:
        src = str(f.extra.get("container_file") or f.source)
        if src not in complete or f.entity not in _IOT_TRIPLET_ENTITIES:
            continue
        f.extra["iot_triplet"] = True
        f.reasons = f.reasons + (
            "同一来源 PK/DN/DS 三类齐备：设备身份可被完整仿冒，不只是单条密钥泄露",
        )
        if f.entity == "IOT_DEVICE_SECRET":
            f.remediation = (
                "【三元组齐备·最高优先级】立即在 IoT 平台停用并轮换该 DeviceSecret，"
                "排查该设备近期的 MQTT 会话、设备影子与 OTA 升级记录；"
                "单纯删除日志不足以处置，必须作废凭据本身"
            )


def iter_targets(paths: list[Path] | list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        # 公开 API 允许直接传字符串路径，内部一律统一成 Path
        p = Path(raw).expanduser()
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(sorted(x for x in p.rglob("*") if x.is_file()))
        else:
            raise FileNotFoundError(f"路径不存在: {p}")
    return out


def _detect_encoding(head: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gb18030", "utf-16", "latin-1"):
        try:
            head.decode(enc)
            return enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return "latin-1"


def _scan_large(path: Path, source: str, min_confidence: float, stats: ScanStats) -> list[Finding]:
    """超大文件按行切块流式处理，块边界落在行首，并保留尾部重叠区。

    PEM 私钥、JSON 字段值等规则会跨多行；若块间零重叠，恰好被切开的命中
    会整条丢失。这里让相邻块共享末尾若干行，并用 (规则, 值, 行, 偏移) 去重，
    保证重叠区在两次检测中算出完全一致的位置。
    """
    with path.open("rb") as fh:
        raw_head = fh.read(65536)
    enc = _detect_encoding(raw_head)
    findings: list[Finding] = []
    seen: set[tuple[str, str, int, int]] = set()
    carry: list[str] = []
    line_offset = 0
    base_offset = 0
    buf: list[str] = []
    size = 0
    sub: dict = {}

    def flush(buf: list[str], line_offset: int, base_offset: int, carry: list[str]) -> None:
        prefix = "".join(carry)
        chunk = prefix + "".join(buf)
        if not chunk:
            return
        carry_lines = prefix.count("\n")
        got = detectors.detect(chunk, source, min_confidence, sub,
                               line_offset=line_offset - carry_lines)
        for f in got:
            f.offset += base_offset - len(prefix)
            key = (f.rule_id, f.normalized or f.value, f.line, f.offset)
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)

    def next_carry(buf: list[str]) -> list[str]:
        out: list[str] = []
        used = 0
        for line in reversed(buf):
            if used + len(line) > OVERLAP_CHARS or len(out) >= OVERLAP_LINES:
                break
            out.append(line)
            used += len(line)
        return list(reversed(out))

    with path.open("r", encoding=enc, errors="replace", newline="") as fh:
        for line in fh:
            buf.append(line)
            size += len(line)
            if size >= CHUNK_CHARS:
                chunk_text = "".join(buf)
                flush(buf, line_offset, base_offset, carry)
                carry = next_carry(buf)
                line_offset += chunk_text.count("\n")
                base_offset += len(chunk_text)
                buf, size = [], 0
        flush(buf, line_offset, base_offset, carry)

    stats.absorb(sub)
    return findings


def _apply_whitelist(found: list[Finding], whitelist: Whitelist | None, stats: ScanStats) -> list[Finding]:
    if whitelist is None or not len(whitelist):
        return found
    kept: list[Finding] = []
    for f in found:
        if whitelist.matches(f):
            stats.whitelisted += 1
        else:
            kept.append(f)
    return kept


def scan(
    paths: list[Path] | list[str],
    whitelist: Whitelist | None = None,
    min_confidence: float = 0.55,
    include_binary: bool = False,
    max_file_mb: int = DEFAULT_MAX_FILE_MB,
    enable_pcap: bool = True,
    enable_container: bool = True,
    verify_config: VerifyConfig | None = None,
    on_progress: ProgressCallback | None = None,
) -> ScanResult:
    """遍历目标并执行检测。

    on_progress 在每处理一个文件前调用，供 UI 显示真实进度；返回 False 则
    抛出 ScanCancelled，实现协作式中止（无需强杀线程）。CLI 不传此参数。
    """
    t0 = time.perf_counter()
    started_at = datetime.now().isoformat(timespec="seconds")
    stats = ScanStats()
    targets = iter_targets(paths)
    all_findings: list[Finding] = []
    max_bytes = max_file_mb * 1024 * 1024
    total_files = len(targets)

    for idx, path in enumerate(targets, 1):
        if on_progress is not None and on_progress(idx, total_files, path) is False:
            raise ScanCancelled("扫描已停止")
        try:
            size = path.stat().st_size
        except OSError:
            stats.files_skipped += 1
            stats.skipped.append(f"{path} (stat 失败)")
            continue

        if size == 0:
            stats.files_skipped += 1
            continue

        with path.open("rb") as fh:
            head = fh.read(8192)

        source = str(path.resolve())

        # pcap 走 tshark 抽载荷的专用通道（旁路/取证流量）
        if pcapmod.is_pcap(head):
            if not enable_pcap:
                stats.files_skipped += 1
                stats.skipped.append(f"{path} (pcap，已用 --no-pcap 禁用)")
                continue
            if pcapmod.tshark_path() is None:
                stats.files_skipped += 1
                stats.skipped.append(f"{path} (pcap，未安装 tshark)")
                continue
            stats.files_scanned += 1
            stats.bytes_read += size
            sub: dict = {}
            try:
                found = pcapmod.scan_pcap(path, min_confidence, sub)
            except (RuntimeError, OSError) as exc:
                stats.files_skipped += 1
                stats.skipped.append(f"{path} (pcap 解析失败: {exc})")
                continue
            stats.absorb(sub)
            all_findings.extend(_apply_whitelist(found, whitelist, stats))
            continue

        # 容器走解包通道：APK / JAR / IPA / Office / 压缩包 / SQLite
        kind = containers.is_container(head)
        if kind is not None:
            if not enable_container:
                stats.files_skipped += 1
                stats.skipped.append(f"{path} ({kind}，已用 --no-container 禁用)")
                continue
            stats.files_scanned += 1
            stats.bytes_read += size
            found_any = False
            budget = containers.Budget()
            try:
                for blob in containers.iter_blobs(path, kind, budget):
                    found_any = True
                    stats.container_entries += 1
                    sub = {}
                    # 单文件容器（sqlite / 纯 gz）条目名与文件名相同，不重复拼一次
                    label = "" if blob.label == path.name else blob.label
                    src = f"{source}!{label}" if label else source
                    threshold = min_confidence
                    if blob.low_signal:
                        stats.locale_entries += 1
                        threshold += LOCALE_PENALTY
                    got = detectors.detect(blob.text, src, threshold, sub,
                                           strings_dump=blob.binary)
                    for f in got:
                        f.extra.setdefault("container", blob.kind)
                        f.extra.setdefault("container_file", source)
                        if label:
                            f.extra.setdefault("entry", label)
                    stats.absorb(sub)
                    all_findings.extend(_apply_whitelist(got, whitelist, stats))
            except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, RuntimeError) as exc:
                stats.files_skipped += 1
                stats.skipped.append(f"{path} ({kind} 解析失败: {exc})")
            if budget.truncated:
                stats.container_truncated = True
                stats.skipped.append(
                    f"{path} ({kind} 解包预算用尽：已扫 {budget.entries} 条目 / "
                    f"{budget.used // (1024 * 1024)}MB，其余条目未扫描)"
                )
            if not found_any:
                stats.skipped.append(
                    f"{path} ({kind} 内没有可扫的文本条目："
                    f"{budget.entries} 条目均非文本/未通过体积上限)"
                )
            continue

        if not include_binary and U.looks_binary(head):
            stats.files_skipped += 1
            stats.skipped.append(f"{path} (二进制，已跳过)")
            continue

        stats.files_scanned += 1
        stats.bytes_read += size

        if size > max_bytes:
            found = _scan_large(path, source, min_confidence, stats)
        else:
            try:
                text, _enc = U.read_text(path)
            except OSError as exc:
                stats.files_skipped += 1
                stats.skipped.append(f"{path} ({exc})")
                continue
            sub = {}
            found = detectors.detect(text, source, min_confidence, sub)
            stats.absorb(sub)

        all_findings.extend(_apply_whitelist(found, whitelist, stats))

    # 同一文件内合并重复值；跨文件保留独立记录（审计需定位到具体文件）
    merged: dict[str, Finding] = {}
    for f in all_findings:
        key = f"{f.dedup_key}|{f.source}"
        prev = merged.get(key)
        if prev is None:
            merged[key] = f
        else:
            prev.occurrences += f.occurrences
            if f.confidence > prev.confidence:
                prev.confidence = f.confidence

    findings = sorted(merged.values(), key=lambda x: (-x.risk_score, -x.confidence, x.source, x.line))
    _mark_iot_triplets(findings)
    result = ScanResult(
        findings=findings,
        stats=stats,
        targets=[str(p) for p in paths],
        started_at=started_at,
        duration_ms=int((time.perf_counter() - t0) * 1000),
        min_confidence=min_confidence,
        whitelist_size=len(whitelist) if whitelist else 0,
    )
    if verify_config is not None:
        summary = VER.run(findings, verify_config)
        result.verification = summary.to_dict()
        # 在线确认"仍有效"会提升为 P0，重排让明细顺序与处置顺序一致
        findings.sort(key=lambda x: (
            {"P0": 0, "P1": 1, "P2": 2}[x.priority], x.risk.order,
            -x.confidence, x.source, x.line,
        ))
        result.findings = findings
    return result
