"""命令行入口：senscan PATH... [选项]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report
from .models import Risk
from .scanner import scan
from .version import __version__
from .verify import VerifyConfig, VerifyPolicyError
from .whitelist import Whitelist

_FORMATS = ("json", "csv", "sarif", "html")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="senscan",
        description="敏感实体审计：从日志、配置、抓包中提取凭据与设备标识，输出可评审报告。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  senscan ./logs\n"
            "  senscan app.log dump.json -o out -w wl.txt\n"
            "  senscan ./firmware-out -m 0.7 --fail-on critical\n"
            "  senscan ./logs --verify-local\n"
            "  senscan ui --port 8777\n"
        ),
    )
    p.add_argument("paths", nargs="+", help="文件或目录，目录递归")
    p.add_argument("-o", "--outdir", default="senscan-reports", help="输出目录（默认 senscan-reports）")
    p.add_argument("-f", "--format", default="json,csv,sarif,html", help="格式，逗号分隔：json,csv,sarif,html")
    p.add_argument("-w", "--whitelist", help="白名单文件")
    p.add_argument("-m", "--min-confidence", type=float, default=0.55, help="置信度阈值（默认 0.55）")
    p.add_argument("--include-binary", action="store_true", help="扫描二进制（误报会增多）")
    p.add_argument("--no-pcap", action="store_true", help="不解析抓包（默认用 tshark 抽明文）")
    p.add_argument("--no-container", action="store_true",
                   help="不拆容器（默认扫 APK/JAR/IPA/Office/zip/tar/gz/SQLite）")
    p.add_argument("--verify-local", action="store_true", help="离线验证：有效期 / 结构 / 过期，不联网")
    p.add_argument("--verify-online", action="store_true", help="在线验证，需授权端点")
    p.add_argument("--verify-config", help="验证配置 JSON")
    p.add_argument("--verify-endpoints", default="", help="只读端点 ID，逗号分隔")
    p.add_argument("--allow-public-endpoints", action="store_true", help="授权向公网只读端点发凭据")
    p.add_argument("--verify-audit", help="审计日志路径")
    p.add_argument("--max-file-mb", type=int, default=512, help="大文件分块阈值 MB（默认 512）")
    p.add_argument("--redact", action="store_true", help="报告脱敏（默认明文，便于核对）")
    p.add_argument("--fail-on", default="high", choices=("critical", "high", "medium", "low", "none"),
                   help="达到该等级返回退出码 2（CI 用，默认 high）")
    p.add_argument("--top", type=int, default=20, help="控制台条数（默认 20）")
    p.add_argument("--no-report", action="store_true", help="只打印摘要，不写文件")
    p.add_argument("-q", "--quiet", action="store_true", help="只输出一行摘要")
    p.add_argument("-V", "--version", action="version", version=f"senscan {__version__}")
    return p


def _print_diagnostics(result) -> None:
    """零命中时给出「为什么」，别让用户对着 0 猜。

    最常见的三种 0 命中：路径根本不存在（已在扫描前抛错）、文件被判为二进制
    跳过、容器里没有可扫文本条目。以前这些原因只写进 stats.skipped，界面上
    什么都看不到，看起来就像「扫描器坏了」。
    """
    stats = result.stats
    skipped = stats.skipped
    if result.findings and not skipped:
        return
    if skipped:
        print()
        print(f"⚠ 跳过 {len(skipped)} 项（前 {min(6, len(skipped))} 条）：")
        for line in skipped[:6]:
            print(f"    · {line}")
        if stats.container_truncated:
            print("    · 提示：容器解包预算用尽，可拆出目标目录后再单独扫描")
    if not result.findings:
        print()
        if stats.files_scanned == 0:
            print("结果为空：没有任何文件被实际扫描（原因见上）。")
        else:
            print(f"结果为空：已扫 {stats.files_scanned} 文件 / {stats.container_entries} 条目，"
                  "未发现达到阈值的实体；可降低 -m 阈值或用 --include-binary 复核。")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "ui":
        from .webui import main as ui_main
        return ui_main(raw_argv[1:])
    args = build_parser().parse_args(raw_argv)

    formats = tuple(x.strip().lower() for x in args.format.split(",") if x.strip())
    bad = [f for f in formats if f not in _FORMATS]
    if bad:
        print(f"错误：未知报告格式 {bad}，可选 {list(_FORMATS)}", file=sys.stderr)
        return 1

    whitelist = None
    if args.whitelist:
        try:
            whitelist = Whitelist.from_file(Path(args.whitelist))
        except FileNotFoundError as exc:
            print(f"错误：{exc}", file=sys.stderr)
            return 1

    verify_config = None
    if args.verify_local or args.verify_online or args.verify_config:
        data: dict = {}
        if args.verify_config:
            try:
                data = json.loads(Path(args.verify_config).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"错误：验证配置读取失败 {exc}", file=sys.stderr)
                return 1
        data["local"] = bool(args.verify_local or args.verify_online or data.get("local"))
        data["online"] = bool(args.verify_online or data.get("online"))
        if args.verify_endpoints:
            data["endpoint_ids"] = [x.strip() for x in args.verify_endpoints.split(",") if x.strip()]
        if args.allow_public_endpoints:
            data["allow_public"] = True
        if args.verify_audit:
            data["audit_path"] = args.verify_audit
        verify_config = VerifyConfig.from_dict(data)
        try:
            verify_config.validate()
        except VerifyPolicyError as exc:
            print(f"错误：{exc}", file=sys.stderr)
            return 1
        if verify_config.online:
            print(
                "⚠ 凭据将发往已授权只读端点，请确认已获授权；审计只记 hash，不记原值。",
                file=sys.stderr,
            )

    try:
        result = scan(
            [Path(x) for x in args.paths],
            whitelist=whitelist,
            min_confidence=args.min_confidence,
            include_binary=args.include_binary,
            max_file_mb=args.max_file_mb,
            enable_pcap=not args.no_pcap,
            enable_container=not args.no_container,
            verify_config=verify_config,
        )
    except FileNotFoundError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    if args.quiet:
        print(f"{len(result.findings)} findings, {result.stats.files_scanned} files, {result.duration_ms} ms")
    else:
        print(report.render_console(result, top=args.top, redact=args.redact))
        _print_diagnostics(result)

    if not args.no_report:
        try:
            written = report.write_all(result, Path(args.outdir), formats, redact=args.redact)
        except OSError as exc:
            print(f"错误：报告写入失败 {exc}", file=sys.stderr)
            return 1
        if not args.quiet:
            print()
            for p in written:
                print(f"  → {p}")

    if args.fail_on == "none":
        return 0
    threshold = Risk(args.fail_on)
    triggered = any(f.risk.order <= threshold.order for f in result.findings)
    return 2 if triggered else 0


if __name__ == "__main__":
    raise SystemExit(main())
