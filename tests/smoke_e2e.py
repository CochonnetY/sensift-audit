"""端到端冒烟：逐项验证容器 / 报告 / 开关 / 验证器 / Web UI。

不是单元测试，走的是真实 CLI 与真实文件；跑完输出一张通过表。

    python tests/smoke_e2e.py

工作台那 3 项需要先在另一个终端启动服务：
    python -m senscan ui --port 8791

脚本只用自己造的假凭据，不联网、不向公网发送任何值。
"""
from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from senscan import containers
from senscan.scanner import scan

ROOT = Path.cwd()
TMP = Path(tempfile.mkdtemp(prefix="senscan-smoke-"))
SECRET = ("sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc")
PW = "P@ssw0rd!2026"
ROWS: list[tuple[str, str, bool, str]] = []


def rec(group: str, name: str, ok: bool, note: str = "") -> None:
    ROWS.append((group, name, bool(ok), note))


def cli(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "senscan", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )


def hit(r, needle: str) -> bool:
    return any(needle in f.value for f in r.findings)


# --------------------------------------------------------------- 容器
def zip_samples() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner.txt", f"api_key={SECRET}\n")
    p = TMP / "nested.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("outer.txt", f"password={PW}\n")
        z.writestr("inner.zip", inner.getvalue())
    r = scan([p])
    rec("容器", "zip + 嵌套 zip", hit(r, SECRET) and hit(r, PW),
        f"{len(r.findings)} 命中 / {r.stats.container_entries} 条目")

    p = TMP / "sample.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        data = f"api_key={SECRET}\n".encode()
        ti = tarfile.TarInfo("cfg/app.txt")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    r = scan([p])
    rec("容器", "tar.gz", hit(r, SECRET), f"{len(r.findings)} 命中")

    p = TMP / "sample.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE cfg (k TEXT, v TEXT)")
    con.execute("INSERT INTO cfg VALUES (?, ?)", ("api_key", SECRET))
    con.commit()
    con.close()
    r = scan([p])
    rec("容器", "SQLite 逐列", hit(r, SECRET), f"{len(r.findings)} 命中")

    p = TMP / "sample.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", f"<w:document><w:t>api_key={SECRET}</w:t></w:document>")
    r = scan([p])
    rec("容器", "Office docx", hit(r, SECRET), f"{len(r.findings)} 命中")

    p = TMP / "sample.jar"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\nX-Note: api_key={SECRET}\n")
        z.writestr("a/B.class", b"\xca\xfe\xba\xbe" + b"\x00" * 32)
    r = scan([p])
    rec("容器", "JAR", hit(r, SECRET), f"{len(r.findings)} 命中")

    p = TMP / "sample.ipa"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Payload/Demo.app/Info.plist", f"<plist><string>api_key={SECRET}</string></plist>")
        z.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
    r = scan([p])
    rec("容器", "IPA", hit(r, SECRET), f"{len(r.findings)} 命中")

    p = TMP / "sample.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        z.writestr("assets/config.json", json.dumps({"api_key": SECRET}))
    r = scan([p])
    rec("容器", "APK", hit(r, SECRET), f"{len(r.findings)} 命中 / {r.stats.container_entries} 条目")
    rec("容器", "--no-container 生效", len(scan([p], enable_container=False).findings) == 0)


# --------------------------------------------------------------- pcap
def pcap_sample() -> None:
    payload = f"api_key={SECRET}\n".encode()
    eth = b"\x00" * 6 + b"\x11" * 6 + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 1, 0, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    tcp = struct.pack("!HHIIBBHHH", 12345, 80, 1, 1, 0x50, 0x18, 8192, 0, 0)
    frame = eth + ip + tcp + payload
    p = TMP / "plain.pcap"
    with p.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)))
        f.write(frame)
    try:
        r = scan([p], enable_container=False)
        rec("抓包", "pcap 明文载荷", hit(r, SECRET), f"{len(r.findings)} 命中")
    except Exception as exc:                                  # noqa: BLE001
        rec("抓包", "pcap 明文载荷", False, f"{type(exc).__name__}: {exc}")
    rec("抓包", "tshark 可用", bool(__import__("shutil").which("tshark")))


# --------------------------------------------------------------- 报告 / 开关
def cli_features() -> None:
    out = TMP / "reports"
    cp = cli("demo/samples", "-o", str(out), "-f", "json,csv,sarif,html",
             "--fail-on", "none", "-q")
    rec("报告", "四种格式写出", cp.returncode == 0, cp.stderr.strip()[:60])
    jf = sorted(out.glob("*.json"))
    ok_json = False
    if jf:
        d = json.loads(jf[-1].read_text(encoding="utf-8"))
        ok_json = "stats" in d and "findings" in d and "locale_entries" in d["stats"]
    rec("报告", "JSON 结构 + 新统计字段", ok_json)
    cf = sorted(out.glob("*.csv"))
    rec("报告", "CSV 可解析", bool(cf) and len(list(csv.DictReader(cf[-1].open(encoding="utf-8")))) > 0)
    sf = sorted(out.glob("*.sarif"))
    ok_sarif = False
    if sf:
        s = json.loads(sf[-1].read_text(encoding="utf-8"))
        ok_sarif = bool(s.get("runs", [{}])[0].get("results"))
    rec("报告", "SARIF runs/results", ok_sarif)
    hf = sorted(out.glob("*.html"))
    rec("报告", "HTML 含结果表", bool(hf) and "senscan" in hf[-1].read_text(encoding="utf-8").lower())

    wl = TMP / "wl.txt"
    wl.write_text(SECRET + "\n", encoding="utf-8")
    o2 = TMP / "wlout"
    cp = cli("demo/samples", "-o", str(o2), "-f", "json", "-w", str(wl), "--fail-on", "none", "-q")
    jf2 = sorted(o2.glob("*.json"))
    rec("过滤", "-w 白名单", cp.returncode == 0 and bool(jf2)
        and not any(SECRET in x.get("value", "") for x in json.loads(jf2[-1].read_text(encoding="utf-8"))["findings"]))

    o3 = TMP / "redact"
    cp = cli("demo/samples", "-o", str(o3), "-f", "json", "--redact", "--fail-on", "none", "-q")
    jf3 = sorted(o3.glob("*.json"))
    d3 = json.loads(jf3[-1].read_text(encoding="utf-8")) if jf3 else {}
    rec("过滤", "--redact 脱敏", cp.returncode == 0 and d3.get("scan", {}).get("redacted") is True
        and any("*" in x.get("value", "") for x in d3.get("findings", [])))

    hi = cli("demo/samples", "--no-report", "--fail-on", "high", "-q")
    no = cli("demo/samples", "--no-report", "--fail-on", "none", "-q")
    rec("阈值", "--fail-on high=2 / none=0", hi.returncode == 2 and no.returncode == 0,
        f"high={hi.returncode} none={no.returncode}")
    m = cli("demo/samples", "--no-report", "-m", "0.95", "--fail-on", "none", "-q")
    base = cli("demo/samples", "--no-report", "--fail-on", "none", "-q")
    n_hi = int(re.search(r"(\d+) findings", m.stdout).group(1)) if re.search(r"(\d+) findings", m.stdout) else -1
    n_base = int(re.search(r"(\d+) findings", base.stdout).group(1)) if re.search(r"(\d+) findings", base.stdout) else -1
    rec("阈值", "-m 0.95 命中数下降", 0 <= n_hi < n_base, f"{n_base} → {n_hi}")

    vb = cli("demo/samples", "--no-report", "--verify-local", "--fail-on", "none", "-q")
    rec("验证器", "--verify-local 离线校验", vb.returncode == 0, vb.stderr.strip()[:60])
    # 不实际发起公网请求：只验证默认策略是「不授权即拒绝」
    from senscan.verify import VerifyConfig
    cfg = VerifyConfig()
    rec("验证器", "在线验证默认不授权公网", not getattr(cfg, "allow_public", False))

    binp = TMP / "blob.bin"
    binp.write_bytes(b"\x00\x01\x02" + f"api_key={SECRET}\n".encode() + b"\x00" * 32)
    off = scan([binp]).findings
    on = scan([binp], include_binary=True).findings
    rec("二进制", "--include-binary 开关", not any(SECRET in f.value for f in off)
        and any(SECRET in f.value for f in on))

    big = TMP / "big.log"
    line = "noise line without any credential data " + "x" * 60 + "\n"
    with big.open("w", encoding="utf-8") as f:
        for _ in range(30000):
            f.write(line)
        f.write(f"api_key={SECRET}\n")
    r = scan([big], max_file_mb=1)
    rec("大文件", "--max-file-mb=1 分块不丢命中", hit(r, SECRET), f"{big.stat().st_size // 1024 // 1024}MB")

    try:
        r = scan(["demo/samples"])
        rec("API", "scan() 接受 str 路径", len(r.findings) > 0)
    except Exception as exc:                                  # noqa: BLE001
        rec("API", "scan() 接受 str 路径", False, f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------- Web UI
def web_ui() -> None:
    base = "http://127.0.0.1:8791"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        html = opener.open(base + "/", timeout=8).read().decode("utf-8")
        m = re.search(r'const TOKEN = "([^"]+)"', html)
        rec("工作台", "首页可访问 + token", bool(m))
        if not m:
            return
        token = m.group(1)
        body = json.dumps({"paths": ["demo/samples"], "min_confidence": 0.55,
                           "verify": {"local": True}}).encode()
        req = urllib.request.Request(base + "/api/scan", data=body, headers={
            "X-Senscan-Token": token, "Content-Type": "application/json"})
        jid = json.load(opener.open(req, timeout=20))["job_id"]
        import time
        status = "?"
        for _ in range(100):
            req = urllib.request.Request(base + f"/api/job?id={jid}",
                                         headers={"X-Senscan-Token": token})
            status = json.load(opener.open(req, timeout=20)).get("status")
            if status != "running":
                break
            time.sleep(0.2)
        req = urllib.request.Request(base + f"/api/result?id={jid}",
                                     headers={"X-Senscan-Token": token})
        d = json.load(opener.open(req, timeout=20))
        st = d.get("stats", {})
        rec("工作台", "扫描接口 + 结果 payload", status not in (None, "running", "?")
            and "locale_entries" in st and "container_entries" in st,
            f"status={status} findings={len(d.get('findings', []))}")
        bad = json.dumps({"paths": [str(TMP / "definitely-missing.apk")]}).encode()
        req = urllib.request.Request(base + "/api/scan", data=bad, headers={
            "X-Senscan-Token": token, "Content-Type": "application/json"})
        try:
            opener.open(req, timeout=10)
            rec("工作台", "不存在路径启动期报错", False, "未报错")
        except urllib.error.HTTPError as e:
            rec("工作台", "不存在路径启动期报错", e.code in (400, 422),
                f"HTTP {e.code}")
    except Exception as exc:                                  # noqa: BLE001
        rec("工作台", "HTTP 接口", False, f"{type(exc).__name__}: {exc}")


def main() -> None:
    for name, fn in (("容器", zip_samples), ("抓包", pcap_sample),
                     ("CLI", cli_features), ("工作台", web_ui)):
        try:
            fn()
        except Exception as exc:                              # noqa: BLE001
            rec(name, "整组异常", False, f"{type(exc).__name__}: {exc}")
    print(f"{'模块':<8}{'检查项':<38}{'结果':<6}说明")
    print("-" * 100)
    for g, n, ok, note in ROWS:
        print(f"{g:<8}{n:<38}{'PASS' if ok else 'FAIL':<6}{note[:60]}")
    bad = [r for r in ROWS if not r[2]]
    print("-" * 100)
    print(f"共 {len(ROWS)} 项，通过 {len(ROWS) - len(bad)}，失败 {len(bad)}")
    print("临时目录:", TMP)
    for r in bad:
        print("  FAIL:", r[0], r[1], r[3])


if __name__ == "__main__":
    main()
