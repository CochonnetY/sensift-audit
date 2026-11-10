"""生成演示/回归样本：覆盖 13 类真阳性 + 8 类典型误报陷阱。

运行：python demo/make_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from senscan.utils import luhn_check_digit  # noqa: E402

OUT = Path(__file__).resolve().parent / "samples"
DEMO = Path(__file__).resolve().parent

IMEI_PREFIX = "86123456789012"
IMEI = IMEI_PREFIX + luhn_check_digit(IMEI_PREFIX)
OAID = "5f8c1e2a-9b3d-4c7e-8f10-2a6b9d4e7c31"
IDFA = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"
MAC = "3c:5a:b4:1f:8e:22"
LTK = "8f3a91c47d2e5b68a0c1d4f7e2b9a350"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiI4NjEyMzQ1Njc4OTAxMjMiLCJkZXZpY2UiOiJhbmRyb2lkIiwiaWF0IjoxNzYyNTM0MDAwfQ"
    ".9mZ3kQx7bT2pLwR8sVnA4cYdH1jK6eUf"
)
SHA256_FP = (
    "4a:1f:9c:3d:7e:22:88:bb:01:f4:6d:9a:2c:5e:70:13:"
    "9f:a8:41:6b:d2:8e:37:c5:0a:94:5f:be:26:7d:18:e3"
)
OSS_URL = (
    "https://corp-assets.oss-cn-hangzhou.aliyuncs.com/2026/11/a.mp4"
    "?OSSAccessKeyId=LTAI5tAbCdEfGhIjKlMn&Expires=1762500000&Signature=xJ3k%2B9Qz"
)
RTSP = "rtsp://admin:Camera%40123@192.168.1.64:554/stream1"

APP_LOG = f"""\
2026-11-08 09:12:31.442  INFO [net] POST https://api.corp.example.com/v1/upload
2026-11-08 09:12:31.443 DEBUG [net] Authorization: Bearer {JWT}
2026-11-08 09:12:32.101 DEBUG [device] imei={IMEI}
2026-11-08 09:12:32.102 DEBUG [device] oaid={OAID}
2026-11-08 09:12:32.103 DEBUG [device] mac={MAC}
2026-11-08 09:12:33.001  INFO [ble]  ltk={LTK}
2026-11-08 09:12:34.220  WARN [auth] login failed for uid=10023, password=Pa55w0rd!2024
2026-11-08 09:12:35.010  INFO [camera] pull stream {RTSP}
2026-11-08 09:12:36.500  INFO [oss]  upload ok: {OSS_URL}
2026-11-08 09:12:37.001  INFO [sess] JSESSIONID=8F2A9C41B7E35D60A1C4E8F2B9D7A3C5
2026-11-08 09:12:38.100  INFO [sms]  验证码 739251，5分钟内有效
2026-11-08 09:12:39.900 DEBUG [cfg]  access_token=Zk8vQ2mNp7Rt4Xy1Bw6Lc9Jd3Hs5Gf0A
"""

TELEMETRY = "\n".join([
    json.dumps({
        "event": "app_launch", "ts": 1762534000,
        "device": {"imei": IMEI, "oaid": OAID, "os": "Android 14", "model": "Pixel 8"},
        "session": {"session_id": "d41f9a2c7b3e8560"},
    }, ensure_ascii=False),
    json.dumps({
        "event": "ad_impression", "ts": 1762534012,
        "ad": {"idfa": IDFA, "placement": "splash"},
    }, ensure_ascii=False),
    json.dumps({
        "event": "upload", "ts": 1762534030,
        "http": {"url": OSS_URL, "authorization": f"Bearer {JWT}"},
    }, ensure_ascii=False),
]) + "\n"

NET_CFG = f"""\
[device]
mac = 3C:5A:B4:1F:8E:22
imei = {IMEI}
sn = SN20261108001

[rtsp]
url = {RTSP}

[ble]
ltk = {LTK}

[auth]
password = Pa55w0rd!2024
api_key = LTAI5tAbCdEfGhIjKlMn
"""

FIRMWARE_LOG = f"""\
[    0.000000] Booting Linux 5.15.0 on arm64
[    0.842311] usb 1-1: new high-speed USB device number 2
[    2.341902] keyring: loading device key
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3sT9pQ7xK2mNvR8bY1cLdF4hJ6gA0eWzS5uPoI3rT7yUvX9b
-----END RSA PRIVATE KEY-----
[    3.112004] tls: pinned cert fingerprint sha256 {SHA256_FP}
[    4.500881] storage: mounted /data, 128MB free
[    5.008332] cfg: device api_key = LTAI5tAbCdEfGhIjKlMn
[    6.220145] ota: check version 2026.11.08
"""

TRAPS_LOG = """\
2026-11-09 10:00:00 INFO  [dbg] request_id=9b2e4c7a-3d18-4f6b-a2c9-7e1f5b8d0a34 trace=ok
2026-11-09 10:00:01 INFO  [git] commit=3f8a9b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90
2026-11-09 10:00:02 INFO  [perf] elapsed=1699512345678 ms
2026-11-09 10:00:03 INFO  [net] peer=2001:0db8:85a3:0000:0000:8a2e:0370:7334
2026-11-09 10:00:04 DEBUG [cfg] mac=ff:ff:ff:ff:ff:ff broadcast dst
2026-11-09 10:00:05 DEBUG [cfg] token=example-token-for-docs
2026-11-09 10:00:06 DEBUG [cfg] password=********
2026-11-09 10:00:07 INFO  [dbg] device_sn=000000000000000
2026-11-09 10:00:08 INFO  [build] sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709
2026-11-09 10:00:09 INFO  [dbg] order_no=20261109000123456 amount=19900
2026-11-09 10:00:10 INFO  [dbg] retry backoff 00:00:05, 00:00:10
2026-11-09 10:00:11 INFO  [dbg] version 1.2.3 build 2026110901
"""

WHITELIST = """\
# 白名单示例：已知安全项
MAC:3c:5a:b4:1f:8e:22
regex:^SN2026
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "app.log").write_text(APP_LOG, encoding="utf-8")
    (OUT / "telemetry.json").write_text(TELEMETRY, encoding="utf-8")
    (OUT / "net.cfg").write_text(NET_CFG, encoding="utf-8")
    (OUT / "firmware.log").write_text(FIRMWARE_LOG, encoding="utf-8")
    # GBK 编码样本，验证编码回退
    (OUT / "traps-gbk.log").write_text(TRAPS_LOG, encoding="gb18030")
    (OUT / "traps.log").write_text(TRAPS_LOG, encoding="utf-8")
    # 白名单放在 samples 之外，避免被自身扫描命中
    (DEMO / "wl.txt").write_text(WHITELIST, encoding="utf-8")
    stale = OUT / "wl.txt"
    if stale.exists():
        stale.unlink()
    print(f"samples 已生成: {OUT}")
    print(f"  IMEI={IMEI}  (Luhn 校验位={IMEI[-1]})")


if __name__ == "__main__":
    main()
