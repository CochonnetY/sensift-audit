"""构造一个最小 pcap（单个明文 HTTP POST），用于验证 tshark 通道。

不依赖 scapy：手写 Ethernet/IPv4/TCP 头并算好校验和。
"""

from __future__ import annotations

import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent / "samples" / "track.pcap"

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiI4NjEyMzQ1Njc4OTAxMjMiLCJkZXZpY2UiOiJhbmRyb2lkIn0"
    ".9mZ3kQx7bT2pLwR8sVnA4cYdH1jK6eUf"
)

BODY = (
    b'{"api_key":"sk-proj-AbCdEfGhIjKlMnOpQrStUvWx",'
    b'"password":"Pa55w0rd!2024","oaid":"5f8c1e2a-9b3d-4c7e-8f10-2a6b9d4e7c31"}'
)

REQUEST = (
    b"POST /api/v1/track?imei=861234567890127 HTTP/1.1\r\n"
    b"Host: track.corp.example.com\r\n"
    b"User-Agent: Dalvik/2.1.0\r\n"
    b"Authorization: Bearer " + JWT.encode() + b"\r\n"
    b"Cookie: JSESSIONID=8F2A9C41B7E35D60A1C4E8F2B9D7A3C5\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    + BODY
)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_frame() -> bytes:
    eth = (
        bytes.fromhex("001122334455")      # dst
        + bytes.fromhex("66778899aabb")    # src
        + b"\x08\x00"                      # IPv4
    )

    src_ip = bytes([192, 168, 1, 100])
    dst_ip = bytes([93, 184, 216, 34])

    tcp_len = 20 + len(REQUEST)
    pseudo = src_ip + dst_ip + b"\x00\x06" + struct.pack(">H", tcp_len)

    tcp = struct.pack(
        ">HHIIHHHH",
        51820, 80,            # sport, dport
        1, 1,                 # seq, ack
        (5 << 12) | 0x18,     # data offset 5, PSH+ACK
        64240, 0, 0,          # window, checksum(占位), urg
    )
    tcp_csum = checksum(pseudo + tcp + REQUEST)
    tcp = tcp[:16] + struct.pack(">H", tcp_csum) + tcp[18:]

    total_len = 20 + tcp_len
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len,
        0x1234, 0x4000, 64, 6, 0,
        src_ip, dst_ip,
    )
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]

    return eth + ip + tcp + REQUEST


def main() -> None:
    frame = build_frame()
    pcap = (
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1762534000, 0, len(frame), len(frame))
        + frame
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(pcap)
    print(f"pcap 已生成: {OUT} ({len(frame)} 字节/帧)")


if __name__ == "__main__":
    main()
