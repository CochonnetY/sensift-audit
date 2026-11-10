"""扩充演示样本：国际 SaaS Token、国内云密钥、连接串、PII（正例）。

误报陷阱集中在 traps-gbk.log / TRAPS_LOG（make_demo.py），此处只放应该被命中的内容。
所有样本值均为程序生成的假值，不包含任何真实凭据。
"""

from __future__ import annotations

import base64
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from senscan.utils import cn_id_check_digit, luhn_check_digit  # noqa: E402

OUT = Path(__file__).resolve().parent / "samples"


def rnd(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def hexs(n: int) -> str:
    return "".join(secrets.choice("0123456789abcdef") for _ in range(n))


def gen_id_card() -> str:
    """生成一个校验位正确的假身份证号（区域码随机合法、日期随机合法）。"""
    area = secrets.choice(["110105", "310104", "440305", "330106", "510107"])
    birth = f"{secrets.choice(range(1970, 2005))}{secrets.choice(range(1, 13)):02d}{secrets.choice(range(1, 29)):02d}"
    seq = f"{secrets.choice(range(1, 500)):03d}"
    body = area + birth + seq
    return body + cn_id_check_digit(body)


def gen_bank_card(prefix: str = "622202", length: int = 16) -> str:
    body = prefix + "".join(secrets.choice(string.digits) for _ in range(length - len(prefix) - 1))
    return body + luhn_check_digit(body)


def gen_iccid() -> str:
    body = "898601" + "".join(secrets.choice(string.digits) for _ in range(13))
    return body + luhn_check_digit(body)


def gen_imei() -> str:
    body = "86" + "".join(secrets.choice(string.digits) for _ in range(12))
    return body + luhn_check_digit(body)


def gen_amex() -> str:
    body = "37" + "".join(secrets.choice(string.digits) for _ in range(12))
    return body + luhn_check_digit(body)


def b64_basic(user: str, pwd: str) -> str:
    return base64.b64encode(f"{user}:{pwd}".encode()).decode()


SAAS_LOG = f"""# 2026-11-08 运维巡检采样（值均为程序生成假值）
[2026-11-08 09:12:01] deploy    api_key = sk_live_{rnd(32)}
[2026-11-08 09:12:02] deploy    aws_access_key_id=AKIAT3STXK9P2WQM4RZL
[2026-11-08 09:12:03] deploy    aws_secret_access_key = {rnd(40, string.ascii_letters + string.digits + "/+")}
[2026-11-08 09:12:04] deploy    github_token="ghp_{rnd(36)}"
[2026-11-08 09:12:05] webhook   slack incoming: https://hooks.slack.com/services/T{rnd(9, string.ascii_uppercase + string.digits)}/B{rnd(9, string.ascii_uppercase + string.digits)}/{rnd(24, string.ascii_letters + string.digits)}
[2026-11-08 09:12:06] bot       telegram token: 8123456789:AAH9xKpQ2mNvR8bY1cLdF4hJ6gA0eWzS5uw
[2026-11-08 09:12:07] mail      sendgrid key SG.{rnd(40, string.ascii_lowercase + string.digits)}.{rnd(26, string.ascii_letters + string.digits)}
[2026-11-08 09:12:08] npm       //registry.npmjs.org/:_authToken=npm_{rnd(36, string.ascii_lowercase + string.digits)}
[2026-11-08 09:12:09] cloud     digitalocean pat dop_v1_{hexs(64)}
[2026-11-08 09:12:10] shop      shopify shpat_{hexs(32)}
[2026-11-08 09:12:11] ai        hf_token = hf_{rnd(34)}
[2026-11-08 09:12:12] weixin    appsecret: {hexs(32)}  (wxapp order-miniapp)
[2026-11-08 09:12:13] db        mysql://appuser:Tr0ub4dor&3@10.20.30.40:3306/orders
[2026-11-08 09:12:14] cache     rediss://default:Ab3kK9mP2xQ8@r-bp1a7d3f.redis.rds.aliyuncs.com:6379/0
[2026-11-08 09:12:15] db        jdbc:mysql://10.20.30.40:3306/oms?useSSL=false&password=Hk93mXq7Lw2d
[2026-11-08 09:12:16] es        http://elastic:Kj8mN2pQ9rS4@10.0.0.5:9200/_cluster/health
[2026-11-08 09:12:17] azure     DefaultEndpointsProtocol=https;AccountName=stprod01;AccountKey={rnd(88, string.ascii_letters + string.digits + "+/")}==;
[2026-11-08 09:12:18] sms       sms_code sent to phone=13912345678, template SMS_460121
[2026-11-08 09:12:19] kyc       idcard={gen_id_card()} name=张*, nation=HAN
[2026-11-08 09:12:20] pay       card_no={gen_bank_card()} exp=08/27 cvv=***
[2026-11-08 09:12:21] sim       iccid: {gen_iccid()} (eSIM order #A1024)
[2026-11-08 09:12:22] email     mail_to: wang.wu@example-corp.com.cn cc=li.si@example-corp.com.cn
[2026-11-08 09:12:23] amex      cardno {gen_amex()} gateway=stripe
[2026-11-08 09:12:24] oss       access_key_secret = Wn4kP9qX2vB8sL5dJ7hG3fN1mC6rT0
[2026-11-08 09:12:25] http      Authorization: Basic {b64_basic("svc-report", "Xk7#mP2$vQ9")}
[2026-11-08 09:12:26] serial    device_sn=F4CE9A2B71D0 (gateway #GW-0331)
[2026-11-08 09:12:27] radio     imsi=460{secrets.choice('0123456789')}{rnd(11, string.digits)} mcc=460 (roaming off)
"""

TRAPS_PII_LOG = f"""# PII 误报陷阱：以下都不应命中或应被压制
user login trace order_no=13812340000123 trace_id=8f9a2b3c
mobile=13800138000
mobile=13900000000
idcard=110105194912310021
card_no=6222020000000000
card=1234567890123456
email=user@example.com
logo@2x.png icon@3x.png sprite@2x.png
password=********
token=REDACTED
api_key=YOUR_API_KEY_HERE
jdbc:mysql://10.0.0.1:3306/app?password=changeme
mysql://root:password@localhost:3306/test
authorization: Basic dXNlcjpwYXNzd29yZA==
authorization: Basic eW91cmlkOnBhc3N3b3Jk
session_key=EXAMPLE_SESSION_KEY_PLACEHOLDER
"""


# ---------------------------------------------------------------------------
# IoT / 嵌入式设备日志（用户提供样例的同构改写，值全部为编造的假值）
#
# 保留原日志里每一种「难写」的字段形态，这是规则的回归重点：
#   模块名粘连 / C 指针箭头 / 两字母缩写 / 冒号后无空格 / 空格分隔字段名 /
#   ANSI 颜色转义 / 同一组值在 4 处重复出现
IOT_PK = "a1Zk9Qm2Xv7Bn4Lp8Tc"
IOT_DN = "devGW0331Kb7Yt2Rs9Qm"
IOT_DS = "Kd8sVn2Lq9Zx4Wp7Rm3Bt6Yc1Fh5Nj"

IOT_LOG = f"""Device info loaded from config_managerproduct_key: {IOT_PK}, device_name: {IOT_DN}, device_secret: {IOT_DS}, domain_name: , region: CN
=========================================demo start ========================================
===========streamsdk version: 1.7.0.1_81184cda_20261022 ===========
device_msg->product_key: {IOT_PK}
device_msg->device_name: {IOT_DN}
device_msg->device_secret: {IOT_DS}
device_msg->domain_name:
device_msg->region: CN
Using device triplet: PK={IOT_PK}, DN={IOT_DN}, DS={IOT_DS}
\x1b[36;22mI/XOS_IOT_SDK      [1970-01-01 01:16:17.904] (xos_iot_device.c:31 setMasterDeviceInfo)set master device info ,device name:{IOT_DN}
\x1b[0m
stacksize:524288
stacksize:524288
"""

# 缩写规则的误报陷阱：这些 PK/DN/DS/AK/SK 都不能被当成凭据
IOT_TRAPS_LOG = """INSERT INTO t (id) VALUES (1); PK=12345678, DN=row_0001, DS=shard01
bind DN=cn=admin,dc=corp,dc=com DS=directory_service
mount DS=/dev/sda1 PK=/usr/local/bin
device_secret: your_device_secret_here
product_key: XXXXXXXXXXXXXXXXXXXX
streamsdk version: 1.7.0.1_81184cda_20261022
stacksize:524288
region: CN
domain_name:
SELECT user_id AS customer_identifier FROM t
[iot watchdog] AS=alias_name_value_here SK=sort_key_order_value
boot: DS=isolated_value_without_any_triplet_context
"""


# ---------------------------------------------------------------------------
# 设备密钥分区 dump（用户第二张截图同构，值全部编造）
# 特征：无 PEM 头的 ASN.1 DER base64、驼峰 JSON 字段、串口日志按列宽硬折行
def _fake_ec_pub() -> str:
    """结构合法但内容无意义的 EC P-256 SubjectPublicKeyInfo（全 0x11 填充）。"""
    head = bytes.fromhex("3049301306072a8648ce3d020106082a8648ce3d03010703420004")
    return base64.b64encode(head + b"\x11" * 64).decode()


_FAKE_PUB = _fake_ec_pub()
PARAM_PART_LOG = f"""[36;22mI/IPC MAIN [2026-11-03 18:07:38.004] (main.c:904 main)>>>>>>>>>>>>>>>>> xos_aes_hw_crypto_init finished![0m
[36;22mI/XOS_PARAM_PART_RW [2026-11-03 18:07:38.010] (xos_bind_param_rw_api.c:235 xos_bind_param_rw_read_param)buf:
F0f8XMmdXGXgyraI5yGU262jQkvknTraWF39OH7qqvA6yh34ZSHMGVAMSL0YcD1ENs6o2F7GEbbUEZUDzKv5s/b8nFe1ZfAKZkWzAWFF9pD+IDzB8nMcRkD5W8ar1Y60dc4hx7iVQg
+CqBlyQ1BVggr8xUOOs2Uod4IViyiJ/ueqoMGHFK9MmBeVOQnseleTItIy8YNIQO2sDsd1SgYoyOoAxtJIs6Jg8
"Factory","mode":"user","sn":"0|080200U6100006A","version":"1.0.0","PrivateKey":"AbCd9f
==","PublicKey":"{_FAKE_PUB[:40]}
{_FAKE_PUB[40:]}","productModel":"","hw_version":"OD800PRO-
MAIN-02A","macaddr":"AA0D800E8S0205","again_time":0,"cpKeySize":"164","productKey":"{IOT_PK}","deviceName":"{IOT_DN}","dev
Secret":"{IOT_DS}","region":"CN","userId":"1374012"
[0m
[36;22mI/XOS_PARAM_PART_RW [2026-11-03 18:07:38.012] (xos_bind_param_rw_api.c:42 xos_bind_param_rw_parse_param_json)is: 0|080200U6100006A[0m
"""


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "saas.log").write_text(SAAS_LOG, encoding="utf-8")
    (OUT / "traps-pii.log").write_text(TRAPS_PII_LOG, encoding="utf-8")
    (OUT / "iot-device.log").write_text(IOT_LOG, encoding="utf-8")
    (OUT / "iot-traps.log").write_text(IOT_TRAPS_LOG, encoding="utf-8")
    (OUT / "param-part.log").write_text(PARAM_PART_LOG, encoding="utf-8")
    print(f"样本已写入 {OUT}")
    print("  saas.log        26 行（国际 SaaS + 国内云 + 连接串 + PII 正例）")
    print("  traps-pii.log   17 行（PII 误报陷阱）")
    print("  iot-device.log  14 行（IoT 三元组：完整名 / PK,DN,DS 缩写 / 箭头 / 粘连 / ANSI）")
    print("  iot-traps.log   12 行（缩写字段名误报陷阱）")
    print("  param-part.log  11 行（密钥分区 dump：裸 DER / PrivateKey / PublicKey / 硬折行）")


if __name__ == "__main__":
    main()
