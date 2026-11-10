# sensift-audit


在日志、配置、埋点 JSON、固件产物和 pcap 里翻找被人忘掉的密钥、令牌和个人信息，然后告诉你它在哪一行、有多可信、该先处理哪一条。

说白了就是个翻垃圾的。翻得比人细，也比人啰嗦。

Python 3.10+，零第三方依赖。抓包解析需要系统里有 `tshark`（Wireshark 自带）；没装也能扫文本，只是 pcap 会被跳过。

## 跑起来

```bash
pip install -e .

senscan ./logs -o reports
senscan capture.pcap -o reports
senscan app.log --no-report          # 只在终端看，不写文件
senscan ui                           # 浏览器打开 http://127.0.0.1:8777
```

不想安装就把 `senscan` 换成 `python -m senscan`，参数一样。工作台只监听本机，换端口用 `python -m senscan ui --port 9000 --no-browser`。

| 参数 | 作用 |
|---|---|
| `-o DIR` | 输出目录，默认 `senscan-reports` |
| `-f json,csv,sarif,html` | 挑报告格式，默认四种全出 |
| `-w wl.txt` | 白名单，支持裸值、`MAC:xxx`、通配符、`regex:` |
| `-m 0.7` | 置信度阈值，越高越保守（默认 0.55） |
| `--verify-local` | 离线判断 JWT 过期、签名 URL 失效、PEM 结构，不联网 |
| `--redact` | 报告脱敏，外发前加 |
| `--fail-on critical` | 命中即返回退出码 2，给 CI 用 |



| 类别 | 实体 | 风险 | 判定依据 |
|---|---|---|---|
| 密钥/证书 | `PRIVATE_KEY` | critical | 完整 PEM 块（须有密钥体）或 BEGIN 头（截断日志）；PuTTY `.ppk`；GCP 服务账号 JSON |
| 凭据 | `API_KEY` | high/critical | AWS（含 Secret Key）、阿里云 AK/SK、腾讯云 SecretId/Key、华为云、微信 AppSecret、Stripe、GitHub（PAT + fine-grained）、GitLab、OpenAI、Anthropic、HuggingFace、SendGrid、Slack（含 webhook）、Telegram、npm、PyPI、Shopify、Vercel、Notion、Linear、DigitalOcean、Twilio、Mailgun、Square、Braintree、Azure Storage |
| 凭据 | `TOKEN` | high | JWT（header 必须可解析）、`Bearer`、`*_token=`、AWS STS |
| 凭据 | `PASSWORD` | high | `password=` 键名、`Authorization: Basic`（解出 user:pass 且非示例值）、OTP |
| 基础设施 | `DB_CREDENTIAL` | high | mysql/postgres/mongodb/redis/ftp/ldap 等连接串（口令不得是占位值）、JDBC、URL 内嵌 Basic 凭据 |
| 基础设施 | `OSS_SIGNED_URL` | high | 阿里云 OSS / AWS S3 / 腾讯 COS / 七牛 / Azure SAS 预签名 URL |
| 基础设施 | `RTSP_CRED` | high | `rtsp://user:pass@host`（摄像头） |
| 个人信息 | `ID_CARD` | high | 18 位身份证，**GB 11643 加权模 11** + 出生日期合法性 |
| 个人信息 | `BANK_CARD` | high | **Luhn** + 15 位仅认 AMEX 前缀（避免与 IMEI 互撞）+ 卡号字段名 |
| 个人信息 | `PHONE` | medium | 大陆号段白名单 + 假号黑名单（13800138000 之类） |
| 个人信息 | `EMAIL` | low | TLD 必须为字母（排除连接串片段）、排除示例域与静态资源 |
| 设备标识 | `IMEI` | medium | 15 位 + Luhn；`imeisv=` 16 位 |
| 设备标识 | `IMSI` | medium | 15 位 + 中国 MCC 前缀（460 等） |
| 设备标识 | `ICCID` | medium | 20 位、89 开头 + Luhn |
| 设备标识 | `OAID` / `IDFA` | medium | 字段名锚定；裸 UUID 必须有上下文 |
| 设备标识 | `MAC` / `LTK` / `DEVICE_SN` / `CERT_FINGERPRINT` | low/medium | 校验和 + 字段名/语境 |
| 设备凭据 | `IOT_DEVICE_SECRET` | critical | IoT 一机一密三元组：`device_secret` / `devSecret` / `DS=` 等键名（值无任何格式特征，纯靠键名定位） |
| 设备标识 | `IOT_PRODUCT_KEY` / `IOT_DEVICE_NAME` | low/medium | `product_key` / `productKey` / `PK=`、`device_name` / `deviceName` / `DN=` |
| 密钥/证书 | `PRIVATE_KEY`（裸 DER） | critical | 无 PEM 头：`PrivateKey` 字段或 ASN.1 DER 前缀（PKCS#1/#8、SEC1、Ed25519）+ base64 解码首字节须为 `0x30` |
| 密钥/证书 | `PUBLIC_KEY` | low | `PublicKey` 字段 / EC·RSA·Ed25519 SPKI 的 DER base64；公钥不涉密，但提示同区可能含私钥 |

## 报告和工作台

| 格式 | 什么时候用 |
|---|---|
| `html` | 单文件离线可开，发评审最省事。带筛选、排序、判定依据和处置建议 |
| `csv` | UTF-8 BOM，Excel 直接打开 |
| `json` | 完整字段加各类汇总，给程序消费 |
| `sarif` | SARIF 2.1.0，丢进 GitHub Code Scanning |





## 其他

完整使用手册在 [docs/USAGE.md](docs/USAGE.md)：读报告、调阈值、写新规则、接 CI、合规注意事项都在里面。
报告默认不脱敏，里面有明文凭据和身份证号，是为了让你核对得动。别顺手甩到群里，外发一律重新跑一次加 `--redact`。

MIT，见 [LICENSE](LICENSE)。
