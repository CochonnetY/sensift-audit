# sensift-audit

在日志、配置、埋点 JSON、固件产物、APK 包和抓包里翻找被人忘掉的密钥、令牌和个人信息，然后告诉你它在哪一行、有多可信、该先处理哪一条。

84 条规则 / 26 类实体。Python 3.10+，零第三方依赖。抓包解析需要系统里有 `tshark`（Wireshark 自带）；没装也能扫文本，只是抓包会被跳过。

## 跑起来

```bash
pip install -e .
python -m senscan ui                          # 浏览器打开 http://127.0.0.1:8777
```

| 参数 | 作用 |
|---|---|
| `-o DIR` | 输出目录，默认 `senscan-reports` |
| `-f json,csv,sarif,html` | 挑报告格式，默认四种全出 |
| `-w wl.txt` | 白名单，支持裸值、`MAC:xxx`、通配符、`regex:` |
| `-m 0.7` | 置信度阈值，越高越保守（默认 0.55） |
| `--verify-local` | 离线判断 JWT 过期、签名 URL 失效、PEM 结构，不联网 |
| `--redact` | 报告脱敏，外发前加 |
| `--fail-on critical` | 命中即返回退出码 2，给 CI 用 |
| `--no-container` | 不拆包，只扫裸文本 |
| `--rules-file my.json` | 追加企业自定义规则（内置 + 自定义，零依赖） |
| `--baseline last.json` | 对比上次 JSON 报告，输出新增 / 仍在 / 已修复 |

能喂进去的东西：

| 目标 | 怎么处理 |
|---|---|
| 日志 / 配置 / JSON / 源码 | 依次试 UTF-8、GBK、UTF-16 解码后直接扫 |
| pcap / pcapng / 蓝牙 HCI | 调 `tshark` 抽明文字段（HTTP、TCP payload、BLE ATT）；TLS 正文看不到。工作台须勾选「解析抓包 (Wireshark)」，CLI 默认开启 |
| APK / JAR / IPA | 解包：assets 等文本直扫，`classes.dex`、`.so`、`resources.arsc` 抽可打印串 |
| Office / zip / tar / gz | Office 取正文 XML；压缩包递归两层，带 zip 炸弹防护 |
| SQLite | 逐表逐列导出 `表.列=值`，列名当上下文 |

包内命中定位写成 `app.apk!assets/config.json:12`，`!` 后面是包内路径。容器默认开启（`--no-container` 可关）；抓包默认开启（`--no-pcap` 可关）。PDF、Git 历史、加密压缩包、TLS 解密、dex 反编译与脱壳不支持。

| 类别 | 实体 | 风险 | 判定依据 |
|---|---|---|---|
| 密钥/证书 | `PRIVATE_KEY` | critical | 完整 PEM 块（须有密钥体）或 BEGIN 头（截断日志）；PuTTY `.ppk`；GCP 服务账号 JSON |
| 凭据 | `API_KEY` | high/critical | AWS（含 Secret Key）、阿里云 AK/SK、腾讯云 SecretId/Key、华为云、微信 AppSecret、Stripe、GitHub（PAT + fine-grained）、GitLab、OpenAI、Anthropic、HuggingFace、SendGrid、Slack（含 webhook）、Telegram、npm、PyPI、Vercel、Notion、Linear、Twilio、Mailgun、Square、Braintree、Azure Storage |
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

键名不挑写法：`db_password`、`数据库密码：`、`设备密钥＝`、`蓝牙密钥:` 都认，全角冒号也不挑。`密码策略:` 这类说明文字不会被当成口令。

## 报告和工作台

| 格式 | 什么时候用 |
|---|---|
| `html` | 单文件离线可开，发评审最省事。带筛选、排序、判定依据和处置建议；详情「原文」高亮命中值 |
| `csv` | UTF-8 BOM，Excel 直接打开 |
| `json` | 完整字段加各类汇总，给程序消费 |
| `sarif` | SARIF 2.1.0，丢进 GitHub Code Scanning；上传前加 `--redact` |

工作台（`python -m senscan ui`）只监听 `127.0.0.1`，一次性 token 鉴权。**不保存扫描记录**：刷新即空态、每次只保留当前一次；侧栏「删除当前测试数据」可清空内存结果与验证审计日志，需要留档就点导出。侧栏还可填「基线报告」路径与自定义规则 JSON，新增「合规映射」页签。

## 合规映射（线索归类，不是法律结论）

四种报告都带可机读的 `compliance` 块：把 26 类实体逐类标为**法定敏感个人信息 / 国标口径敏感 / 一般个人信息 / 设备标识 / 组织凭据 / 技术材料**，附归类依据、适用条款、PIPL 第 55 条 PIA 触发判断、口径差异提醒与待补充缺口；HTML 与工作台有汇总表和法条目录，CSV 有独立列，SARIF 有标签。

依据（核实于 2026-11-25，以申报时生效版本为准）：《个人信息保护法》《网络安全法》《数据安全法》官方全文，GB/T 35273-2020《信息安全技术 个人信息安全规范》，GB/T 39335-2020《个人信息安全影响评估指南》，以及数据出境相关规章。

**两条容易踩的坑，工具已显式区分：**

1. **PIPL 第 28 条与 GB/T 35273 附录 B 口径不同。** 法定敏感个人信息列举为生物识别、宗教信仰、特定身份、医疗健康、金融账户、行踪轨迹及不满十四周岁未成年人信息，**不含手机号、邮箱、设备标识**；GB/T 35273-2020 附录 B 表 B.1 的「个人敏感信息」范围更宽，另含个人电话号码、邮箱地址及口令、系统账号等。GB/T 是**推荐性国家标准**，不能据此直接认定法定敏感性——报告对同一实体分别给出两套分类。
2. **凭据不是个人信息。** API Key、私钥、设备密钥通常是组织资产，不是「与已识别或可识别的自然人有关的信息」（PIPL 第 4 条），适用网安法第 21/42 条、数安法第 27/29 条的安全保障与事件处置义务，不硬套个人信息主体权利条款；但若口令属于自然人账户，GB/T 35273 附录 B 将其列为个人敏感信息，报告会标「需人工确认归属」。

本节不构成法律意见，也不替代 PIA；是否需开展 PIA、数据定性与处置措施须经数据合规律师结合具体处理活动复核。

## 增量复测

```bash
python -m senscan ./logs -o reports --baseline reports/senscan-20261101-120000.json
```

输出「新增 / 仍在 / 已修复」三态，身份键是 `实体 + 值指纹`，与文件位置无关（值挪到别的文件仍算「仍在」）。基线报告即使由 `--redact` 生成也能对齐；旧版脱敏报告缺指纹时会退回按可见文本比对并明确标注结论可能不准。

## CI

仓库自带 [.github/workflows/ci.yml](.github/workflows/ci.yml)：Python 3.10–3.13 单测矩阵 + demo 扫描结果上传 SARIF 到 Code Scanning（脱敏）。门禁用法 `--fail-on critical` 返回退出码 2，见手册 7.1。

## 其他

完整使用手册在 [docs/USAGE.md](docs/USAGE.md)：读报告、调阈值、写新规则、接 CI、合规注意事项都在里面。

报告默认不脱敏，里面有明文凭据和身份证号，是为了让你核对得动。别顺手甩到群里，外发一律重新跑一次加 `--redact`。

MIT，见 [LICENSE](LICENSE)。
