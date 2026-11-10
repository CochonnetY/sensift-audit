# senscan — 敏感实体自动提取审计器

从设备日志、配置文件、埋点上报 JSON、固件解压产物、**pcap 抓包**中提取**凭据类**与**个人信息类**实体，输出带验证状态、存活状态、处置批次与位置定位、可直接用于合规评审的审计报告。提供 **CLI + 本地可视化工作台 + 三层存活验证器**。

零第三方依赖，Python 3.10+。pcap 解析依赖系统的 `tshark`（Wireshark 自带）。

## 快速开始

```bash
# 扫描目录（递归），pcap 自动识别
python -m senscan ./logs -o reports

# 直接扫抓包
python -m senscan capture.pcap -o reports

# 带白名单 + 提高阈值
python -m senscan ./firmware-out -w wl.txt -m 0.7 -o reports

# 只看结果不落盘（探索阶段）
python -m senscan app.log --no-report

# 安装为命令
pip install -e . && senscan ./logs

# 启动可视化工作台（浏览器打开 http://127.0.0.1:8777）
python -m senscan ui

# 离线结构验证：JWT 是否过期、签名 URL 是否失效、PEM 是否加密（不联网）
python -m senscan ./logs --verify-local -o reports
```

生成演示样本并跑一遍：

```bash
python demo/make_demo.py     # 日志/配置/埋点 JSON（含 8 类假阳性陷阱）
python demo/make_demo_v2.py  # 国际 SaaS / 国内云 / 连接串 / PII（含 PII 陷阱）
python demo/make_pcap.py     # 一个明文 HTTP POST 的 pcap
python -m senscan demo/samples -o demo/report -w demo/wl.txt --fail-on none
```

> `demo/samples/saas.log` 是 `make_demo_v2.py` 的生成产物，**不入库**：公开仓库若保留形似真实凭据的合成 token，会被 GitHub Push Protection（GH013）拦截。首次使用请先跑上面的生成命令；单测在样本缺失时也会自动取生成器模板，不需要手工准备。

> 完整使用手册（读报告、调优、集成、扩展规则、合规注意事项）：**[docs/USAGE.md](docs/USAGE.md)**

## 检测能力（83 条规则，来源可追溯）

规则综合了 **gitleaks**（MIT）、**secrets-patterns-db**、**detect-secrets** 的公开规则，
并补齐了它们基本空白的三块：**国内云厂商凭据**、**设备/个人信息标识符**、**嵌入式设备日志里的密钥材料**。

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

每条规则带 `source` 标注（gitleaks / secrets-patterns-db / detect-secrets / senscan），报告中可见来源统计。

## 嵌入式 / IoT 设备日志

通用 secret 扫描器（gitleaks / trufflehog / Nosey Parker）在这类日志上基本全军覆没——
它们依赖厂商前缀（`AKIA`、`ghp_`、`sk-`）或 PEM 头，而设备侧的密钥完全没有这些特征。
实测两段真实设备日志的漏报，已逐条补齐：

| 形态 | 实例 | 处理方式 |
|---|---|---|
| 值没有格式特征 | `n0W2pGZLdZt5DFnsSp627fEAtVLYR1` | 8 条三元组规则靠**字段名**锚定：完整名 / 驼峰 / 两字母缩写 / 整行结构 |
| 模块名粘连、C 指针箭头 | `config_managerproduct_key:`、`device_msg->device_secret:` | 键名不加左边界，赋值符统一支持 `:` `=` 与可选引号 |
| 两字母缩写歧义 | `PK=… DN=… DS=…` | 只在同行出现 `triplet` / `device_secret` 等**强语境词**时提权过线；孤立 `DS=`、数据库主键、LDAP DN 均不报 |
| 串口按列宽硬折行 | `dev` + 换行 + `Secret":`、`JDUNn8` + 换行 + `==` | 键名分隔符允许软换行；值跨行捕获后去空白还原 |
| 无 PEM 头的裸密钥 | `"PublicKey":"MEkwEwYHKoZIzj0CAQYI…"` | ASN.1 DER 前缀 + base64 解码首字节 `0x30` 硬校验，判定为「已校验」 |

**三元组齐备是独立结论。** 同一来源同时出现 PK/DN/DS 时，报告顶部出现红色警示条、
明细表打「三元组」标记、处置建议升级为「必须在 IoT 平台作废并轮换设备密钥，仅删除日志无效」。
三者齐备即可完整仿冒设备接入 MQTT、订阅下行指令、伪造上行数据并触发 OTA，
比单条密钥泄露严重得多。复核时先看这一条，再看单条命中。

## 验证状态与处置批次

每条命中带**验证状态**，这是本工具区别于"正则玩具"的核心：

| 状态 | 含义 | 评审动作 |
|---|---|---|
| `checksum` 已校验 | 数学或结构证据：Luhn、GB 11643、JWT 可解析、PEM 有密钥体、ASN.1 DER 前缀 + base64 解码、Base64 解出 user:pass | **不必讨论真假**，直接确认影响面 |
| `context` 上下文 | 格式成立且同行出现字段名（`oaid=`、`imei=`） | 抽查 |
| `format` 仅格式 | 只命中形态 | 按风险分排序复核 |

风险 × 置信度合成**处置批次**：`P0`（严重级别或已校验高危凭据，立即处置）、`P1`（本迭代）、`P2`（排期/常规治理）。

## 存活验证：从「像不像凭据」到「这凭据还能不能用」

三层，风险与能力严格分开（完整边界见 [docs/USAGE.md](docs/USAGE.md)）：

| 层 | 默认 | 做什么 |
|---|---|---|
| **离线结构验证** | `--verify-local` 开启 | JWT `exp` 是否过期 / `alg=none`、PEM DER 结构自洽且是否加密、签名 URL 有效期、AWS `ASIA` 临时凭据、Stripe `sk_test_`、身份证与卡组织解析。**不联网、无副作用** |
| **在线只读验证** | **关闭**，须显式授权 | 调厂商只读端点判断凭据是否仍被接受：GitHub `/user`、GitLab `/api/v4/user`、Slack `auth.test`、OpenAI `/v1/models`、Stripe `/v1/balance`、npm `/-/whoami`、HuggingFace、Telegram `getMe`、Notion |
| **内网验证代理** | 自定义 | 阿里云/腾讯云/华为云 AK/SK、微信 AppSecret 需构造厂商签名请求，单 token 无法验证；配置自建验证服务，凭据不出内网 |

```bash
python -m senscan ./logs --verify-local -o reports          # 日常推荐
python -m senscan ./logs --verify-online \
  --verify-endpoints github-user,openai-models \
  --allow-public-endpoints --verify-audit audit.jsonl       # 需授权
python -m senscan ./logs --verify-config verify.json        # 可挂内网代理
```

**在线层的硬约束**：端点白名单 + host 二次校验、禁止重定向（防 302 把凭据带到别的域）、超时/QPS/单次上限、同值只验一次、审计日志只记 `sha256` 前 16 位不记原值。**Webhook 类一律不做**——调用会真的投递消息，对第三方产生副作用；网络失败记「未验证」，绝不记「已失效」。在线确认仍有效的命中强制升 P0。

## 可视化工作台

```bash
python -m senscan ui                        # 默认 8777 端口，自动开浏览器
python -m senscan ui --port 9000 --no-browser
```

左侧配置路径/阈值/白名单/验证，右侧四个页签：概览、明细、规则、审计；一键导出四种报告。扫描中显示 `已完成/总数` 文件进度，可随时停止；「隐藏值」统一作用于列表、详情、复制与概览扩散面。仅监听 `127.0.0.1`，Host 白名单 + 一次性 token 防止第三方页面静默读取含明文凭据的结果。在线验证需勾选授权并输入确认短语才会生效。

## 降噪机制（这是能不能用的关键）

**三档打分**，最终 `confidence ∈ [0, 0.97]`：

```
格式分(base)  +  软校验加分(entropy)  +  上下文提权  -  占位符降权
```

四道硬闸：

1. **硬校验**不通过直接丢弃。IMEI 的 Luhn、MAC 的组播位、JWT header 可解析、身份证 GB 11643。
2. **上下文强制**。裸 UUID、裸 hash、无卡号字段名的 16 位数字必须同行出现关键词——否则与 `request_id`、git commit、文件校验和无法区分。
3. **占位符识别**。`example-*`、`your_key`、`******`、`${VAR}`、`000000`、`abcabcabc` 一律降权出局。
4. **冲突消解**。同一值被多条规则命中（15 位数字同时像 IMEI/IMSI、UUID 同时像 OAID/IDFA）只保留最可信的一条；同位置短值是长值子串时（PEM 头 vs 完整块、JDBC 内嵌 password vs 整条连接串）只报信息量大的。

**上下文严格限制在同一行**。跨行取样会让相邻行的 `device_id` 字样污染判定，这是实测中最主要的假提权来源。

真实日志里的高频假阳性均已覆盖在回归测试中：裸 UUID、裸 SHA-1、广播 MAC、IPv6、13 位时间戳、`example` 占位 token、`********` 掩码口令、`00:00:05`、固件构建号 `2026.1029.0000`（Cisco 点分 MAC 形状）、`13800138000`、校验位错误的身份证、`user:password` 示例 Basic、`user@example.com`、`logo@2x.png`。

Cisco 点分格式 `xxxx.xxxx.xxxx` 与版本号/日期批次形状完全相同，因此单列一条规则：必须有 `mac`/`bssid`/`hwaddr`/`物理地址` 等上下文，且硬校验剔除年份开头的纯十进制串；冒号/连字符六段式保持裸格式上报。另外 `mac` 只是形态过滤而非校验和，不再标为「已校验」，改显示「上下文 / 仅格式」。

```bash
python -m unittest discover -s tests -v   # 89 项
```

## 报告格式

| 格式 | 用途 |
|---|---|
| `html` | **单文件、离线可开**：结论与 P0/P1/P2 处置批次、风险/类别分布、热点文件、扩散面提示、可筛选可排序可展开判定依据的明细表、口径说明。适合直接发评审 |
| `json` | 完整字段 + 类别/批次/验证/存活汇总 + 三元组齐备来源 + 热点文件 + 扩散值 + 规则目录（83 条），供程序化消费 |
| `csv` | 17 列（新增 `liveness`，含 priority/validation/category/remediation），UTF-8 BOM，Excel 直接打开 |
| `sarif` | SARIF 2.1.0，带 `security-severity`（GitHub Code Scanning 据此定级）、`help`、`rank`、结果属性 `liveness` |

**默认不脱敏**——审计需要看到真实值才能复核。需要外发时加 `--redact`。

## 白名单

```text
# 注释
192.168.1.64                 # 裸值
MAC:3c:5a:b4:1f:8e:22        # 限定实体
*.corp.example.com           # 通配符
regex:^SN2026                # 正则
```

## 退出码（CI 用）

| 码 | 含义 |
|---|---|
| 0 | 未触发阈值 |
| 2 | 命中 `--fail-on` 指定等级（默认 `high`） |
| 1 | 参数/路径/写入错误 |

```yaml
# GitHub Actions 片段
- name: 敏感数据审计
  run: |
    pip install -e .
    senscan ./build/logs -o reports --fail-on critical
- uses: actions/upload-artifact@v4
  if: always()
  with: {name: senscan-report, path: reports/}
```

## 已知边界（立项前必须对齐）

1. **加密流量只能看到元数据。** pcap 通道经 `tshark -T fields` 抽取 `http.request.full_uri` / `http.cookie` / `http.authorization` / `http.file_data` / `tcp.payload` 等字段，**明文** HTTP 的 URL、请求头、body 都能扫到。但 TLS 密文解码后控制字符占比极高，会被直接丢弃——这是协议边界，不是实现缺陷。要扫 TLS 正文，必须有 `SSLKEYLOGFILE`、终端 Agent 或 MITM 证书；后两种本身是合规决策，不能靠工具绕过。
2. **不承诺 100% 召回。** `TOKEN`/`SESSION_ID` 与随机字符串在理论上不可区分，只给置信度与验证状态，不给结论。报告措辞应为「线索」而非「确认泄露」。
3. **在线验证有明确的覆盖缺口。** 只有提供只读探测端点且能用单个 token 调用的服务才能在线验证；国内云 AK/SK、微信 AppSecret、需要签名的 API、有副作用的 webhook 都不做。没被在线验证的条目一律标记「未验证」，**不能解读为「已失效」**。
4. **工具自身产出的报告是高敏数据。** 报告含明文凭据与个人信息，需限定访问范围；对外流转前用 `--redact`。

## 扩展新实体

只加一条规则，不动执行器。规则按类别放在 `senscan/rules/` 下：

```python
# senscan/rules/pii.py 中追加
Rule(
    id="my-entity",
    entity="MY_ENTITY",
    pattern=r"...",
    risk=Risk.MEDIUM,
    base_confidence=0.6,
    category=PII,
    group=1,
    validators=("not_placeholder",),
    context_keywords=("my_field",),
    remediation="给出可执行的处置建议",
    source="senscan",
)
```

经验：`\b` 默认按 Unicode 判词，中文也算 `\w`，中英混排会漏报——编译规则时统一替换为 `(?a:\b)` 局部 ASCII 边界；能加校验和就加；随机串类一律配 `context_keywords`。新增校验算法注册到 `VALIDATORS` 即可。

## 安全边界与已知限制

- **示例数据**：`demo/samples/` 与生成器里的凭据、设备标识均为随机合成或占位值，不对应任何真实账号。仓库内不预置形似真实凭据的演示样本值——生成器在运行时拼接前缀与随机值，`saas.log` 由脚本本地生成且已被 `.gitignore` 排除。
- **报告含明文**：默认不脱敏，便于验证；外发前用 `--redact` 重新生成。`demo/report/`、`.workbuddy/`、`*.jsonl` 已被 `.gitignore` 排除，请勿手动加入版本库。
- **在线验证**：默认关闭。工作台服务端独立复核授权勾选与确认短语，`/api/scan`、`/api/verify` 都无法绕过；自定义端点只允许本机/内网，公网目标必须在 `custom_hosts` 中显式列出；进程级限速 120 次/分钟。审计日志只记值 SHA-256 前 16 位。
- **检测边界**：TLS 正文不可扫（除非 `SSLKEYLOGFILE` / MITM / Agent）；`context_hit` 只取同一物理行，键名与值分两行书写时可能漏报；本地层把「未过期签名 URL / alg=none JWT」标为「仍有效」是为了抬高处置优先级，并非在线确认。
- **CSV 安全**：以 `= + - @` 开头的单元格前置单引号，防止 Excel 公式 / DDE 注入。

## 路线图

- **P1（已完成）** 文本载体 + pcap 明文载荷；83 条规则（对齐 gitleaks / secrets-patterns-db）；三档打分 + 验证状态 + P0/P1/P2；白名单；JSON/CSV/SARIF/HTML
- **P2（已完成）** 三层存活验证器（离线结构 / 在线只读 / 内网代理）+ 本地可视化工作台 + 存活状态贯穿四种报告
- **P2.5（已完成）** 嵌入式/IoT 日志：设备三元组（含缩写与硬折行）、无 PEM 头的裸 DER 密钥、三元组齐备结论贯穿报告与工作台
- **P3** `--diff` 基线增量比对；HTTP/2 明文帧与 gRPC-Web 文本载荷；Yakit 插件、实时旁路（配合 SSLKEYLOGFILE）、固件构建钩子

## 结构

```
senscan/
  models.py      风险等级 / 类别 / 规则 / 发现项（含处置批次与验证状态）
  utils.py       校验算法（Luhn/GB11643/号段/JWT/PEM/连接串…）、熵、占位符
  rules/         规则包：credentials.py / keys.py（裸 DER 密钥）/ iot.py（设备三元组）/
                 infra.py / pii.py / devices.py
  detectors.py   执行器：编译、硬校验、打分、冲突消解、子串去重
  pcap.py        tshark 字段抽取与 hex 载荷解码
  scanner.py     遍历、二进制跳过、大文件分块、合并、白名单
  whitelist.py   白名单
  verify.py      三层存活验证器：本地结构 / 在线只读端点 / 自定义内网代理
  report.py      json / csv / sarif / 控制台（含存活状态）
  report_html.py 单文件 HTML 报告
  webui.py       本地可视化工作台服务（标准库 http.server + JSON API）
  web/index.html 单页前端（零外部依赖）
  cli.py         命令行 + `senscan ui` 子命令
docs/            使用手册
demo/            样本生成器（日志 + pcap）与样本
tests/           101 项回归测试（假阳性、pcap、报告、XSS、验证策略、mock 在线端点、
                 IoT 缩写/折行、DER 结构校验、三元组结论）
```
