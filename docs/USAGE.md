# senscan 使用手册

面向两类读者：**做评审的人**（看报告、判风险）和**做集成的人**（接 CI、调规则）。
安装与命令速查见 [README](../README.md)，本文讲怎么用对、怎么用在流程里。

---

## 一、它做什么，不做什么

| 能做 | 不能做 |
|---|---|
| 从日志、配置、埋点 JSON、固件解压产物中提取凭据与设备标识 | 判断某条数据是否构成"违法处理" |
| 从 pcap 中提取**明文** HTTP 的 URL / Header / Body | 解密 TLS 流量正文 |
| 给出置信度、风险等级、文件与行列定位、上下文片段 | 保证 100% 召回 |
| 导出 CSV 交评审、SARIF 进 CI、HTML 给汇报 | 替代人工复核 |
| 白名单放行已知安全项 | 自动修复泄露 |

一句话定位：**它是一个"线索发现器"，不是"结论生成器"。** 报告里每一条都应该能被人工复核，否则那条规则就该调。

---

## 二、安装

```bash
# 基础功能（纯标准库，无第三方依赖）
pip install -e .

# 需要扫 pcap 时额外要求（Windows 装 Wireshark 即自带）
tshark -v
```

要求 Python 3.10+。pcap 解析会自动查找 `tshark`：先查 `PATH`，再查 Wireshark 常见安装路径。找不到时 pcap 文件会被跳过并在"跳过原因"里注明，不会中断扫描。

---

## 三、三个上手场景

### 场景 1：审一份 App 端日志

```bash
senscan ./app-logs -o reports
```

先看控制台摘要，重点看这一行的三段数字：

```
候选 4821  →  校验淘汰 3120  →  压制 1480  →  白名单 0  →  输出 221
```

- 候选 4821，最后只剩 221 —— 说明降噪在起作用。**如果输出接近候选数，说明规则太宽**，先别急着交报告。
- 「压制」是被上下文校验拦下的（比如裸 UUID 没有 `oaid=` 前缀），这个数字大是好事。

### 场景 2：审一份抓包

```bash
senscan capture.pcap -o reports
```

报告里的「位置」是**帧号**，拿这个号直接去 Wireshark 里 `frame.number == 42` 就能定位到原始包。

注意：**只有明文 HTTP 能扫到内容。** 如果输出为 0，先用 tshark 确认抓包里到底有没有明文：

```bash
tshark -r capture.pcap -Y "http.request" -T fields -e frame.number -e http.host | head
```

一条都没有，说明流量是加密的，这不是工具的问题，见第八节。

### 场景 3：接进 CI

```bash
senscan ./build/logs --fail-on critical --no-report
echo $?   # 0 = 通过, 2 = 发现严重问题
```

`--no-report` 只判不写，适合流水线里的门禁步骤。要留证据就带上报告。

---

## 四、命令行参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `paths` | 必填 | 文件或目录，可多个；目录递归 |
| `-o, --outdir` | `senscan-reports` | 报告输出目录 |
| `-f, --format` | `json,csv,sarif,html` | 逗号分隔，按需裁剪 |
| `-w, --whitelist` | 无 | 白名单文件 |
| `-m, --min-confidence` | `0.55` | 置信度阈值，低于此值不上报 |
| `--fail-on` | `high` | 触发退出码 2 的最低等级：`critical/high/medium/low/none` |
| `--redact` | 关 | 报告中的值与上下文脱敏 |
| `--include-binary` | 关 | 不跳过二进制文件（固件场景慎用，噪声极大） |
| `--no-pcap` | 关 | 关闭 pcap 解析通道 |
| `--max-file-mb` | `512` | 单文件上限，超出则按行分块流式处理 |
| `--top` | `20` | 控制台最多展示条数 |
| `--no-report` | 关 | 只打印，不落盘 |
| `-q, --quiet` | 关 | 只输出一行统计，适合脚本调用 |
| `--verify-local` | 关 | 离线结构验证：JWT 有效期、PEM、签名 URL 过期等，不联网 |
| `--verify-online` | 关 | 开启在线存活验证，必须同时授权端点或给 `--verify-config` |
| `--verify-endpoints` | 空 | 启用的内置只读端点 id，逗号分隔 |
| `--allow-public-endpoints` | 关 | 显式授权向公网只读端点发送凭据 |
| `--verify-config` | 无 | 验证配置 JSON（端点、限速、上限、审计路径、自定义代理） |
| `--verify-audit` | 自动生成 | 在线验证审计日志路径 |

另有子命令 `senscan ui [--port 8777] [--no-browser]`，启动可视化工作台（见第十一节）。

退出码：`0` 未触发阈值 / `2` 触发 `--fail-on` / `1` 参数或读写错误。

---

## 五、怎么读报告

### 5.0 先看结论区：验证状态与处置批次

报告（HTML/JSON/CSV）里每条命中带两个新维度，先理解它们能省一半沟通成本：

**验证状态**——"这条有多可能是真的"的证据强度：

| 状态 | 含义 | 评审动作 |
|---|---|---|
| `已校验` (checksum) | 通过数学/结构证据：Luhn、GB 11643 身份证、JWT header 可解析、PEM 有密钥体、Base64 能解出 user:pass、连接串口令非占位 | **不用再讨论真假**，直接确认影响面、进入处置 |
| `上下文` (context) | 格式成立且同行出现字段名（`oaid=`、`imei=`、`card_no=`） | 抽查即可，误报率低 |
| `仅格式` (format) | 只命中形态 | 按风险分排序复核 |

手机号、IMEI/IMSI、MAC、LTK、邮箱没有校验位，最高只到「上下文」——号段白名单、长度+MCC 前缀、32 位 hex 都只是形态过滤，不是校验和。以下三类默认不进报告，需要捞线索时把阈值调低（`--min-confidence 0.35`），会以「仅格式」出现：

- 数值语义字段：`size` / `bytes` / `count` / `timestamp` / `用户数` / 订单号等，以及 JSON 里未加引号的裸数字；
- 没有字段名佐证的裸数字：手机号、IMEI、IMSI；有 `phone=` / `imei=` / `imsi=` 等字段名时正常上报；
- 官方文档示例凭据（如 `AKIAIOSFODNN7EXAMPLE`）按占位符丢弃。

上下文判定只认**当前字段**：一行里挤着多个 JSON 字段时，`{"trace":"139...","phone":"..."}` 里的 `phone` 不会给 `trace` 提权。自由文本（如 IoT 三元组日志）仍按整行语境判断，避免砍掉真实召回。

**中文键名与常见写法**——同一句话里的键名可能有四种写法，全部识别：

| 写法 | 样例 |
|---|---|
| 英文 | `db_password=xxx`、`device_secret: xxx` |
| 带前缀 | `db_password`、`user_login_password`（`_` 前缀不会被 `\b` 挡住） |
| 中文 | `数据库密码：xxx`、`设备密钥＝xxx`、`序列号:xxx`、`蓝牙密钥:xxx` |
| 全角分隔符 | 全角冒号 `：`、全角等号 `＝` |

`密码策略:`、`密钥管理:`、`令牌桶限流:`、`序列号规则:` 这类说明文字不会被当成凭据——键名后带策略/强度/管理之类后缀时直接跳过。

**处置批次**——风险 × 置信度合成后的执行顺序：

- **P0**：严重级别（私钥、云厂商 Secret、身份证、银行卡）或已校验的高危凭据 → 立即处置
- **P1**：高危但需人工确认，或中危且已校验 → 本迭代
- **P2**：低危或仅格式匹配的线索 → 排期/常规治理

报告首页的"结论与处置批次"区会把 P0 的前 3 条直接列出来并附处置建议；"热点文件"告诉你从哪漏的；"扩散面"列出**同一凭据出现在多个文件**的情况——这类不能只删一处日志，要按源头—副本逐处清理并轮换。

### 5.1 风险等级不等于置信度

两个维度要分开看：

- **风险等级**由实体类型决定，与命中上下文无关。私钥就是 critical，MAC 就是 low。
- **置信度**是判定这条**真的是**该实体的把握，0–0.97。

所以会出现「低置信度的高危项」——例如一段像私钥的字符串但没找到完整块头。**这类要人工看一眼再决定**，别直接按等级排序处理。

报告表格默认按 `风险分 × 置信度` 排序，就是为了让"高危且确定"的排最前面；点列头可改按优先级/实体/位置排序。

### 5.2 置信度是打分，不是概率

```
置信度 = 格式分 + 校验加分 + 上下文提权 − 占位符降权
```

它只用于**排序和分层复核**，不能说"0.9 意味着 90% 概率是真泄露"。同一类实体在不同上下文下的分差才是有意义的信号。

明细表每条可展开「判定依据 / 处置」：判定链（哪条规则、过了什么校验、上下文命中的关键词）、处置建议、原文上下文、归一化值。评审人不需要翻文档就能理解这条为什么被报出来。

### 5.3 四个统计数字的含义

| 数字 | 含义 | 异常时的处置 |
|---|---|---|
| 候选 | 格式命中总数 | 过小说明规则覆盖不足 |
| 校验淘汰 | 硬校验未过（Luhn、GB 11643、组播 MAC、JWT 结构） | 正常应有相当比例 |
| 缺上下文压制 | 裸 UUID、无卡号字段名的 16 位数字等被主动丢弃 | 这个数为 0 说明上下文规则没生效 |
| 低置信压制 | 分数低于阈值 | 阈值调高的直接后果 |
| 白名单 | 被放行的命中 | 突然暴涨说明白名单被写宽了 |

### 5.4 报告格式怎么选

| 场合 | 用哪个 |
|---|---|
| 自己快速看 | 控制台摘要（含 P0 提示） |
| 交合规评审、走 Excel 归档 | `csv`（17 列，含 priority/validation/**liveness**/category/remediation，UTF-8 BOM） |
| 给管理层汇报 | `html`（单文件，双击即开，可筛选排序） |
| 进 GitHub/GitLab Code Scanning | `sarif`（带 `security-severity`，平台自动定级） |
| 二次处理、接 SIEM | `json`（含类别/批次汇总、热点文件、扩散值、规则目录） |

HTML 报告是单文件、无外部依赖，可以直接邮件发送——**但它含明文凭据**，发之前想清楚。

### 5.5 证据 ≠ 存活

这是两个独立维度，别混着读：

- **证据**（已校验 / 上下文 / 仅格式）：这条**是不是真的**。
- **存活**（仍有效 / 已失效 / 已过期 / 结构有效 / 未验证 / 不适用）：这凭据**还能不能用**。

明细表两列并列展示；点开「详情」可看到存活验证的具体结论与依据。启用验证后，HTML 顶部会出现「存活验证」区，列出各状态数量、端点、审计日志路径。「口径说明」默认折叠，需要时展开。

**最关键的一条口径**：网络失败、超上限、未配置端点都记为「未验证」，**绝不能当成「已失效」**。把 unknown 误读成 inactive，是这套功能最危险的误用。

---

## 六、白名单

### 6.1 语法

```text
# 空行和 # 开头是注释
192.168.1.64                  # 裸值：所有实体中等于该值的都放行
MAC:3c:5a:b4:1f:8e:22         # 限定实体
*.corp.example.com            # 通配符
regex:^SN2026                 # 正则（对原始值和归一化值都试）
```

匹配顺序不分优先级，命中任意一条即放行。实体名写在冒号前，必须大写。

### 6.2 怎么维护

建议按来源分文件，不要把所有东西堆一个文件：

```bash
senscan ./logs -w wl/baseline.txt     # 团队共识的安全项
# 新增条目走 review，别让个人随手加
```

两个常见误用：

- **把"不方便处理"的命中加进白名单。** 白名单应该只装"确认安全"的项，装"暂时不管"的项等于自欺欺人。
- **用正则兜底太多。** `regex:.*test.*` 这种会把真泄露一起放行。

---

## 七、集成

### 7.1 CI 门禁

```yaml
- name: 敏感数据审计
  run: |
    pip install -e .
    senscan ./build/logs -o reports --fail-on critical
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: senscan-report
    path: reports/
```

**建议入门用 `critical` 而不是 `high`。** 一开始就把门禁设太严，流水线天天红，最后所有人都会加 `|| true`，等于没有门禁。等基线稳定再收紧。

### 7.2 固件构建

在镜像打包前扫构建产物里的日志与配置：

```bash
senscan ./rootfs/etc ./rootfs/var/log -o reports --fail-on critical --format json,sarif
```

固件目录里二进制很多，默认会跳过——这正是想要的行为。真要看二进制里的字符串，先解出来再扫，别直接用 `--include-binary`。

### 7.3 定时巡检

用系统计划任务每天扫一次日志目录，报告带日期落盘，只对新出现的项告警（P2 会提供 `--diff`，当前可自行比对两次 JSON）。

---

## 八、调优与排错

### 误报太多

按这个顺序调：

1. 提高阈值：`-m 0.7`
2. 加白名单放行已知项
3. 检查是不是 `--include-binary` 打开了
4. 到 `senscan/rules/` 对应类别文件里收紧该规则的 `pattern` 或加 `context_required=True`

**不要**直接删规则——删除会同时丢掉召回。

### 漏报

1. 降阈值：`-m 0.4`，看是不是被阈值卡掉的
2. 看「压制」数，若为 0 说明上下文规则把候选全拦了
3. 确认数据载体：被 `.gitignore` 之外的因素漏掉的文件？编码问题？
4. 该实体类型可能不在规则表里，见第九节

### pcap 扫不到内容

依次确认：

```bash
# 1. tshark 可用
tshark -v

# 2. 抓包里有没有明文 HTTP
tshark -r x.pcap -Y "http" -T fields -e frame.number | head

# 3. 是不是只在 TLS 里
tshark -r x.pcap -Y "tls.handshake" -T fields -e tls.handshake.extensions_server_name | head
```

第 2 条有输出但 senscan 没命中 → 规则覆盖问题；第 2 条没输出、第 3 条有输出 → 流量全加密，正常。

### 编码问题

日志是 GBK/GB18030 时会自动回退解码。若出现乱码：

```python
from senscan.utils import read_text
text, enc = read_text(Path("x.log"))   # enc 告诉你实际用了什么编码
```

`latin-1` 是最后的兜底，用它可以读任何字节但中文会乱——看到这个就要检查源文件编码了。

---

## 九、扩展规则

规则按类别放在 `senscan/rules/` 下（credentials / infra / pii / devices），每条规则建议标注 `source`（借鉴自哪个开源规则集）与 `remediation`（处置建议会直接进报告）。

### 加一类实体

在对应类别文件里追加：

```python
Rule(
    id="bank-card",
    entity="BANK_CARD",
    pattern=r"(?<!\d)(\d{16,19})(?!\d)",
    risk=Risk.HIGH,
    base_confidence=0.5,
    group=1,                          # 取值用第几个捕获组
    validators=("luhn",),             # 硬校验，不过即丢弃
    bonus_validators=("entropy",),    # 软校验，过了加分
    context_keywords=("card", "卡号", "pan"),
    context_required=False,           # True = 没有上下文一律不报
    note="银行卡号",
)
```

三条经验：

1. **正则尾部别用 `\b`。** 中文也是 `\w`，`\b` 在"数字后紧跟中文"时不成立。用 `(?!\d)` / `(?![0-9A-Fa-f])`。
2. **能加校验和就加。** Luhn 把误报砍掉一个数量级。
3. **随机串类实体一律 `context_required=True`。** 没有上下文就交给人工，等于没报。

### 加一个校验算法

在 `detectors.py` 的 `VALIDATORS` 里注册一个 `Callable[[str], bool]`，然后规则里引用名字即可。
能给出数学/结构证据的（校验和、可解码）记得加进 `STRONG_VALIDATORS`，命中的会标为「已校验」。

改完跑一遍：

```bash
python -m unittest discover -s tests
```

测试里有一条"规则引用的校验器必须存在"的守卫（`test_validators_registry_complete`），
拼错校验器名字会直接测试失败，不会静默失效。

---

## 十、合规注意事项

1. **报告本身是高敏数据。** 含明文凭据与个人信息，等同于把泄露面复制了一份。存放目录要限权、要留访问记录，别放共享盘。
2. **对外流转前加 `--redact`。** 保留前 4 后 4 位，足够对方核对是不是那一条。
3. **扫描行为本身需要授权。** 扫生产日志、抓包镜像属于对信息系统的操作，走变更或安全测试授权流程。
4. **不要把工具输出直接当处罚依据。** 置信度是排序信号，处置前必须人工确认。
5. **发现真实泄露后按事件流程走。** 这份报告可能成为证据材料，注意生成时间、版本号（报告页脚有）的可追溯性。
6. **在线验证是一次独立的、需要单独授权的测试动作。** 它等于拿抓到的凭据去登录对方服务。即使端点只读，也可能在对方审计日志里留下记录、触发风控或告警；跨境调用还涉及数据出境问题。做之前确认：目标账户属于你方或已获书面授权、测试窗口已报备、对端日志留存要求已确认。
7. **审计日志本身要留痕但不扩散。** `verify-audit.jsonl` 只记值 hash、端点、状态、耗时，不含原值；但它能反推出"哪些凭据在什么时候被验证过"，仍需按内部日志的保管要求管理。

---

## 附：当前能力边界速查

| 载体 | 支持 | 说明 |
|---|---|---|
| 日志 / 配置 / 文本 | ✅ | 自动识别 UTF-8 / GB18030 / UTF-16 |
| 埋点 JSON | ✅ | 支持 `"key": "value"` 与 `key=value` 两种写法 |
| pcap / pcapng | ✅ 明文 HTTP | 需 tshark；TLS 正文不可见 |
| 固件解压产物 | ✅ 文本部分 | 二进制默认跳过 |
| 压缩包（zip/tar） | ❌ | 先解压 |
| 数据库 / 对象存储 | ❌ | 先导出 |
| 嵌入式 / IoT 设备日志（三元组、密钥分区 dump） | ✅ | 支持缩写字段名、串口硬折行、无 PEM 头的 DER base64 |
| 凭据存活验证（离线） | ✅ | 默认关闭，`--verify-local` 开启；不联网 |
| 凭据存活验证（在线） | ⚠️ 部分 | 仅只读端点、须显式授权；webhook / 需签名 API 不支持 |


---

## 十一、可视化工作台

```bash
python -m senscan ui                          # 打开 http://127.0.0.1:8777
python -m senscan ui --port 9000 --no-browser
python -m senscan ui --audit D:/audit/verify.jsonl
```

**页面结构**：左侧配置（路径、浏览、置信度、抓包/二进制/脱敏开关、白名单、验证、导出），右侧四个页签。

| 页签 | 内容 |
|---|---|
| 概览 | 4 个 KPI、风险横条、类别环形图、P0/P1/P2 批次、降噪漏斗、验证摘要、热点文件、扩散面 |
| 明细 | 按风险/批次/类别/实体/存活筛选 + 搜索 + 5 列可排序 + 分页（每页 20）；点行开抽屉看命中值、判定依据、建议、验证结论。「隐藏值」同时作用于列表、概览扩散面、详情与复制，不影响导出与原始数据 |
| 规则 | 83 条规则可搜索，含风险、来源、说明 |
| 审计 | JSONL 日志（时间/端点/实体/指纹/结果/HTTP/耗时/Host）与端点目录 |

打开页面会恢复本次进程内最近一次扫描结果；没有结果时点「运行示例」。扫描中显示 `已完成/总数` 文件进度，可点「停止」中止；进度查询超过 10 分钟自动停止轮询。目录浏览里点文件即把该文件加入目标，不必手打路径。

**安全边界**：只监听 `127.0.0.1`；每个启动进程生成一次性 token 注入页面，所有 `/api/*` 请求必须携带；Host 头白名单挡 DNS rebinding；不设置任何 CORS 头，CSP 只允许本页内联脚本与同源连接；扫描结果保存在**进程内存**，只有点导出时才生成文件。服务停掉后界面数据即消失，需要留档请导出报告。

---

## 十二、存活验证与在线验证器

### 12.1 三层，什么时候用哪层

| 层 | 网络行为 | 能回答 | 不能回答 |
|---|---|---|---|
| 离线结构验证 | 无 | JWT 是否过期、`alg` 是否 `none`、PEM DER 是否自洽/加密、签名 URL 是否过有效期、AWS `ASIA` 临时凭据、Stripe 测试密钥、身份证/卡组织解析 | 凭据是否仍被服务端接受 |
| 在线只读验证 | 向白名单端点发一次带凭据的只读请求 | 服务端是否还认这个 token | 权限范围有多大、是否被盗用 |
| 内网验证代理 | 凭据只发到你自建的服务 | 国内云 AK/SK、微信 AppSecret 等需签名请求的场景 | — |

**默认只做离线层**。在线层是 opt-in，CLI 与界面都要求显式授权。

### 12.2 内置端点（全部只读、无副作用）

| id | 端点 | 匹配的凭据 |
|---|---|---|
| `github-user` | `GET api.github.com/user` | GitHub PAT / fine-grained PAT |
| `gitlab-user` | `GET gitlab.com/api/v4/user` | GitLab PAT |
| `slack-auth-test` | `POST slack.com/api/auth.test` | Slack Bot / App Token |
| `openai-models` | `GET api.openai.com/v1/models` | OpenAI API Key |
| `huggingface-whoami` | `GET api.huggingface.co/whoami-v2` | HF Token |
| `stripe-balance` | `GET api.stripe.com/v1/balance` | Stripe Secret Key |
| `npm-whoami` | `GET registry.npmjs.org/-/whoami` | npm Token |
| `telegram-getme` | `GET api.telegram.org/bot<token>/getMe` | Telegram Bot Token |
| `notion-users` | `GET api.notion.com/v1/users` | Notion Token |

**明确不做的**：Slack/Discord webhook（POST 会真的往频道发消息）；SendGrid / Twilio / Mailgun（无简单只读探测）；阿里云 / 腾讯云 / 华为云 / 微信（需构造厂商签名，请走自定义代理）。

### 12.3 用法

```bash
# 只开离线层（不动网络）
python -m senscan ./logs --verify-local

# 在线层：三个条件缺一不可
python -m senscan ./logs --verify-online \
  --verify-endpoints github-user,gitlab-user \
  --allow-public-endpoints --verify-audit audit.jsonl
```

配置文件方式（`--verify-config verify.json`），适合挂内网代理：

```json
{
  "local": true,
  "online": true,
  "endpoint_ids": ["github-user"],
  "allow_public": true,
  "timeout": 3.0,
  "max_checks": 20,
  "qps": 2,
  "audit_path": "audit.jsonl",
  "custom": [
    {
      "id": "internal-checker",
      "provider": "内网验证代理",
      "url": "https://verify.corp.internal/check",
      "method": "POST",
      "body": "{\"secret\": \"{{SECRET}}\"}",
      "match_rules": ["aliyun-access-key-id", "tencent-secret-id"],
      "success_codes": [200],
      "invalid_codes": [401, 403]
    }
  ]
}
```

`{{SECRET}}` 是唯一允许替换凭据的占位符；自定义端点必须 https（或 `http://127.0.0.1`）。`match_rules` 支持 `aliyun-*` 这类前缀通配。

自定义端点默认只允许本机、`127.0.0.1`、RFC1918 私网地址及 `.internal` / `.local` / `.corp` 等内网域名；若确实需要指向公网验证代理，须在配置里显式声明 `custom_hosts: ["verify.example.com"]`，否则策略校验直接拒绝（防止把凭据外带到任意主机）。工作台还会独立复核授权勾选与确认短语「允许在线验证」，前端勾选不构成授权。

### 12.4 策略守卫（实现层面，不是口号）

- 未配置任何端点就拒绝启动在线验证；使用公网内置端点还必须 `allow_public=true`；
- 请求发出前二次校验目标 host 在允许列表；**禁止重定向**，防止 302 把凭据带到别的域；
- 同值按 `sha256` 只验一次；`max_checks` 默认 50、界面默认 20；QPS 默认 2；单次超时 3 秒；
- 本地层已判定「已过期」的不再外发，避免无意义请求；
- 审计日志每行只记 `value_sha256`（前 16 位）、端点、实体、规则、状态、HTTP 码、耗时、host，**不写原值**；
- 网络不可达 / 超时 / 429 / 5xx 一律 `unknown`；只有服务端明确 401/403/404 才记 `inactive`；
- 在线确认 `active` 的命中**强制 P0**，报告与界面都会重排。

### 12.5 什么时候不该开在线验证

- 凭据来自客户/第三方系统，且没有书面测试授权；
- 目标服务在境外，而凭据或验证结果涉及境内个人信息，出境合规性未评估；
- 无法承受"对方看到一次异常登录"的后果（会触发告警、锁定账号、污染对方审计日志）；
- 只是想确认"这个值是不是真的"——用离线层的校验和就够，不需要联网。

这些场景**只开 `--verify-local`**，把在线验证留给有明确授权与测试窗口的专项核查。


---

## 十三、嵌入式 / IoT 设备日志

这一节针对实测中漏报的两类真实设备日志。它们的共同点是：**值本身没有任何格式特征**，
不能用"看起来像密钥"来判断，只能靠字段名与密钥的二进制结构。

### 13.1 设备三元组（一机一密）

```
config_managerproduct_key: NFsjvbSelFOzEwWOxSKq      ← 模块名与字段名粘连
device_msg->device_secret: n0W2pGZLdZt5DFnsSp627fEA   ← C 指针箭头
Using device triplet: PK=..., DN=..., DS=...          ← 两字母缩写
```

| 键 | 识别的写法 | 定级 |
|---|---|---|
| DeviceSecret | `device_secret` / `deviceSecret` / `devSecret` / `device key` / `DS=` | critical |
| ProductKey | `product_key` / `productKey` / `prodKey` / `PK=` | low |
| DeviceName | `device_name` / `deviceName` / `device name` / `client_id` / `DN=` | medium |

**缩写为什么需要语境**：`PK` / `DN` / `DS` 在通用日志里可能是 primary key、
LDAP distinguished name、data source。规则把缩写的基础置信度压到默认阈值以下，
只有**同一行**出现 `triplet` / `device_secret` / `product_key` / `mqtt` / `alink` 等
强语境词才提权过线。所以：

- `Using device triplet: PK=…, DN=…, DS=…` → 三条都报；
- 孤立 `DS=xxx`、数据库 `PK=12345678, DN=row_0001`、LDAP `DN=cn=admin,...` → 不报。

想看这些弱线索，把阈值调低：`senscan ./logs -m 0.4`。

> 实现上有个容易踩的坑：**不能把缩写键名自己放进语境词表**。`DS=xxx` 的原文里
> 天然含 `ds=`，会自己给自己提权。同理，语境词也不能用 `iot` 这种短词
> （会命中 riot / idiot / pilot）。当前实现已把两者都排除。

### 13.2 串口日志的硬折行

设备串口按列宽硬换行，会把键名和值拆到两行：

```
...,"dev
Secret":"n0W2pGZLdZt5DFnsSp627fEAtVLYR1",...
"PrivateKey":"JDUNn8
==","PublicKey":"MEkwEwYHKoZIzj0CAQYI...
```

键名规则的分隔符允许一个软换行，值捕获允许跨行并在打分前去掉空白还原。
**报告里的「位置」是折行前的行号**，上下文片段会保留原始折行，复核时按上下文看即可。

### 13.3 没有 PEM 头的密钥材料

设备把密钥分区整块 base64 dump 出来，没有 `-----BEGIN PRIVATE KEY-----`：

```json
{"PrivateKey":"…","PublicKey":"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"}
```

识别两条路：

- **字段名**：`PrivateKey` / `privateKey` / `private_key` / `PublicKey` / `publicKey` 等，
  值允许 base64 字符集与跨行；
- **结构**：ASN.1 DER 的固定前缀（PKCS#1 / PKCS#8 / SEC1 / Ed25519 / EC·RSA SPKI），
  再加一道硬校验——base64 解码后首字节必须是 `0x30`（SEQUENCE）。
  通过的命中标记「已校验」，不必再讨论真假。

裸公钥定 **low**：公钥本身不涉密，但它出现在日志里通常意味着「整个密钥分区被打印了」，
是同批存在私钥的强线索，处置建议里写明了要确认同批日志。

### 13.4 三元组齐备：一个比单条密钥更重要的结论

同一来源文件里同时发现 ProductKey / DeviceName / DeviceSecret 时，
工具会额外做三件事：

1. HTML 报告顶部出现红色**「设备三元组完整泄露」**警示条，可视化工作台概览页同步提示；
2. 明细表这三行打「三元组」标记，判定依据里追加说明，JSON 的
   `summary.iot_triplet_files` 列出齐备的来源文件；
3. DeviceSecret 的处置建议升级为：**必须在 IoT 平台停用并轮换该密钥**，
   排查 MQTT 会话、设备影子与 OTA 记录——单纯删除日志不构成处置。

合规口径上，这一条建议单独写进结论：三者齐备即可以该设备身份接入平台、
订阅下行指令、伪造上行数据，风险不是三条 low/critical 命中简单相加。

### 13.5 复现

```bash
python demo/make_demo.py && python demo/make_pcap.py && python demo/make_demo_v2.py
python -m senscan demo/samples -o demo/report --verify-local --fail-on none
```

`demo/samples/iot-device.log` 与 `param-part.log` 是两类日志的同构样本
（值均为编造假值）；`iot-traps.log`、`traps-pii.log`、`traps.log` 是误报陷阱，
正常应全部零命中。
