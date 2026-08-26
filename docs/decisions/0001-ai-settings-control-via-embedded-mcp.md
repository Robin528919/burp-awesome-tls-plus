# ADR-0001：通过内嵌 MCP 实现 AI Settings Control

- 状态：Accepted / Locked（2026-08-25 经用户明确批准修订一次，见 §22）
- 实现状态：Implemented（2026-08-25）。除第 17.3 节要求的 Codex Desktop / Codex CLI 真实 Burp E2E 外，本文锁定的行为均已实现并有可复核的自动检查；详见 §21 实现记录
- 日期：2026-08-25
- 范围：Burp 扩展内的设置查看、AI 修改提议、Burp 本地审批及其运行保障
- 规范性：本文是该功能的开发与验收合同；改变已接受决策必须取得用户明确批准并同步更新本文与仓库根目录 `AGENTS.md`

## 1. 决策摘要

在 Burp 扩展进程内嵌一个仅监听本机回环地址的 MCP Streamable HTTP adapter，并在其后建立唯一的 `SettingsControl` 模块。AI 只能查看设置和提交修改提议；用户只能在 Burp UI 中批准、拒绝或撤销，AI 永远不能直接应用设置。

首版是面向所有扩展用户的正式功能，但运行模型是单个 Burp 实例、单个本地用户。首要验证客户端是 Codex Desktop 和 Codex CLI；其他符合 MCP `2026-07-28` 的原生客户端仅提供 best-effort 兼容。浏览器型客户端明确不支持。

本设计接受一个显式风险：MCP 不使用 Token、OAuth 或其他认证，并默认向调用方返回完整代理凭据和完整 Hex ClientHello。绑定回环地址并不代表秘密不会泄露给本机其他进程，因此每次启用时必须向用户显示这一事实。

## 2. 目标与非目标

### 2.1 目标

- AI 能查看当前已提交的全部业务设置、有效 domain rules、可用指纹、运行影响和待审批状态。
- AI 能提交语义化设置 patch，并得到完整 diff、校验结果和运行影响。
- 用户能在 Burp 内审查并原子批准或拒绝整份提议。
- UI、MCP 和请求热路径读取同一个已提交设置模型，避免校验、缓存和持久化分叉。
- Preferences 与 `rules.json` 任一写入失败时，不向请求线程发布混合或半完成状态。
- AI 查看和提议不得进行 DNS 查询、连接目标、发送代理请求或产生其他目标侧网络流量。

### 2.2 非目标

首版不提供：

- AI 可调用的 apply、commit、approve、reject 或 revert tool；
  **（2026-08-25 修订：见 §22。仍不提供 AI 可调用的 apply/approve/reject/revert tool；但新增用户在 Burp 中手动开启的 auto-apply 开关，开启期间 propose 通过校验后立即提交。）**
- 无人值守、可信客户端或自动批准模式；
  **（2026-08-25 修订：见 §22。auto-apply 是会话级、默认关闭、需二次确认的自动批准模式。）**
- 远程监听、`0.0.0.0`、浏览器 CORS 接入或通用远程控制平面；
- Token、OAuth 或可选认证模式；
- 任意 Preferences key、文件路径、命令、JSON Patch 路径或原始 `TransportConfig` 写入；
- 完整历史版本恢复；
- 将 Preferences 与 `rules.json` 迁移成单一存储；
- 为该功能修改 Java/Go `TransportConfig` 字段合同。

上述任一能力都需要新的架构决策和用户明确批准。

## 3. 总体架构

```text
Codex Desktop / CLI
        │ MCP 2026-07-28: inspect / propose
        ▼
Embedded MCP adapter ───────┐
                            ▼
SettingsTab adapter ──> SettingsControl
                            │
                 ┌──────────┼──────────┐
                 ▼          ▼          ▼
          Preferences   RuleStore   Audit / WAL
                 └──────────┬──────────┘
                            ▼
       Atomic committed snapshot + matching RuleMatcher
                            │
                            ▼
                     request hot path
```

`SettingsControl` 是设置能力的唯一深层 seam，位于 `Settings`、Montoya `Preferences`、`RuleStore` 和 `SettingsTab` 之上。Swing 与 MCP 都是 adapter，必须共用以下实现：

- immutable committed snapshot；
- canonical normalization 与 revision；
- 设置及 domain-rule 校验；
- semantic patch、diff 与风险分类；
- proposal 生命周期与并发检查；
- 持久化、补偿、恢复与审计；
- runtime impact 计算；
- 设置变更通知和 EDT 刷新。

请求热路径只读内存。已提交设置和预编译的 `RuleMatcher` 必须放在同一个原子/volatile holder 中一次发布，使请求线程只能看到完整旧版本或完整新版本。

Configured/active 判断不能靠 Java 猜测。实现必须增加独立的 `RuntimeStatePort` 和 Go/JNA status adapter，允许新增类似 `GetRuntimeStatus` 的只读 bridge，但它必须与 request `TransportConfig` 完全分离，不得给 `TransportConfig` 加字段。Go 侧维护同步保护的 immutable runtime snapshot，至少包含 spoof listener 的 `STARTING/RUNNING/STOPPED/FAILED`、实际 bind address/last error，以及 intercept proxy 的同类状态、实际 intercept address、Go 当前实际采用的 Burp upstream endpoint/last error。该 upstream endpoint 不是 Burp Proxy listener 的实际 bind interface；当前 Montoya API 不提供该值，UI、inspect 和预检必须把它标为 unavailable，而不能猜测 Burp 实际绑定在 `127.0.0.1`、`0.0.0.0` 或其他地址。Start/stop 与异步 bind 结果先更新该 snapshot，Java 再读取；不能继续根据 configured value 或线程是否存活推断 Go-owned active state。该 status seam 同时供端口冲突预检、inspect runtime section、runtime impact 和 unload verification 使用。

AI Control 自身的端口、启停状态和完整审计开关属于 control-plane 设置：

- AI 不可查看或修改这些设置；
- 端口和审计开关持久化在 Preferences；
- enable 状态不持久化，每次 Burp 启动都必须手动开启；
- 它们不进入业务设置 revision，也不使业务 proposal 自动失效。

## 4. MCP Transport 与本地信任边界

### 4.1 Endpoint 和生命周期

- 协议目标：MCP `2026-07-28`。
- Transport：stateless Streamable HTTP，首版只接受 `/mcp` 上的 POST。
- 默认 endpoint：`http://127.0.0.1:8885/mcp`。
- 只绑定字面地址 `127.0.0.1`；不绑定主机名、`::1`、任意网卡或远程地址。
- 端口固定且用户可配置，但只能在 AI Control 关闭时修改。
- 端口预检只比较可观察值：spoof/intercept 的 configured 与 Go-reported active bind address、configured Burp proxy endpoint，以及 Go 当前实际采用的 Burp upstream endpoint。由于无法通过当前 Montoya API 得知 Burp Proxy listener 的实际 bind interface，预检不得声称已排除其 `0.0.0.0:<port>` 等覆盖式绑定；对 MCP 的真实 `127.0.0.1:<port>` bind 是唯一权威冲突检查，失败就保持 disabled 并报告原始错误。
- 端口被占用时启动失败，不随机换端口；多个 Burp 实例需要分别配置端口。
- 成功启用后持续运行，直到用户手动关闭或扩展 unload；不设置 idle timeout。
- 关闭时立即停止 listener，并清除 pending proposal、幂等记录、限流状态和可撤销快照；审计文件保留。
- bind 失败或 listener 异常退出时进入 disabled 状态，清除上述内存状态，保持业务设置不变，显示原始可操作错误并要求用户手动重试；禁止无限自动重试。
- extension unload 必须有界地停止 listener 与线程池，并验证端口和线程均已释放。

固定 endpoint 允许 Codex 配置一次后复用，但 Burp 每次启动仍需用户在 UI 中重新启用服务。

### 4.2 无认证模式

首版只有 unauthenticated 模式：

- 不生成、不要求、不保存 Token；
- 不实现 OAuth discovery、authorize、callback 或 token endpoint；
- 审计 actor 固定为 `unauthenticated-local`；
- MCP `clientInfo` 仅用于展示，是不可信的客户端自报信息，不能用于权限或审计身份判断。

每次启用必须显示阻断式说明，并要求用户勾选“我理解并接受本机进程可读取完整敏感设置”的 checkbox；未勾选时 Enable 按钮不可用。**（2026-08-26 修订：见 §23。说明仍每次显示，勾选本身改为持久化，只需一次。）** 说明必须明确告知：

- 任何能连接本机 `127.0.0.1:<port>` 的进程都能读取完整代理凭据和完整 Hex ClientHello；
- 任何此类进程都能提交待审批 proposal；
- 最终应用仍必须由用户在 Burp UI 中完成；
- 当前完整审计开关是 ON 还是 OFF。

### 4.3 Host、Origin 和 CORS

对 `/mcp` 的每一个请求：

- 必须且只能有一个 `Host` header，并精确等于 `127.0.0.1:<当前配置端口>`；缺失、重复或其他值都拒绝；
- 只要任一 `Origin` header 存在就拒绝，不比较其值；重复或空值也视为存在；
- 不返回宽松 CORS header；
- 不信任 `X-Forwarded-Host`、`Forwarded` 或其他代理转发 header；
- 回环绑定、Host 校验和 Origin 拒绝不能被描述成身份认证。

此策略针对 Codex 原生客户端。未来若支持浏览器、OAuth 或其他会携带 Origin 的客户端，必须另立决策，不能放宽现有入口后仍声称保持同一信任边界。

## 5. 外部 MCP 工具

首版只暴露两个 tool：

### 5.1 `awesome_tls.settings.inspect`

纯只读、无目标侧副作用。返回内容包括：

- schema version；
- 当前业务设置 revision；
- 全部已提交 scalar settings，包括完整代理 URL 凭据和完整 Hex ClientHello；
- 所有可供 AI 操作的有效 domain rules；
- 被隐藏的无效原始规则数量 `hiddenInvalidRuleCount`；
- 可用 fingerprint catalog；
- configured 与 active runtime 状态及 reload/restart impact；
- pending、rejected 或 expired proposal 状态和原因；
- 可选的 effective-config 查询结果及每个值的来源追踪。

Effective-config 查询必须：

- 每次最多接受 20 个 bare hostname；
- 拒绝 scheme、port、path、空格和非法 wildcard；
- 只执行本地 normalization、rule matching 和 inheritance；
- 不做 DNS、不连接目标、不触发 Burp 或 Go proxy 请求。

普通 inspect 输出不脱敏。长 Hex 在 Burp UI 中完整保留，但默认折叠，并提供展开与复制。

返回可按 section 分页。分页 cursor 必须绑定 revision 与 section；revision 变化后返回 `CURSOR_STALE`。只有输出合同显式声明为 `StringValue`/`ScalarValue` 的字段才能在超过 256 KiB 时使用 allowlisted revision/path/offset cursor 分块；普通 `string` 字段受固定长度上限约束且永不变成 `ChunkReference`。服务端不得缓存完整敏感字符串；revision 变化使该 cursor 失效。

### 5.2 `awesome_tls.settings.propose`

`propose` 只校验并创建待审批 proposal，不得修改内存、Preferences、`rules.json`、UI draft 或 active runtime。请求至少包含：

- `schemaVersion`；
- `expectedRevision`；
- `requestId` 幂等键；
- semantic settings patch；
- 与 fingerprint/Hex 组合相关时所需的显式 `acknowledgements`；
- 可选 `summary`，最长 500 个字符，只用于 UI 和审计，不参与 digest、merge 或授权。

限制：

- HTTP request body 最大 16 MiB；
- 单个 proposal 最多包含 100 条 rule changes；
- 每个通过 Host、Origin 和基础 HTTP framing gate 的 `/mcp` 请求尝试都计入每分钟 30 次的限制，包括最终被协议或业务校验拒绝的请求；
- 最多同时处理 2 个请求，计数发生在完整 body 解析前；
- 超限返回稳定的 `RATE_LIMITED` 或相应结构化错误，不排队制造无界内存压力。

由于没有可信 client identity，rate 与 concurrency limit 都是当前 listener 全局限制，不能按 clientInfo、source port 或自报字段分桶。Rate 使用滚动 60 秒窗口，disable/unload 清零；并发名额在完成 Host/Origin 与基础 HTTP framing 检查后、读取 body 前占用，并在响应完成或连接终止时释放。

`requestId` 在一次 enabled session 内生效：

- 相同 ID 与相同规范化请求返回原始结果；
- 相同 ID 与不同请求体返回冲突错误；
- 最多保留 1000 个不同 ID，不淘汰仍处于同一 enabled session 的记录；达到上限后拒绝新的 ID 并返回 `IDEMPOTENCY_CAPACITY`，已有 ID 的重试仍可复现原结果；
- disable 或 unload 后清除幂等状态。

这里的“相同请求”固定为完整已解析 tool arguments 的 JCS bytes 相同：JSON 空白和 object key 顺序不影响判断，任何参数值、数组顺序、`summary` 或 `acknowledgements` 变化都视为不同请求；HTTP header 和不可信 clientInfo 不进入该摘要。请求摘要在 settings normalization 之前计算，防止用同一 requestId 把不同原始意图折叠成一次操作。

若规范化 patch 不产生变化，返回 `NO_CHANGES`，记录审计但不占 pending slot、不生成新 revision。

## 6. Semantic Patch 合同

### 6.1 通用语义

- 字段缺失表示保留当前值。
- 对允许清除的字段，显式 `null` 或 normalization 后的空字符串表示清除；必填字段不接受 `null`。
- 拒绝未知字段、未知 schema、任意 Preferences key、路径、命令和 request-only transport 字段。
- `Host`、`Scheme`、`HeaderOrder` 不属于用户设置，永远不可提议。
- intercept 开关和 intercept/Burp proxy address 是 global-only，不能放入 domain rule。
- control-plane 的端口、enable 状态和审计开关不能通过 inspect/propose 读写。

### 6.2 Domain-rule patch

只提供：

- `upsert`：以 normalization 后、大小写不敏感的 `hostPattern` 为 key；
- `remove`：按同一语义 key 删除。

不提供数组索引、Swing row index、`replaceAll` 或完整 rules 数组替换。已有规则原位更新，并保留其磁盘中的原始 `hostPattern` spelling（包括 leading-dot legacy alias）；新规则使用 canonical normalized key 并追加到当前磁盘顺序末尾。

`upsert` 至少包含 `hostPattern` 和一个待修改字段。若 normalized key 不存在，则按以下固定默认值创建新规则后再应用 patch：`enabled=true`、`fingerprint=""`、`hexClientHello=""`、`externalProxyUrl=""`、`httpTimeout=null`。若 key 已存在，缺失字段继续保留原值。单个请求内 `upsert`、`remove` 以及二者之间的 normalized key 都不得重复或相互冲突。

Host key normalization 固定为同一共享函数：先按既有 UI 语义 trim；rule-key mode 中，leading `.` 作为既有 `*.` alias 并 canonicalize 为 `*.`，wildcard 只允许这一最左侧形式且不匹配 apex；exact-query mode（request hot path 与 effective-config host）拒绝所有 wildcard/leading-dot。其余 label 通过 Java `IDN.toASCII(..., IDN.USE_STD3_ASCII_RULES)`，再用 `Locale.ROOT` 小写。拒绝 trailing dot、空 label、scheme、port、path、whitespace、IPv6 literal 和其他 `*`；IPv4 literal 可作为 exact key。每个 A-label 最长 63 bytes，完整 exact hostname 最长 253 bytes。Request hot path、effective-config、UI 校验、AI patch、revision 和 matcher 必须调用同一 normalization implementation 并只切换 mode；不能由 adapter 各自实现近似版本。

保持现有匹配语义：

1. exact host 优先；
2. wildcard 次之；
3. 多个 wildcard 命中时选择 suffix 最长者；
4. row order 不参与有效规则的匹配优先级。

### 6.3 Fingerprint 与 Hex

Fingerprint 和 Hex ClientHello 的优先关系必须显式处理，禁止隐式修改持久化值：

- 修改 global fingerprint 时，若 global Hex 非空，patch 必须同时显式清除 Hex，否则拒绝；
- 设置 global 或 rule Hex 时，patch 必须显式确认对应 fingerprint 将暂时不生效，但保留 fingerprint 的持久化值；
- 现有 domain-rule 语义保持不变：非空 rule fingerprint 会在该 host 的 effective `TransportConfig` 中抑制继承的 global Hex，但不会清空 global 设置；AI patch 必须显式确认这一 effective effect；
- 非空 rule Hex 同理在该 host 的 effective config 中抑制 fingerprint，不隐式删除已存 fingerprint；
- UI diff 必须把关联字段、被抑制的继承值及最终 effective 值放在同一风险上下文中展示。

## 7. 共享校验与无效规则

将当前 `SettingsTab` 中可复用的 normalization 和基础约束迁入 `SettingsControl`。UI、import、MCP 和 approval recheck 使用同一个校验引擎，但由该模块集中提供明确的 caller policy，禁止 adapter 各自复制规则：

- `UI_DRAFT` 保留现有 rules autosave 能保存未完成 raw row 的行为；
- `IMPORT` 保留现有整批严格校验；
- `AI_PROPOSAL` 在基础约束上增加 unknown-field、ambiguity、acknowledgement 和 proposal-only 限制；
- `COMMIT` 对最终 candidate、matcher 和持久化不变量做统一复检。

AI proposal 是严格输入，至少拒绝：

- 非法 `host:port` address；
- 无法由当前 pinned Go `tls-client` proxy dialer 解析的非空 external proxy URL；
- 奇数长度或非十六进制 ClientHello；
- 未知 fingerprint；
- 不在 `1..3600` 范围内的 timeout；
- 非 bare hostname、非法 wildcard、重复或冲突的 `hostPattern`；
- fingerprint/Hex 语义不明确；
- 任何未授权字段或 patch path。

External proxy URL 的 v1 语法与当前 Go dependency 对齐：trim 后允许空值表示 direct/inherit；非空值必须能被 Go `url.Parse` 解析、具有 non-empty host、合法可选 port，并且 scheme 只能是 `http`、`https`、`socks4`、`socks4a`、`socks5`、`socks5h`；userinfo/credentials 允许。校验只解析，不做 DNS 或连接；持久化值除 trim 外不重写。实现必须用共享纯校验器并以当前 Go dialer 的 golden vectors 对照，未来 dependency 支持集变化不能静默扩大/缩小 v1 合同。

现有 UI 仍允许用户暂存未完成的 rule row。所有无效原始规则：

- 原样保留在 UI 和 `rules.json`；
- 纳入 canonical revision 和三方合并，避免 AI 静默删除；
- 从 `RuleMatcher` 中排除，因此不进入请求路径；
- 从 inspect 的 rule 列表中隐藏，只返回 `hiddenInvalidRuleCount`；
- 与 AI upsert/remove 的规范化 host 冲突时返回 `HIDDEN_RULE_CONFLICT`，要求用户先在 Burp 修复或删除。**（这对客户端是死路，且必须保持如此：见 §26.1。propose 本身不得造出隐藏行，见 §26.2。）**

存在隐藏无效规则时，AI 仍可修改无关设置；这些行必须保持原样且继续 inactive。

从 `RuleMatcher` 排除所有 invalid 或 duplicate raw rows 是本功能引入的有意行为修正，不是对当前实现的描述。实现前必须补回归测试，确保无效行不再因“最后一个 exact 覆盖”或 wildcard 排序偶然参与请求匹配；有效规则的 exact/wildcard/longest-suffix 语义保持不变。

“文件无效”和“允许保存但 inactive 的行无效”必须分开：

- 当前 `rules.json` 的 canonical 磁盘格式保持既有 RuleStore v1 wrapper：`{"version":1,"rules":[...]}`。为兼容现有手写/导出文件，读取时继续接受 legacy bare top-level array；下一次正常保存仍按既有行为写回 v1 wrapper，这不是本功能新增的存储迁移；
- Wrapper 只允许 `version`、`rules`；rule object 只允许 `hostPattern`、`fingerprint`、`hexClientHello`、`externalProxyUrl`、`httpTimeout`、`enabled`。缺失/`0` 版本按既有 legacy wrapper 兼容读取，`version > 1` 或其他未经批准的版本拒绝；
- malformed/blank JSON、既非 v1/legacy wrapper 也非 bare array 的 root、非 object row、未知 field、错误 JSON type 或未来未批准的 file shape 属于 file-invalid，阻断 inspect/propose/approval 的磁盘基线建立；文件不存在才表示空规则集；
- SettingsTab 已保存的行级语义问题属于 row-invalid，可作为 hidden raw row 留存；
- base 中已存在的 hidden raw row 作为 opaque ordered entry 保留，AI 不可修改；
- 外部编辑若新增、删除、重排或修改 hidden raw row，则视为 external-invalid divergence，阻断 approval，避免按不稳定 host identity 猜测合并。

V1/legacy 中缺失的已知 rule 字段按 `FingerprintRule` 兼容默认值物化；JSON `null` string 按既有兼容规则变成空字符串。Parser 必须先以 JSON tree 严格检查 shape 和字段，再映射 domain object，不能让 Gson 静默丢弃未知字段。未来若提高 `RuleStore.FORMAT_VERSION` 或改变 wrapper/rule shape，属于单独 storage migration 决策。

上述 strict shape 是本 ADR 明确批准的兼容性 hardening，不是 on-disk shape migration：它有意替代当前 `RuleStore.parse()` 对 blank file 当空规则、丢弃 null row、以及 Gson 静默忽略 unknown field 的宽松行为。实现必须更新这些旧 regression，并新增严格失败测试。遇到这类既有文件时保留原始 bytes 原位，不建立空 baseline、不自动重写；blocking UI 必须显示原因并提供 Open rules file、从 `.bak` 恢复或显式 import 的修复入口。只有用户明确选择的修复动作才可 quarantine/replace。文档与 release notes 必须把这一升级行为列为兼容性变化。

Rules UI 保留 500 ms autosave，但必须通过 `SettingsControl` 形成 committed revision。活动 cell editor、未触发的 debounce 或其他未保存 draft 都属于 dirty state。

## 8. Revision、Proposal 与并发

### 8.1 Revision

业务 revision 是以下内容的 SHA-256：

- schema version；
- canonical、normalized 的全部已提交业务 scalar settings；
- 完整原始 rules，包括隐藏无效行和稳定存储顺序。

AI Control 的端口、enable 和审计开关不进入该 revision。Revision 是内容标识，不使用 last-write-wins，也不要求可预测的自增序号。

字节级 canonicalization 固定为：

1. 构造 schema v1 logical document，根对象仅含 `schemaVersion`、`defaults`、`advanced`、`rules`。
2. 物化每个已知字段；缺失 string 先按存储兼容规则变成空字符串，nullable timeout 显式保留 `null`，boolean 显式写出，禁止用“字段缺失”代替值。
3. 地址、host pattern、Hex 等先应用与 SettingsControl 相同且 locale-independent 的字段 normalization；有效 host key 使用 `Locale.ROOT` 小写，Hex 使用小写。Fingerprint 和 proxy URL 除 trim 外不做猜测性重写。
4. Hidden row 以存储顺序写入并物化全部已知字段；除兼容性 null/missing 默认物化外，其 raw string 不 trim、不改大小写、不重写 Hex，以便任何实际保存值变化都改变 revision。重复 normalized key 的所有行都作为 hidden duplicate 写入，不选择 first/last winner。
5. 使用 RFC 8785 JSON Canonicalization Scheme 生成 JSON，UTF-8 编码、无 BOM、无尾随换行；object key 由 JCS 排序，rules array 保持存储顺序，JSON number 必须是整数表示。
6. 计算 SHA-256 小写十六进制并加 `sha256:` 前缀。不得包含 timestamp、proposal、audit、control-plane 或 active runtime 状态。

Golden vector：以下 canonical bytes 的 revision 必须为 `sha256:3e3e681a6422f5cd90d4c3d6bb226e4ba6713a19efb43f5a9706b0eb8046f2b3`。

```json
{"advanced":{"burpProxyAddress":"127.0.0.1:8080","interceptProxyAddress":"127.0.0.1:8886","useInterceptedFingerprint":false},"defaults":{"externalProxyUrl":"","fingerprint":"default","hexClientHello":"","httpTimeout":30,"spoofProxyAddress":"127.0.0.1:8887"},"rules":[],"schemaVersion":1}
```

所有通过 `SettingsControl` 成功提交的 UI save、rules autosave、import、AI apply 和 AI revert 都生成与最终内容对应的 revision。外部绕过 `SettingsControl` 修改 scalar Preferences 时不做自动三方合并；检测到 divergence 后拒绝 proposal/approval，并要求 reload、reinspect 或用户修复。

### 8.2 Proposal 生命周期

- 全局最多一个 pending proposal，与自报 clientInfo 无关。
- Proposal TTL 为 15 分钟，只保存在内存。
- pending 存在时拒绝新的 proposal。
- 过期后清除 pending slot，但 inspect 返回 `EXPIRED`，直到新 proposal 到来或 AI Control 关闭。
- 用户拒绝后保存状态与原因，inspect 持续返回，直到新 proposal 或 session 结束。
- AI Control 关闭或 extension unload 清除 proposal、授权上下文和 in-memory 状态。

`proposalId` 使用至少 128 bit CSPRNG entropy 的 URL-safe 随机标识。完整 candidate 按第 8.1 节算法计算 `candidateRevision`。`proposalDigest` 是以下 closed logical document 的 JCS bytes 的 SHA-256：业务字面值 `"schemaVersion":"awesome_tls.settings.v1"`、`proposalId`、`baseRevision`、`candidateRevision`、normalized semantic patch、normalized acknowledgement set、完整 diff、risk flags、runtime impact、`reviewGeneration` 和 `expiresAt`。`summary`、clientInfo 和 wall-clock read time 不进入 digest。Approval 必须同时匹配 proposal ID、digest、review generation 和 expiry。

Digest 输入使用未分页、未分块的完整 logical values，绝不包含 `ChunkReference`、cursor 或 wire page boundary，避免 cursor 绑定 proposalDigest 后形成循环。Canonical array order 固定：acknowledgement 按枚举名排序；semantic patch 的 `upsert`/`remove` 保留请求数组顺序（新 rule 的 append order 因此可重现）；diff 按 output path、再按 operation 排序；每个 risk 的 paths 排序，risk flags 按 code 排序；runtime impact 按 path、再按 effect 排序。任何仍有同 key tie 的条目保持 candidate 磁盘顺序。Object key 继续由 JCS 排序。

### 8.3 UI dirty state

若 Swing 存在未保存草稿、活动编辑器或 rules debounce 尚未完成：

- inspect 返回 dirty 状态；
- propose 拒绝；
- approval 也拒绝；
- 不得覆盖 UI 字段或强制结束 editor。

用户必须先保存、放弃或解决草稿。

## 9. Burp 审批流程

`SettingsTab` 增加第四个 `AI Control` tab，至少包含：

- endpoint、端口编辑、启用/关闭与当前 listener 状态；
- 每次启用的无认证/完整敏感值警告；
- 完整审计开关与当前 ON/OFF；
- pending proposal badge，不抢焦点、不弹出自动 modal；
- 完整 field-level diff、运行影响、风险摘要；
- Apply、Reject、撤销最近一次 AI 应用；
- 最近审计事件、完整详情和 Open audit folder；不提供删除按钮。

审批固定顺序：

1. AI 通过 inspect 取得 revision。
2. propose 校验 schema、revision、requestId 和 semantic patch，纯计算 candidate、diff、digest 与 runtime impact。
3. UI 展示完整未脱敏值；长 Hex 默认折叠但可查看和复制。
4. 用户对整份 proposal 选择 Apply 或 Reject，不支持部分勾选应用。
5. Apply 重新检查 proposal ID、digest、TTL、revision、UI dirty state、Preferences 状态和 `rules.json` digest。
6. 若 proposal 属于高风险，显示独立风险摘要并要求第二次确认。
7. 持久化完整成功后，原子发布新 snapshot 与 matcher，并在 EDT 刷新 Swing，禁止触发 rules autosave 回环。
8. AI 再次 inspect 验证 revision 与结果。

以下任一情况属于高风险：

- spoof listener、intercept 或 Burp proxy address；
- external proxy 或其凭据；
- global fingerprint 或 Hex ClientHello；
- intercepted-fingerprint global toggle；
- 删除任意 domain rule；
- 单次变更不少于 10 条 domain rules。

整份 proposal 仍保持原子；高风险只增加第二次确认，不允许拆成未经审查的部分提交。现有用户直接编辑/保存 SettingsTab 的交互不额外增加 AI proposal 二次确认。

## 10. 外部 `rules.json` 三方合并

不增加 file watcher。inspect、propose 和 approval 都通过无副作用的 `RuleStore` probe 检查磁盘内容与 digest，approval 使用：

- base：AI inspect 时的 rules；
- current：审批时的磁盘 rules；
- proposed：AI semantic patch 的候选 rules。

`rulesFileDigest` 固定为磁盘文件 raw bytes 的 SHA-256，用于最后 `saveIfUnchanged`；三方合并比较的是严格 parse 后的 logical rows。若外部只改变 JSON whitespace/indent 而 logical rows 完全相同，可更新 observed raw digest 后继续，不产生业务 diff 或强制 re-review；任何 logical field/order 变化仍按本节处理。

合并规则：

- 以 normalized、case-insensitive `hostPattern` 定位规则；
- 同一规则内按 field 进行三方合并；
- AI 与外部修改不同 field 时可自动合并；
- 同一 field 改为不同值时整份 proposal 冲突；
- delete 与 modify 冲突；
- 外部文件无法解析或无效时保留原文件，不 approval、不写回，要求用户先修复；
- 结果沿用 current 磁盘顺序，更新项原位保留，AI 新增项追加。

如果无冲突合并改变了用户先前看到的最终 candidate，必须重新生成完整 diff 与 digest，并要求用户再次点击 Apply。

现有 `RuleStore.load()` 在解析失败时会 quarantine/move 文件，不能用于 bootstrap strict probe、inspect、propose 或 approval。实现必须增加类似 `probe`/`readForConflictCheck` 的无副作用读取路径；这些路径不得移动、删除、重命名或重写损坏文件。普通 parse failure 在启动时也保持原文件原位并进入 blocking repair UI；quarantine/replace 只允许用户明确触发。Transaction journal 对已知 phase 的自动 recovery 是另一条受 digest 约束的流程，不得借其名义处理任意损坏文件。

最终写入必须使用 `saveIfUnchanged(expectedDigest, candidate)` 语义，在替换前再次核对磁盘 digest；不匹配则放弃写入并重新进入 conflict/merge。普通文件系统无法对不合作的外部编辑器提供绝对 CAS，最后一次核验与 rename 之间仍有残余 TOCTOU；实现必须缩短窗口、保留 `.bak`、不声称绝对互斥，并在检测到冲突时明确报告。

Montoya Preferences 同样没有多 key CAS，而且 `set*` 返回 `void`，没有 flush/commit 或 durability acknowledgement。Coordinator 必须在写入前重新读取全部业务 scalar settings 并比较 canonical digest；一次 Preferences 写入“成功”只表示所有 `set*` 调用未抛错且紧接着的全 key reread canonical digest 与目标一致。该可观察成功不能证明底层已经 durable flush。Journal 负责 partial write compensation 与下次启动 reconciliation；这里也只能减少而不能消除底层 flush failure 或不合作外部写入的残余竞态，检测到未知组合时进入 recovery/blocking state，不能宣称 Preferences 具备事务、CAS 或可确认的落盘 durability。

## 11. 持久化、恢复与原子可见性

继续使用现有存储边界：

- scalar settings：Montoya Preferences；
- domain rules：`RuleStore` 管理的 `rules.json`；
- audit 与 transaction journal：应用 OS config directory 下的独立目录/文件。

MCP adapter 和 AI 客户端不能直接写任何一种存储。所有设置写入都由 `SettingsControl` 串行协调；完整审计开启时，audit 也是同一 transaction journal 覆盖的持久化参与者。以下 `durable` 只适用于本项目可 `fsync`/atomic-replace 的 journal、audit 和 rule files；Preferences 参与者使用上一段定义的“调用未抛错 + 全 key reread digest 匹配”可观察标准：

1. 读取并固定 base snapshot、Preferences digest、rules digest 和 audit 状态。
2. 构建、normalize、校验完整 candidate，并预编译 candidate `RuleMatcher`。
3. durable 写入 journal `PREPARED`，其中包含 transaction ID、old/new snapshot、各存储 before/after digest、当前 phase 和待写 audit event/snapshot digest。
4. 审计开启时先 durable append `MUTATION_PREPARED`，成功后将 journal phase 更新为 `AUDIT_PREPARED`；失败则不触碰设置存储。
5. 以 expected digest 写 Preferences 与 `rules.json`，每完成一个参与者都在 journal 中更新 phase；Preferences 按上述可观察标准复核，rules 使用 `saveIfUnchanged`、临时文件、atomic replace 和 `.bak`。
6. 两个设置参与者都匹配 candidate digest 后，审计开启时 durable append `MUTATION_COMMIT_READY` 及去重 snapshot reference；然后 durable 更新 journal 为 `COMMIT_READY`。该 audit event 只表示已准备提交，不能写成 committed。
7. 执行唯一 commit decision。完整审计 ON 时，按 transaction ID 与预期 event digest 原子、幂等、durable append `MUTATION_COMMITTED`；这个成功 append 本身就是 commit decision，随后更新 journal 为 `COMMIT_DECIDED`。审计 OFF 时，durable 更新 journal 为 `COMMIT_DECIDED` 本身就是 commit decision。Decision 之前的明确失败都按 journal compensation 到 old committed state；补偿失败则保留 journal 并进入阻断式恢复。
8. Commit-decision 写调用若报告失败，必须按 transaction 固定的审计模式严格 probe 对应 durable evidence：审计 ON 必须找到完整、校验通过且 transaction ID/event digest 匹配的 `MUTATION_COMMITTED`，journal phase 不能替代该证据；审计 OFF 必须找到完整 `COMMIT_DECIDED` journal。能确定对应 evidence 不存在才 rollback；截断、损坏或无法确定时保持阻断，既不发布也不盲目回滚。Decision evidence 一旦存在就绝不回滚 candidate；journal phase 更新失败只留下可恢复状态，不撤销 decision。
9. 确认 decision evidence 后，一次发布 candidate snapshot 与 matcher，再把 journal 更新为 `RUNTIME_PUBLISHED`。进程若在 phase 更新前崩溃，重复发布同一 revision 必须幂等。
10. durable 标记 transaction `COMPLETE`，随后可重试地清理 journal、发送 change event 并在 EDT 刷新 UI。Commit decision 后的 phase、清理、通知或 UI 故障都不能把结果报告成“已回滚/未应用”；若尚未完成 runtime publish，则返回并显示 `RECOVERY_REQUIRED`/`commit_decided`，阻止新写入直到 forward recovery 完成。

Preferences 与 `rules.json` 不是一个 ACID store，文档和错误不得声称底层 ACID 或已证明 Preferences flush。对外保证的是 staged validation、API 可观察写后复核、唯一 commit decision、运行态原子可见性、不会把 commit-decision 后的故障误报为 rollback，以及 crash recovery。

Extension 启动时必须在发布任何 SettingsControl snapshot、启动 MCP listener 或允许新写入前检查未完成 journal：

- Journal phase 必须带每个参与者的 before/after digest。`PREPARED`、`AUDIT_PREPARED` 和各 setting-written phase 是 commit decision 之前的状态；只有当前存储组合属于这些 phase 允许的已知 digest 组合时，才自动回滚到 old committed state；
- `COMMIT_READY` 必须结合 transaction 固定的审计模式判定：审计 OFF 时尚无 decision，按 pre-decision rollback；审计 ON 时严格查找匹配 transaction ID/event digest 的完整 `MUTATION_COMMITTED`，存在则 forward，不存在则 rollback，audit 截断、损坏或不可读则阻断；
- `COMMIT_DECIDED` 或 `RUNTIME_PUBLISHED` 必须只做 forward recovery：复核/重写已批准的 candidate，确认审计 ON transaction 已有匹配 committed event，然后发布 candidate snapshot。Preferences 若回到已知 old digest，可按 commit decision 重写并 reread；未知 digest 仍按下一条阻断；
- 残留的 `COMPLETE` 只表示 journal 声称流程完成但 cleanup 未完成，它本身不构成 decision evidence。必须先按 transaction 审计模式严格复核：审计 ON 只有完整 matching `MUTATION_COMMITTED` 才能进入后续三分支，event 缺失、损坏、不可读或不匹配一律阻断，且不得仅凭 `COMPLETE` 重建第二个 committed event；审计 OFF 以完整 `COMPLETE`/journal decision chain 为证据。证据有效后，所有参与者均为 candidate digest 时只幂等补齐本地通知/UI 初始化并清理 journal；任一参与者回到 journal 记录的 known old/partial digest 时，依据既有 commit decision 幂等 forward rewrite candidate、复核后再初始化并清理，这只是 storage recovery，不生成新 proposal、审批、业务 revision 或第二个 committed mutation；出现任何 unknown digest 时阻断。`COMPLETE` 永不回滚；
- 若当前 digest 不属于 journal 的任何已知 phase，说明崩溃后发生了外部修改，不得盲目覆盖，必须保留所有文件并进入阻断式人工修复状态；
- 只有审计 ON transaction 的 durable matching `MUTATION_COMMITTED`，或审计 OFF transaction 的 durable `COMMIT_DECIDED`，才证明 candidate 已获本地审批并允许 forward-complete；decision 前 candidate 永远回滚，不得借 recovery 静默提交；
- 对启用了完整审计的 transaction，每次 rollback 或 forward recovery 都记录带 transaction ID、原 phase、结果与最终 digest 的 recovery audit；audit 暂不可用时保持阻断，不得跳过后继续发布。审计关闭的 transaction 不因 recovery 临时生成完整审计；
- 恢复成功后才正常初始化；
- 恢复失败时禁用 AI Control，阻止设置提交并显示阻断式修复错误，不发布混合状态。

Bootstrap 必须保留仓库现有的两条 upgrade compatibility 链，但顺序固定，避免迁移覆盖 crash recovery：

1. 只定位当前 `burp-awesome-tls-plus` config directory，不调用带 adopt side effect 的现有 `RuleStore.inConfigDir()`；先检查并完成当前目录 transaction journal recovery。
2. 仅在没有未完成 journal、当前 `rules.json` 确实不存在时，才执行旧 `burp-awesome-tls` 目录中 `rules.json`/`.bak` 的既有 adopt 流程。
3. Adopt 后当前文件仍不存在时，才读取 Preferences 中既有 legacy `DomainRules` fallback；与当前行为一致，成功迁移后不删除该 Preferences 值，以保留 downgrade path。
4. Adopt/Preferences migration 作为 bootstrap mutation 纳入 journal；完整审计 ON 时也必须 durable audit，失败则不建立新当前文件。迁移失败保留 source，并进入可修复的 blocking state，不能悄悄建立空 baseline。
5. 只有完成上述顺序并严格 probe 最终当前文件后，才建立首个 committed snapshot/revision、发布 matcher、初始化 UI，最后才允许手动 Enable MCP。

必须为“旧目录文件 + backup adopt”和“仅 legacy Preferences DomainRules”分别增加升级回归测试，并覆盖它们与未完成 journal 同时存在时 journal-first、不丢规则的顺序。

## 12. Configured 与 Active Runtime

设置 diff 和 inspect 必须同时说明 configured value、active value 与生效时机：

| 设置 | 审批后的运行效果 |
| --- | --- |
| fingerprint、Hex ClientHello、external proxy、timeout | 对后续新请求立即生效 |
| domain rules | 对后续新请求立即生效 |
| spoof listener address | 只配置到下次 extension load；当前请求继续转发到 Go server 实际监听地址 |
| intercept proxy address、Burp proxy address | proxy 未运行时下次启动使用；已运行时标记 reload/restart required，不伪装成立即生效 |
| intercepted-fingerprint toggle | 继续使用现有全局 Go proxy start/stop 行为，不能按 domain 改变 |

实现必须修正当前“保存新 spoof address 后请求立即改投尚未监听端口”的风险。SettingsControl 将 approved user settings 映射到现有 request path，不扩展或重命名 Java/Go `TransportConfig`。

## 13. 撤销最近一次 AI 应用

Burp UI 提供一次性 `Revert last AI apply`：

- 只保留最近一次成功 AI apply 前的 snapshot；
- 仅在当前 Burp 运行期和当前 enabled session 中存在于内存；
- 只有当前 revision 仍等于该 AI apply 的结果 revision 时可用；
- 任意后续 committed change、外部存储 divergence、AI Control disable 或 extension unload 都使其失效；
- revert 是新的本地原子设置变更，执行完整校验、持久化、审计和 runtime-impact 展示，并产生新 revision；
- 高风险 revert 同样要求第二次确认。

不从 audit 文件重建可撤销状态，也不提供任意历史版本选择。

## 14. 完整审计

### 14.1 开关与内容

完整审计是独立、持久化的 Preferences 开关，默认 OFF。AI Control 每次启用警告必须显示其当前状态。

开启后，记录：

- listener 启停、bind failure 和异常退出；
- 每个通过协议解析的 MCP 调用的完整参数、完整结果或完整业务错误；
- inspect 返回的完整凭据与完整 Hex；
- proposal、diff、digest、merge、冲突、批准、拒绝、过期和 revert；
- UI save、rules autosave、import、recovery 等所有来源的 settings mutation；
- 每个 revision 一份去重后的完整 settings snapshot，事件引用对应 snapshot，避免重复存储相同内容；
- actor `unauthenticated-local` 和不可信、仅展示用的 clientInfo。

Host/Origin 拒绝、超大 body 或无法解析的任意协议载荷只记录时间、来源类别、大小、拒绝原因等元数据，不把原始攻击载荷当作合法业务参数完整保存。

### 14.2 失败策略

完整审计开启时采用 fail closed：

- enable 在开始监听前必须先 durable 记录 enable attempt；失败则不启动 listener；
- inspect 先构建结果，再成功 durable 写入完整结果事件，最后才向客户端返回；写入失败则只返回 `AUDIT_UNAVAILABLE`；
- propose 先构建 proposal，再成功 durable 写入完整 proposal 事件，最后才安装 pending state；写入失败不得留下 pending、幂等成功结果或其他可观察 proposal state；
- approval、revert 和任何其他 SettingsControl mutation 在成功写入本 transaction 的完整 committed audit 之前，不得产生 commit decision、发布 runtime 或宣称成功。能确定 committed audit 不存在时，任何 staged storage write 必须按第 11 节 rollback；append durability 无法判定时，只能保留 journal-governed staged state 并进入阻断恢复，不能暴露为新 committed runtime。匹配的 durable `MUTATION_COMMITTED` 本身就是“审计写入成功”和 commit decision，因此其后的故障按既有 decision forward recovery，不属于未审计 mutation；
- UI 显示阻断错误，不得把未审计操作伪装成成功。

安全关闭优先于审计可用性：manual disable、listener failure cleanup 和 extension unload 即使 audit append 失败也必须立即关闭 listener、清内存状态并释放端口；UI/日志报告未审计的 shutdown，但绝不能为了等待审计恢复而继续暴露 endpoint。Idempotent retry 也算新 MCP event：先取得 cached original result，再成功记录本次完整 replay event 后才返回；本次 audit 失败只返回 `AUDIT_UNAVAILABLE`，不篡改已缓存的原始结果。

### 14.3 存储和保留

- 位置：应用 OS config directory 下的 `audit/`。
- 首版不加密，也不主动设置 owner-only 权限；继承 OS、目录和 Burp 进程默认权限。
- UI 提供 recent events、完整详情和 Open audit folder。
- UI 不提供 clear/delete；用户仍可在扩展外手工管理文件。
- 自动保留上限为 30 天、1000 个 events 或 100 MiB，任一上限达到即轮转删除最旧内容。

本地使用不等于不存在泄露风险。开发文档、enable warning 和审计设置 UI 都必须明确说明 plaintext secrets 可能被同机进程、同机用户、备份软件或获得目录访问权的程序读取。

## 15. Schema、错误和协议结果

版本空间必须分离，不能把以下值混用：

- MCP wire protocol：`2026-07-28`；
- inspect/propose 业务 payload：固定字符串 `awesome_tls.settings.v1`；
- revision logical document：整数 `schemaVersion: 1`；
- transaction journal 与 audit record：分别使用自己的整数 `formatVersion: 1`。

未知业务 payload 版本或项目拥有对象中的未知字段严格拒绝，不做 best-effort 猜测，返回 `UNSUPPORTED_SCHEMA`；journal/audit 格式升级必须提供明确 migration。未知字段拒绝只作用于本文定义的 tool arguments 和 structured business payload，不得对官方 MCP `_meta` 使用 `additionalProperties: false`，因为 `_meta` 是协议扩展点。

协议层遵循 MCP `2026-07-28` 和 JSON-RPC 的状态码/错误规则。JSON-RPC `error.code` 必须是整数，不能直接放本文的字符串业务码。MCP 已保留 `-32020..-32099`，JSON-RPC 已保留 `-32768..-32000`；除规范定义的 `-32020`、`-32021`、`-32022` 外，本项目自定义 transport code 固定放在未保留的 `-31900..-31906`，不得占用规范保留区间。

畸形 JSON-RPC、无效 `CallToolRequest`、未知 tool/method、header mismatch、不支持协议版本和服务器内部协议故障使用 HTTP + JSON-RPC error envelope。至少锁定：

| 场景 | HTTP | JSON-RPC |
| --- | --- | --- |
| JSON parse error | 400 | `-32700` |
| invalid JSON-RPC / CallToolRequest envelope 或 unknown tool | 400 | `-32600`/`-32602`，按官方 schema 分类 |
| Streamable HTTP notification POST | 400 | project code `-31906`，`error.data.code=UNSUPPORTED_NOTIFICATION` |
| unknown JSON-RPC method | 404 | `-32601` |
| required header 缺失或 header/body mismatch | 400 | `-32020` |
| Host/Origin gate 拒绝 | 403 | project code `-31900`，`error.data.code` 为 `HOST_REJECTED` 或 `ORIGIN_REJECTED` |
| unsupported protocol version | 400 | `-32022`，`error.data` 含 `requested` 与 `supported` |
| unsupported Content-Type/Encoding | 415 | project code `-31901`，`error.data.code=UNSUPPORTED_MEDIA_TYPE` |
| required Accept variants 缺失 | 406 | project code `-31902`，`error.data.code=NOT_ACCEPTABLE` |
| body 超限 | 413 | project code `-31903`，`error.data.code=BODY_TOO_LARGE` |
| transport rate limit | 429 | project code `-31904`，`error.data.code=RATE_LIMITED` |
| concurrency limit | 429 | project code `-31905`，`error.data.code=CONCURRENCY_LIMITED` |

`-31900` data 只含上述二选一 `code`；`-31901`、`-31902`、`-31906` data 分别只含对应的固定 `code`；`-31903` data 固定含 `code=BODY_TOO_LARGE`、`maxBytes=16777216`，已知时再含 `observedBytes`；`-31904` data 固定含 `code=RATE_LIMITED`、`limit=30`、`windowSeconds=60`、`retryAfterMs`；`-31905` data 固定含 `code=CONCURRENCY_LIMITED`、`limit=2`、`retryable=true`。这些 `error.data` 都是 closed object，除列出的字段外不得添加任意内容。能关联到合法 JSON-RPC request 时回显其 `id`；在 body 尚不可解析、安全 gate 先拒绝或 notification 本身没有 request id 时省略 `id` 字段，不得写 `id:null` 或猜测 id。Rate response 同时返回与 `retryAfterMs` 向上取整一致的 HTTP `Retry-After` 秒数。

有效 `tools/call` 进入 SettingsControl 后产生的校验、revision conflict、proposal state、audit unavailable 和 persistence 等业务错误，必须作为成功的 JSON-RPC `result` 中的 MCP `CallToolResult` 返回，而不是字符串 JSON-RPC error code。请求尚未进入有效 tool call 前触发的 body、并发或速率限制使用上表固定的 HTTP/JSON-RPC error。固定业务错误 envelope 为：

```json
{
  "resultType": "complete",
  "content": [
    {
      "type": "text",
      "text": "{\"kind\":\"error\",\"schemaVersion\":\"awesome_tls.settings.v1\",\"status\":\"ERROR\",\"code\":\"REVISION_CONFLICT\",...}"
    }
  ],
  "structuredContent": {
    "kind": "error",
    "schemaVersion": "awesome_tls.settings.v1",
    "status": "ERROR",
    "code": "REVISION_CONFLICT",
    "message": "The committed settings revision changed.",
    "details": [
      {
        "path": "/expectedRevision",
        "reason": "does_not_match_committed_revision",
        "expected": "sha256:...",
        "actual": "sha256:..."
      }
    ],
    "retryable": true,
    "currentRevision": "sha256:..."
  },
  "isError": true
}
```

- `content` 必须存在并包含 `structuredContent` 的完整 JSON text serialization，不能在兼容文本中脱敏；`structuredContent` 必须符合该 tool 的 `outputSchema`。
- 成功结果使用同一 envelope：`resultType: "complete"`、完整 `content`、完整 `structuredContent`、`isError: false`。
- `details` 固定为 closed `errorDetail` 数组；每项只允许 `path`、`reason`、`expected`、`actual`，其中 `expected`/`actual` 只能是 string、integer、boolean、`null` 或本文定义的 `ChunkReference`。需要表达多个值时增加多项，不开放任意 JSON object。
- `currentRevision` 只在适用时出现。
- 不向 MCP 客户端返回 Java stack trace、内部文件路径或未结构化异常文本。
- 首版 tool 结果不产生 MRTR `input_required`；用户审批发生在 Burp UI，AI 通过后续 inspect 验证。
- v1 业务码固定为 `UNSUPPORTED_SCHEMA`、`VALIDATION_FAILED`、`REVISION_CONFLICT`、`DIRTY_UI`、`PROPOSAL_PENDING`、`EXPIRED`、`REQUEST_ID_CONFLICT`、`IDEMPOTENCY_CAPACITY`、`HIDDEN_RULE_CONFLICT`、`AMBIGUOUS_FINGERPRINT_HEX`、`CURSOR_INVALID`、`CURSOR_STALE`、`RULE_FILE_INVALID`、`EXTERNAL_DIVERGENCE`、`MERGE_CONFLICT`、`AUDIT_UNAVAILABLE`、`CONTROL_DISABLED`、`PERSISTENCE_FAILED`、`RECOVERY_REQUIRED`。同一条件不得随意换码；增加或改变语义必须同步更新 v1 schema、golden vectors 和本文。`NO_CHANGES` 是成功 status，不是错误码；transport 的 `error.data.code` 固定使用 `HOST_REJECTED`、`ORIGIN_REJECTED`、`UNSUPPORTED_MEDIA_TYPE`、`NOT_ACCEPTABLE`、`BODY_TOO_LARGE`、`RATE_LIMITED`、`CONCURRENCY_LIMITED` 或 `UNSUPPORTED_NOTIFICATION`。

## 16. MCP 实现与依赖策略

### 16.1 协议 adapter

`SettingsControl` 与 MCP wire protocol 完全解耦。首版目标是最小 MCP `2026-07-28` adapter，并复用现有 Gson。Adapter 至少正确实现：

- POST-only stateless transport；
- `server/discover`；
- `tools/list` 与 `tools/call`；
- 每个 request 的 `params._meta` 至少包含 `io.modelcontextprotocol/protocolVersion` 与 `io.modelcontextprotocol/clientCapabilities`；`io.modelcontextprotocol/clientInfo` 可选且不可信，服务器不能沿用前一次请求的 metadata；
- `MCP-Protocol-Version` 必须为 `2026-07-28`；每个 JSON-RPC request 都必须带与 body method 完全一致的 `Mcp-Method`。按官方标准 header 合同，`tools/call`、`resources/read`、`prompts/get` 必须分别带与 body `params.name`、`params.uri`、`params.name` 完全一致的 `Mcp-Name`；本服务已实现的方法中只有 `tools/call` 属于此列。即使 `resources/read` 与 `prompts/get` 最终因未实现而返回 404/`-32601`，也必须先执行相应 header 校验与 HeaderMismatch 分类；其他 method 不要求或解释 `Mcp-Name`；
- MCP header names 按 HTTP 规则大小写不敏感、header values 大小写敏感；required MCP header 必须恰有一个逻辑值。`Mcp-Name` 比较前实现官方 `=?base64?...?=` sentinel 解码与非法编码拒绝；两个固定 tool name 仍按普通 ASCII 发送。V1 input schemas 不使用 `x-mcp-header`，因此不要求或解释任何 `Mcp-Param-*`；
- 请求 `Content-Type` 必须是 `application/json`（允许标准 charset parameter），拒绝任何非 identity `Content-Encoding`；16 MiB 上限同时在声明长度和流式实际读取处执行，不能因缺失 `Content-Length` 或 chunked transfer 绕过；
- 要求请求 `Accept` 同时声明 `application/json` 与 `text/event-stream`；
- v1 对 JSON-RPC request 固定返回单个 `application/json` JSON object，不主动选择 SSE，也不产生 request-scoped progress event；未来若实际启用 SSE，必须同时实现断开 cancellation 和对应 conformance，再更新本节；
- MCP `2026-07-28` core 在 Streamable HTTP 上不定义 client-to-server notification；v1 也不增加 project notification。收到 notification POST 时不 dispatch、不改变状态，返回 HTTP 400 与省略 `id` 的 JSON-RPC project code `-31906`/`UNSUPPORTED_NOTIFICATION`，并只记录拒绝 metadata；因此不存在“accepted notification 202”路径；
- `/mcp` 的 GET/DELETE 返回 HTTP 405，禁止旧版独立 stream 和 protocol session；
- unknown JSON-RPC method 返回 HTTP 404 与 JSON-RPC `-32601`；
- 缺失/错误版本与 header/body mismatch 按规范返回 HTTP 400，其中 HeaderMismatch 使用 JSON-RPC `-32020`；
- 忽略而不生成或回显旧版 `Mcp-Session-Id`；`Last-Event-ID` 即使存在也必须被忽略，不能据此 resume，也不能仅因该 header 拒绝请求；
- 每个 result 都有 `resultType`；`ttlMs` 与 `cacheScope` 只用于 `server/discover`、`tools/list` 等 cacheable result，不得放入 `tools/call` 的 `CallToolResult`；
- HTTP 与 JSON-RPC error mapping；
- Host/Origin、防滥用和 unload 生命周期。

在 2026-08-25 做出本决策时，官方 Java SDK 2.0.1 对应 MCP `2025-11-25`，其 HTTP server transport 依赖 Servlet container，不能作为本项目的 2026 实现。禁止通过补 header 或私有 fork 将其标注为兼容 `2026-07-28`。

本文中的 enabled session 只指 Burp 本地“手动启用到关闭/unload”的生命周期，不是 MCP protocol session。每个 POST 独立，不签发、要求或回显 `Mcp-Session-Id`。

### 16.2 Discovery 与 tool list 固定合同

`server/discover` 固定返回：

```json
{
  "resultType": "complete",
  "supportedVersions": ["2026-07-28"],
  "capabilities": {"tools": {"listChanged": false}},
  "_meta": {
    "io.modelcontextprotocol/serverInfo": {
      "name": "burp-awesome-tls-plus",
      "version": "<extension-version>"
    }
  },
  "instructions": "Inspect settings or submit a proposal. Applying, rejecting, and reverting are available only in the Burp AI Control tab.",
  "ttlMs": 0,
  "cacheScope": "private"
}
```

`tools/list` 以确定顺序只返回 `awesome_tls.settings.inspect`、`awesome_tls.settings.propose` 两项，省略 `nextCursor`，并返回 `resultType: "complete"`、`ttlMs: 0`、`cacheScope: "private"`。每项必须包含本文锁定的 JSON Schema 2020-12 `inputSchema` 与 `outputSchema`。Tool definition 同时固定为：

| Tool | exact title / description | annotations |
| --- | --- | --- |
| `awesome_tls.settings.inspect` | title: `Inspect Awesome TLS settings`；description: `Returns committed Awesome TLS business settings, valid domain rules, fingerprint catalog, runtime/proposal state, and optional effective host configuration. Values are unredacted; it never performs DNS or target network traffic.` | `readOnlyHint=true`、`destructiveHint=false`、`idempotentHint=true`、`openWorldHint=false` |
| `awesome_tls.settings.propose` | title: `Propose Awesome TLS settings changes`；description: `Validates and records one settings proposal for review in Burp. It never applies settings; approval, rejection, and revert remain local Burp UI actions.` | `readOnlyHint=false`、`destructiveHint=false`、`idempotentHint=true`、`openWorldHint=false` |

Tool list 在 enabled session 内不因调用结果变化，也不发送 `tools/list_changed`。Annotations 只是客户端提示，不能替代服务端副作用和审批边界。

### 16.3 Tool wire schema

以下合同是 v1 wire schema 的规范来源。所有本文拥有的 record 都是 closed object：实现后的 JSON Schema 必须为其设置 `additionalProperties: false`；标记 `?` 的字段可省略，其他字段必须存在。官方 MCP envelope 与 `_meta` 仍按官方 schema 处理，不套用该关闭规则。

`inspect` 的 `inputSchema` 固定为：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "$defs": {
    "bareHostname": {
      "type": "string",
      "minLength": 1,
      "maxLength": 253
    },
    "cursor": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4096
    }
  },
  "oneOf": [
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["schemaVersion"],
      "properties": {
        "schemaVersion": {"const": "awesome_tls.settings.v1"},
        "sections": {
          "type": "array",
          "minItems": 1,
          "uniqueItems": true,
          "items": {
            "enum": [
              "settings",
              "rules",
              "fingerprints",
              "runtime",
              "proposal",
              "effectiveConfig"
            ]
          }
        },
        "hosts": {
          "type": "array",
          "minItems": 1,
          "maxItems": 20,
          "uniqueItems": true,
          "items": {"$ref": "#/$defs/bareHostname"}
        }
      }
    },
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["schemaVersion", "cursor"],
      "properties": {
        "schemaVersion": {"const": "awesome_tls.settings.v1"},
        "cursor": {"$ref": "#/$defs/cursor"}
      }
    }
  ]
}
```

Fresh inspect 省略 `sections` 时返回 `settings`、`rules`、`fingerprints`、`runtime`、`proposal`；若同时提供 `hosts`，再返回 `effectiveConfig`。显式请求 `effectiveConfig` 时必须提供 `hosts`；提供 `hosts` 时，`sections` 若存在则必须含 `effectiveConfig`。Cursor continuation 不接受其他查询字段，不能借 continuation 改变原查询。

`propose` 的 `inputSchema` 固定为：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$defs": {
    "revision": {
      "type": "string",
      "pattern": "^sha256:[0-9a-f]{64}$"
    },
    "address": {
      "type": "string",
      "minLength": 1,
      "maxLength": 1024
    },
    "hostPattern": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255
    },
    "fingerprintName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "clearableString": {
      "type": ["string", "null"]
    },
    "clearableHex": {
      "oneOf": [
        {"type": "string", "pattern": "^(?:[0-9A-Fa-f]{2})*$"},
        {"type": "null"}
      ]
    },
    "settingsPatch": {
      "type": "object",
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "spoofProxyAddress": {"$ref": "#/$defs/address"},
        "interceptProxyAddress": {"$ref": "#/$defs/address"},
        "burpProxyAddress": {"$ref": "#/$defs/address"},
        "fingerprint": {"$ref": "#/$defs/fingerprintName"},
        "hexClientHello": {"$ref": "#/$defs/clearableHex"},
        "useInterceptedFingerprint": {"type": "boolean"},
        "httpTimeout": {"type": "integer", "minimum": 1, "maximum": 3600},
        "externalProxyUrl": {"$ref": "#/$defs/clearableString"}
      }
    },
    "ruleUpsert": {
      "type": "object",
      "additionalProperties": false,
      "required": ["hostPattern"],
      "minProperties": 2,
      "properties": {
        "hostPattern": {"$ref": "#/$defs/hostPattern"},
        "enabled": {"type": "boolean"},
        "fingerprint": {
          "oneOf": [
            {"type": "string", "maxLength": 256},
            {"type": "null"}
          ]
        },
        "hexClientHello": {"$ref": "#/$defs/clearableHex"},
        "externalProxyUrl": {"$ref": "#/$defs/clearableString"},
        "httpTimeout": {
          "oneOf": [
            {"type": "integer", "minimum": 1, "maximum": 3600},
            {"type": "null"}
          ]
        }
      }
    },
    "domainRuleChanges": {
      "type": "object",
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "upsert": {
          "type": "array",
          "maxItems": 100,
          "items": {"$ref": "#/$defs/ruleUpsert"}
        },
        "remove": {
          "type": "array",
          "maxItems": 100,
          "items": {"$ref": "#/$defs/hostPattern"}
        }
      }
    },
    "patch": {
      "type": "object",
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "settings": {"$ref": "#/$defs/settingsPatch"},
        "domainRules": {"$ref": "#/$defs/domainRuleChanges"}
      }
    }
  },
  "type": "object",
  "additionalProperties": false,
  "required": ["schemaVersion", "expectedRevision", "requestId", "patch"],
  "properties": {
    "schemaVersion": {"const": "awesome_tls.settings.v1"},
    "expectedRevision": {"$ref": "#/$defs/revision"},
    "requestId": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[A-Za-z0-9._:-]+$"
    },
    "summary": {"type": "string", "maxLength": 500},
    "acknowledgements": {
      "type": "array",
      "uniqueItems": true,
      "items": {
        "enum": [
          "GLOBAL_HEX_OVERRIDES_FINGERPRINT",
          "RULE_HEX_OVERRIDES_FINGERPRINT",
          "RULE_FINGERPRINT_SUPPRESSES_INHERITED_HEX"
        ]
      }
    },
    "patch": {"$ref": "#/$defs/patch"}
  }
}
```

JSON Schema 只做结构粗筛。`SettingsControl` 继续负责 IDNA/normalization、动态 fingerprint catalog、address/URL 完整解析、`upsert + remove <= 100`、normalized key 冲突、隐藏规则冲突和当前 revision 等二阶段约束。`acknowledgements` 参与 requestId 幂等请求摘要、proposalDigest 和审计，但不进入 settings revision 或 candidateRevision；缺少当前 patch 所需的 acknowledgement 时返回 `AMBIGUOUS_FINGERPRINT_HEX`。

输入省略 `summary` 时 normalize 为输出中的空字符串 `""`；该默认值只用于 closed result/UI/audit，仍不进入 proposalDigest。

### 16.4 Structured output 合同

下列代数数据类型固定两个 tool 的 structured payload。`record` 全部关闭；`A | B` 在 `outputSchema` 中实现为带 discriminator 的 `oneOf`；`[]` 是数组。RFC 3339 timestamp 使用 UTC 且 `maxLength=32`；revision/digest 固定 71 个 ASCII 字符并匹配 `^sha256:[0-9a-f]{64}$`。

```text
StringValue = string(maxLength 262144 chars and <= 256 KiB UTF-8) | ChunkReference
ScalarValue = StringValue | integer | boolean | null
BusinessCode =
  "UNSUPPORTED_SCHEMA" | "VALIDATION_FAILED" | "REVISION_CONFLICT" |
  "DIRTY_UI" | "PROPOSAL_PENDING" | "EXPIRED" |
  "REQUEST_ID_CONFLICT" | "IDEMPOTENCY_CAPACITY" |
  "HIDDEN_RULE_CONFLICT" | "AMBIGUOUS_FINGERPRINT_HEX" |
  "CURSOR_INVALID" | "CURSOR_STALE" | "RULE_FILE_INVALID" |
  "EXTERNAL_DIVERGENCE" | "MERGE_CONFLICT" | "AUDIT_UNAVAILABLE" |
  "CONTROL_DISABLED" | "PERSISTENCE_FAILED" | "RECOVERY_REQUIRED"

ChunkReference {
  kind: "chunk_reference"
  scopeDigest: digest
  path: string
  totalUtf8Bytes: integer >= 0
  sha256: digest
  cursor: string
}

BusinessSettings {
  spoofProxyAddress: string
  interceptProxyAddress: string
  burpProxyAddress: string
  fingerprint: string
  hexClientHello: StringValue
  useInterceptedFingerprint: boolean
  httpTimeout: integer 1..3600
  externalProxyUrl: StringValue
}

DomainRule {
  hostPattern: string
  enabled: boolean
  fingerprint: string
  hexClientHello: StringValue
  externalProxyUrl: StringValue
  httpTimeout: integer 1..3600 | null
}

RuntimeState {
  path: string
  configured: ScalarValue
  active: ScalarValue
  effect: "ACTIVE_NOW" | "NEXT_REQUEST" | "NEXT_START" |
          "RELOAD_REQUIRED" | "RESTART_REQUIRED"
}

FieldChange =
  {operation: "add", path: string, after: ScalarValue} |
  {operation: "replace", path: string, before: ScalarValue, after: ScalarValue} |
  {operation: "remove", path: string, before: ScalarValue}

RiskFlag {
  code: string matching ^[A-Z0-9_]{1,128}$
  severity: "LOW" | "MEDIUM" | "HIGH"
  paths: string[]
  message: string
}

RuntimeImpact {
  path: string
  effect: "NEXT_REQUEST" | "NEXT_START" | "RELOAD_REQUIRED" | "RESTART_REQUIRED"
  requiresUserAction: boolean
  message: string
}

PendingProposal {
  status: "PENDING"
  proposalId: string
  proposalDigest: digest
  baseRevision: revision
  candidateRevision: revision
  createdAt: timestamp
  expiresAt: timestamp
  reviewGeneration: integer >= 1
  summary: string
  diff: FieldChange[]
  riskFlags: RiskFlag[]
  runtimeImpact: RuntimeImpact[]
}

ProposalState =
  {status: "NONE"} |
  PendingProposal |
  {status: "REJECTED", proposalId: string, reason: string, rejectedAt: timestamp} |
  {status: "EXPIRED", proposalId: string, reason: "TTL_EXPIRED", expiredAt: timestamp} |
  {
    status: "CONFLICTED"
    proposalId: string
    code: "REVISION_CONFLICT" | "EXTERNAL_DIVERGENCE" | "MERGE_CONFLICT" | "DIRTY_UI"
    message: string
    details: ErrorDetail[]
    detectedAt: timestamp
    currentRevision: revision
  }

EffectiveConfig {
  host: string
  matchedRuleHostPattern: string | null
  transport: {
    fingerprint: string
    hexClientHello: StringValue
    externalProxyUrl: StringValue
    httpTimeout: integer 1..3600
    useInterceptedFingerprint: boolean
    interceptProxyAddress: string
    burpProxyAddress: string
  }
  sources: {
    fingerprint: string
    hexClientHello: string
    externalProxyUrl: string
    httpTimeout: string
    useInterceptedFingerprint: "GLOBAL_DEFAULT"
    interceptProxyAddress: "GLOBAL_DEFAULT"
    burpProxyAddress: "GLOBAL_DEFAULT"
  }
  tlsResolution: {
    staticMode: "HEX_CLIENT_HELLO" | "FINGERPRINT" | "LIBRARY_DEFAULT"
    runtimeMode: "STATIC" | "INTERCEPTED_IF_AVAILABLE_ELSE_STATIC"
    selectedPath: string | null
    suppressedPaths: string[]
  }
}

SectionContinuation {
  section: "rules" | "fingerprints" | "runtime" | "proposal" | "effectiveConfig"
  cursor: string
}

InspectPage {
  kind: "inspect_page"
  schemaVersion: "awesome_tls.settings.v1"
  revision: revision
  dirty: boolean
  dirtyReasons: ("ACTIVE_CELL_EDITOR" | "PENDING_AUTOSAVE" | "UNSAVED_UI_DRAFT")[]
  hiddenInvalidRuleCount: integer >= 0
  sections: {
    settings?: BusinessSettings
    rules?: DomainRule[]
    fingerprints?: string[]
    runtime?: RuntimeState[]
    proposal?: ProposalState
    effectiveConfigs?: EffectiveConfig[]
  }
  continuations?: SectionContinuation[]
}

InspectChunk {
  kind: "inspect_chunk"
  schemaVersion: "awesome_tls.settings.v1"
  revision: revision
  scopeDigest: digest
  path: string
  offsetUtf8Bytes: integer >= 0
  totalUtf8Bytes: integer >= 0
  sha256: digest
  data: string
  nextCursor?: string
}

ProposalPendingResult {
  kind: "proposal_result"
  schemaVersion: "awesome_tls.settings.v1"
  status: "PENDING"
  proposalId: string
  proposalDigest: digest
  baseRevision: revision
  candidateRevision: revision
  createdAt: timestamp
  expiresAt: timestamp
  reviewGeneration: integer >= 1
  summary: string
  diff: FieldChange[]
  riskFlags: RiskFlag[]
  runtimeImpact: RuntimeImpact[]
}

ProposalNoChangesResult {
  kind: "proposal_result"
  schemaVersion: "awesome_tls.settings.v1"
  status: "NO_CHANGES"
  revision: revision
  diff: []
  riskFlags: []
  runtimeImpact: []
}

ErrorDetail {
  path?: string
  reason: string
  expected?: ScalarValue
  actual?: ScalarValue
}

BusinessError {
  kind: "error"
  schemaVersion: "awesome_tls.settings.v1"
  status: "ERROR"
  code: BusinessCode
  message: string
  details: ErrorDetail[]
  retryable: boolean
  currentRevision?: revision
}
```

`inspect.outputSchema = InspectPage | InspectChunk | BusinessError`；`propose.outputSchema = ProposalPendingResult | ProposalNoChangesResult | BusinessError`。`NO_CHANGES` 是成功结果，`isError=false`。业务错误的 `isError=true`。每个 `CallToolResult` 固定只含一个 text content；其 `text` 必须是 `structuredContent` 的 JCS serialization。`outputSchema` 只描述 `structuredContent`，外层 `CallToolResult` 另按官方 MCP schema 校验。

`FieldChange` 永远是 leaf-field diff，不能把整条 rule 塞入开放 object。其 `path` 只是输出定位符，不是可写 patch path：global field 使用 RFC 6901 形式 `/settings/<field>`；rule field 使用 `/domainRules/byHost/<escaped-normalized-hostPattern>/<field>`。Rule host key 变更表示旧 key 的逐字段 remove 加新 key 的逐字段 add。`RiskFlag.paths`、`RuntimeImpact.path` 和错误 detail path 复用该输出语法。Effective source 固定返回 `GLOBAL_DEFAULT` 或 `RULE:<normalized-hostPattern>`。

Effective-config 是本地可确定的、发送给 Go server 前的 request `TransportConfig` 视图，不含 request-only `Host`、`Scheme`、`HeaderOrder`，也不把 spoof listener address 混入 transport。若 global Hex 与 fingerprint 同时存在，`tlsResolution.staticMode` 必须显示 Hex 胜出并把 fingerprint path 列入 `suppressedPaths`；rule fingerprint/Hex 使用第 6.3 节的 paired precedence。`useInterceptedFingerprint=true` 时，实际 Go runtime 只有在已捕获值存在时才覆盖 static selection，因此返回 `INTERCEPTED_IF_AVAILABLE_ELSE_STATIC`，不得通过网络或猜测伪造最终捕获值。

三方合并改变 candidate 时，保留同一 `proposalId`，生成新的 `proposalDigest`，递增 `reviewGeneration`，替换完整 diff/risk/runtime impact，并把 proposal 留在 `PENDING`；之前的 UI 确认只对旧 generation 生效，用户必须重新查看并再次点击 Apply。检测到不可合并冲突时进入 `CONFLICTED`，占用 pending slot，直到用户 Reject、TTL 到期或 session 结束。

只有类型显式为 `StringValue` 或包含它的 `ScalarValue` 字段才参与分块：UTF-8 长度不超过 256 KiB 时内联，超过时替换为 `ChunkReference`。所有类型为普通 `string` 的字段永不分块，machine-readable output schema 必须编码其字符上限，SettingsControl 还须执行 UTF-8 byte 上限：`summary` 仍限 500 字符且最多 4096 bytes；UI reject reason、conflict/error/risk/runtime message 与 detail reason 最多 4096 bytes；非 enum 的 risk `code` 必须匹配 `^[A-Z0-9_]{1,128}$`；timestamp 最多 32 ASCII 字符；revision/digest 固定 71 ASCII 字符；fingerprint 名最多 256 字符/1024 bytes；address、path、source、ID 和 cursor 最多 4096 bytes；exact host 最多 253 ASCII bytes，rule `hostPattern` 因允许最左侧 `*.` 最多 255 ASCII bytes；其他 enum/fixed literal 的可取值本身就是其上限；`InspectChunk.data` 是唯一大普通字符串例外，最多 256 KiB 且不会再次分块。未来任何可能超过其普通 string 上限的新字段必须显式改用 `StringValue` 并更新 schema，不得在运行时偷偷改变 locked type。分块只在 Unicode scalar 边界切割，`offsetUtf8Bytes` 与 `totalUtf8Bytes` 按 UTF-8 byte 计；单块 `data` 不超过 256 KiB。Cursor 是由本 enabled session 签发并完整性保护的不透明值，绑定业务 revision、section、该 section 的当前 content digest、原查询摘要、path、offset，以及适用时的 proposal digest；它不是客户端认证凭据。Section content digest 与 string `sha256` 都从未分块完整 logical value 计算，排除 cursor、ChunkReference 和 page boundary，随后才生成 wire reference，因此不存在自引用。`scopeDigest` 对 committed string 使用 revision，对 proposal string 使用 proposal digest，对不进入 revision 的动态 section 使用 section content digest。Cursor 可取的 path 必须来自 allowlist，不得据任意客户端 path 读取数据；disable/unload 或任一绑定 digest 变化后返回 `CURSOR_STALE`。

每个 inspect structured payload 经允许字段分块后仍以 1 MiB UTF-8 为最大值；数组在完整 record 边界分页，顺序稳定，并为每个尚未完成的 section 返回独立 continuation。`settings` 不分页；`effectiveConfigs` 保持输入 host 顺序；rules 保持有效规则的磁盘顺序；fingerprints 使用 catalog 的稳定排序。不得为分页或分块缓存完整敏感值。

实现时须将 v1 schemas 作为 machine-readable resource 纳入 jar，并从上述 closed records 生成或人工维护后做 golden 校验。`tools/list` 发布的每个 `inputSchema`/`outputSchema` 必须自包含或已 dereference，不能含客户端无法解析的本地外部 `$ref`。Golden test 必须精确比较完整 `tools/list` schema，防止只剩宽泛的 `{"type":"object"}`。

### 16.5 HTTP engine Spike

在锁定依赖前，必须用真实 Burp bundled runtime 做 release-blocking Spike。候选 engine 由证据选择，要求：

- 能在 Burp 中启动、关闭、重复启停和 unload；
- 不依赖 Burp runtime 当前可能缺失的 `jdk.httpserver`；
- 与 fat jar 打包、classloader 和现有 JNA/Gson 依赖兼容；
- 不要求引入完整 Servlet container；
- 不手写通用 `ServerSocket` HTTP parser；
- 能通过官方 schema/conformance 和真实 Codex E2E。

若没有候选通过 Spike，则重新评估或等待官方 Java SDK 3.x；不自动降级到 2025 协议，也不发布 partial beta 冒充完成。

### 16.6 Java 基线

Gradle 明确锁定 Java 17 toolchain，避免由开发机当前 JDK 隐式决定 bytecode。未来官方 Java SDK 可在保持 `SettingsControl`、schema、审批和审计合同不变的前提下替换 MCP adapter，但协议或行为变化仍需更新 ADR。

## 17. Verification Gates

### 17.1 SettingsControl 单元与故障注入

至少覆盖：

- inspect 和 propose 对业务设置无副作用；
- canonical normalization 与 revision 稳定；
- UI、import 和 MCP 使用同一 validator；
- unknown、越权、非法、duplicate 和 ambiguous patch 被一致拒绝；
- 无效 raw rule 保留但不进入 matcher 或 inspect；
- RuleStore v1 wrapper、legacy bare array、strict unknown/null/blank failure 与 blocking repair UX；
- legacy config-directory adopt、legacy Preferences DomainRules fallback 及其 journal-first bootstrap 顺序；
- exact/wildcard/longest-suffix 与 fingerprint/Hex precedence 不回归；
- leading-dot wildcard alias 与 `*.` canonical key 冲突被一致识别；
- matching、未过期且显式批准的 proposal 才能改变设置；
- requestId 幂等、TTL、单 pending、rate、concurrency、body 和 rule-change 限制；
- dirty UI、revision、Preferences divergence 和 rule digest 冲突不覆盖用户数据；
- field-level 三方合并、delete/modify 冲突和 re-review；
- inspect/propose 的 rule-file probe 在文件损坏时无任何 move/quarantine/write 副作用；
- `saveIfUnchanged` 在最后 digest 不匹配时不替换外部文件，并保留可恢复 backup；
- commit decision 前的 Preferences 可观察写后复核失败或 RuleStore 故障都不发布新 snapshot；真实 Preferences adapter 的测试只宣称 `set*` 未抛错与全 key reread digest 匹配，不把不可观察 flush 当成已验证；
- commit decision 前 compensation/启动 rollback、commit decision 后 forward recovery，以及 unknown-digest unrecoverable 状态；
- audit ON 的 commit-decision 故障矩阵：matching `MUTATION_COMMITTED` 已 durable 但 journal phase 未更新时 forward；能确定 committed event 不存在时 rollback；append/audit 状态截断、损坏或不可判定时阻断且不发布；
- `COMMIT_READY` 启动恢复显式覆盖 audit ON + matching event、ON + confirmed absent event、ON + missing/corrupt/unreadable ambiguous audit，以及 audit OFF 四条分支；
- `COMPLETE` journal 在 cleanup failure 后重启时覆盖全 candidate 的 cleanup 路径，以及 Preferences 回到 known-old/partial digest 后幂等 forward rewrite candidate 的路径；两者都不回滚、不生成新业务 revision/审批，unknown digest 才阻断；
- audit ON + `COMPLETE` 还必须分别覆盖 matching、missing、corrupt committed event；后两者阻断，不得凭 journal phase 前滚或重建 committed event；
- snapshot 与 RuleMatcher 始终原子配对；
- configured/active runtime impact 正确；
- 独立 RuntimeStatePort 能报告 spoof/intercept 的真实 bind 成功、失败、停止、active addresses 和 last error；Go 并发状态通过 `go test -race` 或等价 race gate；
- audit ON 写失败对读写均 fail closed；
- AI revert 的 revision 与生命周期限制。

### 17.2 Swing 集成

- 第四个 tab、启用警告、pending badge、完整 diff、Hex 折叠/复制、二次确认和审计详情可用；
- pending proposal 不抢焦点、不自动弹 modal；
- approval 后只在 EDT 更新 UI；
- 刷新不触发 rules autosave loop；
- 活动 editor 和 draft 不被覆盖；
- 端口只能在 disabled 状态编辑；
- listener failure 和 audit failure 显示明确阻断状态。

### 17.3 MCP、Burp 与 Codex E2E

正式发布前必须在真实 Burp 中用 Codex Desktop 和 Codex CLI 分别验证：

```text
server/discover
  -> tools/list
  -> awesome_tls.settings.inspect
  -> awesome_tls.settings.propose
  -> Burp UI approve/reject
  -> awesome_tls.settings.inspect
```

同时验证：

- 官方 MCP `2026-07-28` schema/conformance；
- 所有强制 header、body `_meta`、header/body mismatch、未知 method 和 error mapping；
- `Mcp-Method` 对所有 request 必填匹配；`Mcp-Name` 对 `tools/call`、未实现的 `resources/read` 与 `prompts/get` 分别按 `params.name`、`params.uri`、`params.name` 校验，且 header mismatch 优先于 method-not-found；`Last-Event-ID` 被忽略且不 resume；
- dual-value `Accept`、固定 JSON response、HTTP notification POST 400/no state change、GET/DELETE 405、unknown method 404/`-32601` 和 HeaderMismatch `-32020`；
- exact Host 通过，错误 Host 与任意 Origin 被拒绝，无 CORS；
- full credentials 与 large Hex 的直接和 cursor 输出；
- bind failure、重复启停、manual disable 与 extension unload；
- unload 后端口、线程、pending、幂等和 revert 状态全部释放；
- inspect/effective query 不产生 DNS 或目标网络流量；
- fat jar 在受支持 Burp runtime 中独立加载；
- Java/Go `TransportConfig` 合同没有因本功能改变。

只把实际完成上述 E2E 的 Codex Desktop/CLI 版本写成 verified support。其他原生 MCP 客户端不得在没有对应测试的情况下宣传为正式支持。

## 18. 推荐实施顺序

1. 锁定 Java 17 toolchain，建立纯 Java `SettingsControl` domain model、snapshot、validator、revision 和 matcher seam。
2. 将现有 SettingsTab save、rules autosave 和 import 迁移到该 seam，并先验证现有 UI 行为不回归。
3. 增加 transaction journal、fault-injection adapter、compensation 和启动恢复。
4. 实现 proposal、diff、risk、三方合并、approval 和 in-memory revert。
5. 实现第四个 AI Control tab 与完整审计。
6. 完成真实 Burp HTTP engine Spike，再实现最小 MCP `2026-07-28` adapter。
7. 完成 SettingsControl、Swing、官方 conformance 和 Codex Desktop/CLI E2E gates 后再宣称功能完成。

不得先让 MCP handler 直接调用现有 setters，再补 revision、事务或 UI 同步；这会固化本 ADR 要消除的分叉。

## 19. 完成定义

只有同时满足以下条件，AI Settings Control 才可视为完成：

- 本文所有锁定行为已实现，没有 Token、默认脱敏、AI apply 或协议降级等方向漂移；
- 两个 tool 的 schema、错误和副作用边界稳定；
- Burp UI 是唯一 approval/reject/revert 权限边界；
- 持久化故障、外部修改、dirty UI 和 unload 均不会产生静默覆盖或混合 runtime；
- 完整敏感值、无认证和 plaintext audit 的风险在每次 enable 时准确呈现；
- Java 17、真实 Burp、官方 MCP conformance 与 Codex Desktop/CLI E2E 全部通过并留有可复核结果。

## 20. 参考资料

- [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP 2026-07-28 base protocol and error codes](https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes)
- [MCP 2026-07-28 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP Java SDK changelog](https://github.com/modelcontextprotocol/java-sdk/blob/main/CHANGELOG.md)
- [MCP Java SDK 3.x milestone](https://github.com/modelcontextprotocol/java-sdk/milestone/28)

## 21. 实现记录（2026-08-25）

本节记录实现结果与验证状态，不改变上文任何已接受决策。

### 21.1 HTTP engine Spike 结论（§16.5）

Burp 自带运行时为 **JRE 24.0.1，且 `java --list-modules` 中没有 `jdk.httpserver`**，`com.sun.net.httpserver` 不可用，这与 §16.5 的担忧一致。选定 **Jetty 12 core（`org.eclipse.jetty:jetty-server:12.0.16`）**：5 个 jar 约 2.1 MB，不需要 Servlet container，不依赖 XNIO，不使用 `jdk.httpserver`，且不需要手写 HTTP parser。已在 Burp 自带 JRE 上验证重复启停、端口释放、无残留线程、端口冲突以 `IOException` 失败且不改端口。

### 21.2 已实现并有自动检查覆盖

- `SettingsControl` 单一 seam、原子发布 snapshot + matcher、staged commit、唯一 commit decision、补偿与启动恢复（`burp.control.SettingsControlCheck`，含故障注入与全部 phase 的恢复矩阵）；
- canonical 化与 revision，含 §8.1 golden vector（`burp.control.Jcs`、`burp.control.SettingsSnapshot`）；
- 共享 `HostKey` normalization、共享 validator、无效/重复 raw row 不进入 matcher 的行为修正（`burp.control.HostKey`、`Validation`、`burp.RuleMatcher`）；
- RuleStore v1 wrapper / legacy bare array / strict 失败、无副作用 `probe()`、`saveIfUnchanged`（`burp.RuleStore`）；
- proposal 生命周期、幂等、TTL、单 pending、三方合并与 re-review、AI revert 限制（`burp.control.AiSettingsServiceCheck`、`ThreeWayMerge`、`Proposal`）；
- MCP `2026-07-28` adapter：§15 错误映射逐行、header 合同、gate、限流与并发上限、固定 discovery/tools 合同与 schema golden 比较（`burp.control.McpServerCheck`，对真实 listener 发起）；
- inspect / propose 不做 DNS：通过 `java.net.spi.InetAddressResolverProvider` 计数器实测为 0（`./gradlew noNetworkCheck`）；
- Go 侧独立 `RuntimeStatePort`：新增 `runtimestatus.go` 与 `GetRuntimeStatus` cgo 导出，`TransportConfig` 未改动；并发状态通过 `go test -race`；
- external proxy URL v1 合同的 Java/Go 双向 golden vectors（`burp.control.ProxyUrl` 与 `src-go/server/proxyurl_test.go`）；
- fat jar 在 Burp 自带 JRE 24 上独立加载并跑通全部自检；扩展在替身 Montoya API 下可初始化、建 UI、启停 MCP 并 unload（`./gradlew extensionSmoke`）。

### 21.3 尚未完成的 gate

- **§17.3 的 Codex Desktop / Codex CLI 真实 Burp E2E 未执行**，需要这两个客户端与运行中的 Burp，无法在此环境自动化。在完成并留档之前，不得按 §19 宣称功能完成，也不得把任何客户端写成 verified support。
- §17.2 的 Swing 集成项为人工检查项，尚未在真实 Burp 界面中逐项走查。
- v1 未签发 cursor，因此 `ChunkReference` / `InspectChunk` 路径已在 schema 与错误码中就位，但未产生真实分块输出；带 cursor 的 inspect 一律返回 `CURSOR_INVALID`。
- `Mcp-Name` 的 `=?base64?...?=` sentinel 解码按本文字面实现，并兼容 RFC 2047 的 `=?utf-8?B?...?=` 拼写；E2E 时须对照官方规范确认。

## 22. 修订记录 R1：会话级 auto-apply（2026-08-25，用户明确批准）

### 22.1 变更内容

新增一个 Burp UI 开关「Apply changes automatically, without review」。开启期间，`propose` 在通过全部校验后**立即提交**，不再进入待审队列，返回新的 `status: "APPLIED"` 结果（含 `revision`、`appliedAt` 和实际提交的 diff/risk/impact）。

### 22.2 未变更的部分

这次修订移除的**只有人工闸门**，其余全部保留：

- 仍然**没有** AI 可调用的 apply/approve/reject/revert tool。tool 集合仍是 `inspect` 和 `propose` 两个，开关只能由用户在 Burp 中拨动；
- 校验、canonical revision、fingerprint/Hex acknowledgement、hidden-rule 冲突检查全部不变；
- 事务日志、补偿、启动恢复、唯一 commit decision 不变；
- 完整审计 ON 时仍然 fail closed：写不进审计的变更不会发生；
- `rules.json` 三方合并不变。auto-apply 下若干净合并改变了结果，直接提交合并结果并在 `APPLIED` 的 diff 中如实返回（无人可复审，返回旧 diff 会是谎报）；
- dirty UI、revision 冲突、rule-file invalid 仍然阻断；
- `Revert last AI apply` 不变。

### 22.3 开关的约束

**（2026-08-26 修订：见 §24。以下前两条已作废，其余保留。）**

- **默认关闭**，且**不持久化**；
- 勾选时弹出二次确认，说明「本机任何进程可无提示改变设置，包括上游代理和监听地址」；
- 关闭 AI Control 监听器时自动解除，重新启用不会恢复；
- 与 §3 中其他 control-plane 设置一致：不进入业务 revision，不使待审 proposal 失效。

### 22.4 为什么接受这个风险

端点无认证，因此 auto-apply armed 期间，本机任意进程都能无提示改写设置。用户在了解该后果后明确选择了这一模式，理由是指纹调试属于「propose → 应用 → 验证 → 再来一轮」的紧密循环，每轮一次点击加 15 分钟 TTL 的成本过高。

会话级、默认关闭、需二次确认，是在满足该需求的前提下能保留的最强约束：它把「无认证端点可静默改设置」限定为用户当天主动武装过的状态，而不是一个装完就永久生效的属性。

### 22.5 合同影响

- `propose` 的 `outputSchema` 增加 `APPLIED` 变体（`src/main/resources/mcp/propose-output.json`）；
- `tools/list` 中 `propose` 的 description 与 `server/discover` 的 `instructions` 随开关变化，如实描述当前行为——armed 时仍宣称「never applies settings」比没有描述更糟；
- §19 完成定义中的「Burp UI 是唯一 approval/reject/revert 权限边界」按本节修订理解：**权限边界仍在 Burp UI**（只有用户能拨动开关），但 armed 期间不再逐次审批。

## 23. 修订记录 R2：风险确认改为持久化（2026-08-26，用户明确批准）

### 23.1 变更内容

§5 要求「每次启用必须显示阻断式说明，并要求用户主动勾选一次『我理解并接受本机进程可读取完整敏感设置』的 checkbox」。本次修订把**勾选**的范围从「每次启用」放宽为「一次，之后记住」，存入 Preferences（`AiControlRiskAcknowledged`）。

### 23.2 未变更的部分

- **说明本身仍然每次显示**（**2026-08-26 修订：见 §25，改为确认后折叠**）。监听器未运行时警告区始终在屏幕上，内容不变：无认证、本机任意进程可读全部凭据与 Hex、可提交变更、当前完整审计开关状态；
- **enable 状态仍不持久化**（§5、§7）。每次 Burp 启动仍必须手动开启，端点不会自行回来；
- **auto-apply 仍是会话级、默认关闭、需二次确认**（§22.3），不受本次修订影响；
- 未勾选时 Enable 按钮仍不可用；取消勾选即恢复阻断。

### 23.3 为什么

被确认的风险是**端点的属性**，不是当天会话的属性——它在两次重启之间不会改变。反复收集同一个勾选并不产生新的知情同意，只是把一次真实的决定退化成肌肉记忆，这反而削弱了 §5 想要的效果。§5 真正保护的是「用户看见这个事实」，而看见由每次都显示的警告区保证，不由点击保证。

原实现还在**关闭监听器时清空勾选**，于是同一会话内关掉再开也要重勾一次；这一条一并移除。

### 23.4 合同影响

- 新增一个 control-plane 持久化项 `AiControlRiskAcknowledged`。与 §3 中其他 control-plane 设置一致：不进入业务 revision，不使待审 proposal 失效；
- §19 完成定义中「每次 enable 时准确呈现无认证/完整敏感值/plaintext audit 风险」按显示理解，不再要求逐次重新勾选。

## 24. 修订记录 R3：auto-apply 改为持久化（2026-08-26，用户明确批准）

### 24.1 变更内容

§22.3 规定 auto-apply「默认关闭，且不持久化」，并在关闭监听器时自动解除。本次修订保留默认关闭与二次确认，取消不持久化与自动解除：开关存入 Preferences（`AiControlAutoApply`），跨重启保留。

### 24.2 未变更的部分

- **enable 状态仍不持久化**，且这是本节唯一不放宽的一条。监听器每次启动都是关闭的，只有用户能打开它；
- 首次武装仍弹二次确认，文案改为如实说明「会被记住，但监听器不会」。恢复一个已存储的武装状态不再弹窗——那是重复收集同一次同意；
- `tools/list` description 与 `server/discover` instructions 仍随开关如实变化；
- 校验、事务日志、审计 fail-closed、三方合并、`Revert last AI apply` 全部不变。

### 24.3 为什么可以接受

§22.4 把会话级作为约束的理由是「限定为用户当天主动武装过的状态」。但真正承担该约束的不是 auto-apply 的会话性，而是 **enable 的会话性**：端点每次启动都是关闭的，armed 与否在它打开之前不产生任何可观察行为。存储的武装状态决定的是「用户主动打开端点之后如何表现」，而不是「端点是否会自己打开」。

在此前提下，每次重启重新武装并不缩小攻击面——攻击面由端点是否打开决定——只是把 §23 里那个「反复收集同一个勾选」的问题换了个控件重演一遍。指纹调试是紧密循环，这一步的成本是真实的。

### 24.4 合同影响

- 新增 control-plane 持久化项 `AiControlAutoApply`。与 §3 一致：不进入业务 revision，不使待审 proposal 失效；
- §22.3 中「不持久化」与「关闭监听器时自动解除」两条按本节修订作废，其余各条保留。

## 25. 修订记录 R4：风险说明改为确认后折叠（2026-08-26，用户明确批准）

§23.2 承诺「说明本身仍然每次显示」。本次修订把整个 `Before you enable this` 区块改为**确认后隐藏**：未勾选时全文展开且 Enable 不可用；勾选后整块消失，视觉上与监听中的状态一致；取消勾选即重新出现并重新阻断 Enable。

确认 checkbox 因此移到顶部工具栏，与 auto-apply、完整审计两个开关同排，标签缩短为 `Risk acknowledged`（完整句子进 tooltip）。它必须留在区块之外：一个把自己藏起来的控件无法被取消勾选。缩短的标签不会造成信息缺口——在勾选之前，完整句子始终在屏幕上，勾选是读过它之后才可能发生的动作。

§4.2 要求在决策时刻呈现的完整审计状态与 auto-apply 状态：未勾选时仍在区块内以完整句子呈现；勾选后由工具栏上那两个常驻 checkbox 承担，它们的标签本身就是行为描述（"Apply changes automatically, without review" / "Record everything to the audit trail"）。

理由与 §23.3 相同：说明的作用是让用户读到一次，而不是让它永久占据版面。隐藏是可逆的，取消勾选就能重新读到全文，这也是它重新阻断 Enable 的同一个动作。

## 26. 已知边界（2026-08-26）

以下都是设计取舍的直接后果，不是缺陷。记在这里，是为了下次有人把它们当 bug"顺手修掉"之前先读到理由。

### 26.1 隐藏规则对客户端是死路

一旦某行进入 §8.2 的隐藏状态（结构非法、或与另一行 normalized key 重复），**任何 MCP 客户端都无法再触碰它**——`HIDDEN_RULE_CONFLICT` 同时拦住 upsert 和 remove。用户必须在 Burp UI 里修好或删掉。

remove 看上去比 upsert 安全，因此"至少允许 AI 删掉隐藏行"是个反复会被提起的提议。**不要放宽**：隐藏行最常见的来源就是用户正在编辑、还没填完的一行，而"删掉用户正在编辑的行"是这里最坏的结果，比"用户多点两下"糟得多。inspect 也只返回 `hiddenInvalidRuleCount`、不返回内容（§8.2），所以客户端连自己要删什么都看不见——在这个前提下允许删除等于允许盲删。

`HIDDEN_RULE_CONFLICT` 的 message 必须继续指明"先在 Burp 里修复或删除这些行"，因为那是唯一出路。

### 26.2 propose 不能造出隐藏行（2026-08-26 修复）

上一条只在隐藏行**由用户造成**时才是可接受的取舍。曾经有一段时间不是：逐条校验 upsert 时用 `SettingsSnapshot.ruleByKey` 查找，而那张索引只收录通过校验的行，于是被 patch 改成非法的规则查不到、循环跳过、"靠什么都没找到"通过校验，最后以 `APPLIED` + **空 diff** 落盘成一条隐藏行——客户端造出了一个自己收不了的场。

其它非法字段从未暴露该缺口，因为 input schema 在上一层就挡掉了；`note` 的唯一约束是长度上限，成为第一个走到缺口的字段。

修复固定为两层，改动任一层前先读本节：

1. 逐条校验从**存储**中查找该 key 的行（`storedRuleWithKey`），那里才有 patch 自己的产物，与快照要不要用它无关；
2. 兜底不变式：**一次 proposal 不得增加 `hiddenInvalidRuleCount`**。逐字段检查点不出名字的情况（host pattern 烂到无法 normalize、新引入的重复 key）由它覆盖。

不变式的理由一句话即可记住：**一条落地即隐藏的规则，是一条 diff 没有描述的规则**，而 diff 是 §11 里 auto-apply 唯一的事后交代。

### 26.3 rule `note` 不影响运行时，但进 revision

`note`（§8.1 rule 字段）不跨 JNA、不进 `TransportConfig`、不参与匹配。它仍然进入 canonical document 和 revision，因为 `rules.json` 是三方合并的 base：备注若不进摘要，两条只差备注的行摘要相同，下一次合并会无冲突地丢掉其中一条。

因此**升级到带 `note` 的版本会使既有配置的 revision 迁移一次**，客户端手上的 `expectedRevision` 会失效一次，重新 inspect 即可。同理，旧版 `RuleStore.parse` 的严格解析会把 `note` 当未知字段拒绝，**降级前必须先移除该字段**。
