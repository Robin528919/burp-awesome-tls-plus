# 需求：AI Control 面向多客户端

- 状态：已实施（2026-08-26）。P0 R1–R5 全部落地，ADR-0001 已同步至 §27；R6 挂起，重启条件见 §4
- 日期：2026-08-26
- 上游规范：[ADR-0001](../decisions/0001-ai-settings-control-via-embedded-mcp.md)
- 范围：`AiControlPanel` 的 *Connect a client* 区域、`skills/awesome-tls-mcp/SKILL.md`
- 不在范围：`McpServer` 的协议层行为（见 §4 R6）

## 1. 问题

AI Control 的连接区只给了 Claude Code 和 Codex 两条命令，读起来像是"只支持这两个客户端"。
但这个印象和真实的限制**不是一回事**，两者都需要处理：

### 1.1 真实限制在协议层，不在按钮

`McpServer` 只接受 `MCP-Protocol-Version: 2026-07-28`，不实现 `initialize`，拒绝一切
notification 和任何 `Origin` 头（ADR §16.1，故意如此）。对运行中的端点实测：

| 请求 | 结果 |
| --- | --- |
| legacy `initialize`，`MCP-Protocol-Version: 2025-11-25` | `400` / `-32022`，`supported: ["2026-07-28"]` |
| 省略 `MCP-Protocol-Version`（规范允许服务器按 `2025-03-26` 处理） | `400` / `-32022` |
| `2026-07-28` + `Mcp-Method` + `Mcp-Name` | `200`，正常返回 |

MCP 官方对 2026-07-28 服务器的建议是**同时**回答 legacy `initialize`，让仍在 `2025-11-25`
的客户端继续可连；四个官方 SDK 的 2026-07-28 支持在本文日期仍是 beta。本项目选择不这么做。

**结论：给某个客户端加一个注册按钮，不会让它连上。** 按钮解决的是发现性，不是兼容性。

### 1.2 Skill 分发已经是跨工具标准，现有两个按钮一错一旧

Agent Skills（`SKILL.md`）自 2025-12-18 起是开放标准，30+ 工具共用同一目录约定。
OpenCode 明确扫描 `~/.claude/skills/*/SKILL.md` 与 `~/.agents/skills/*/SKILL.md`；
Cursor、Gemini CLI、Copilot / VS Code 同理。

- `Install skill: Claude Code` 写入 `~/.claude/skills/`，**事实上已经覆盖**上述全部客户端。
  问题只是名字让人以为它专属 Claude Code。
- `Install skill: Codex` 往 `~/.codex/AGENTS.md` **追加** 162 行。Codex 自 2025-12 起读
  `~/.codex/skills/*/SKILL.md`；追加到 AGENTS.md 会把这份文档变成 Codex 的全局常驻指令，
  且重复执行会留下多份副本（现有面板文案已自认这一点）。

### 1.3 Skill 不能替代 MCP 服务端，但可以替代 MCP 客户端

`SKILL.md` 是纯文本，没有执行能力 —— 去掉 MCP 等于去掉全部能力。
但一次普通 `POST` 就能完成 `tools/call`，只需 5 个 header，`params._meta` 实测并非必填：

```
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: awesome_tls.settings.inspect
```

任何能执行 shell 的 agent 都可以走这条路，**与其 MCP 实现版本无关**。
`SKILL.md` §7 已经写了这些 header，但标题是 "Raw HTTP (debugging only)"，被当成排错附录。
这是当前唯一与客户端无关的通道，应当按正式通道对待。

## 2. 目标与非目标

### 2.1 目标

- 任何主流 agent 客户端的用户，都能拿到这份 skill 并成功操作扩展 —— 原生 MCP 走不通时走 HTTP。
- 面板如实说明哪些客户端已验证、哪些是 best-effort、连不上时怎么办。

### 2.2 非目标

- **不为每个客户端加一个按钮。** 40+ 客户端，而 skill 路径本就共享、MCP 配置本就是同一段 JSON；
  逐个列举会在每次客户端更名或改路径时腐烂。
- **不去掉 MCP。** 见 §1.3。
- **不在本次放宽协议层。** 见 §4。

## 3. P0 需求

### R1 — skill 安装按钮改名并写标准路径

按钮文案改为 **Install skill (all agents)**，一条命令把 `SKILL.md` 落到两个通用路径：

- `~/.claude/skills/awesome-tls-mcp/SKILL.md` — Claude Code、OpenCode、Cursor、Copilot、Gemini CLI
- `~/.agents/skills/awesome-tls-mcp/SKILL.md` — 中立标准路径

下载一次、复制到第二处，不用符号链接（Windows 上不可靠）。

**验收**：在只装了 OpenCode 的机器上执行该命令后，OpenCode 能列出 `awesome-tls-mcp` skill。

### R2 — Codex 按钮改写 skills 目录

改为写 `~/.codex/skills/awesome-tls-mcp/SKILL.md`，**不再追加 `AGENTS.md`**。
配套删掉面板上"运行两次会留两份副本"那句 —— 它描述的是被移除的行为。

**验收**：重复执行两次，`~/.codex/skills/awesome-tls-mcp/SKILL.md` 内容与源文件逐字节相同；
`~/.codex/AGENTS.md` 未被触碰。

### R3 — `SKILL.md` §7 升级为正式的 HTTP 通道

标题由 "Raw HTTP (debugging only)" 改为面向"没有可用 MCP 客户端"的正式章节，内容补齐：

- 完整可直接复制的 `tools/list`、`inspect`、`propose` 三条 `curl`；
- 明确 `params._meta` 非必填；
- 明确这条路径**不改变授权模型** —— `propose` 仍然只是登记提议，仍需在 Burp UI 批准。

**验收**：把文档里的 `curl` 原样粘贴进终端，对运行中的端点分别得到 `200` 与预期 JSON。

### R4 — 连接区文案改为三段式

替换现有那段"注册即可用"的暗示，明确分层：

1. **已验证** — Codex Desktop / Codex CLI（ADR §17.3 的 E2E 对象）；
2. **Best-effort** — 其他实现 MCP `2026-07-28` 的原生客户端；仍在 `2025-11-25` 或更早的客户端
   会收到 `400` / `-32022`，这不是配置错误；
3. **兜底** — 连不上的客户端用 R3 的 HTTP 通道，能力完全相同。

**验收**：面板文案中不出现"任何 MCP 客户端都能连"一类无条件表述。

### R5 — JSON config 按钮补 OpenCode 变体

现有 `mcpServers` 形状对 OpenCode 无效。补一个变体：

```json
{
  "mcp": {
    "awesome-tls": { "type": "remote", "url": "http://127.0.0.1:8885/mcp", "enabled": true }
  }
}
```

**验收**：贴进 `opencode.json` 后 OpenCode 能解析（能否握手成功取决于其 MCP 版本，见 R4 第 2 层）。

## 4. R6 — 双时代 MCP 兼容（挂起）

额外接受 `2025-11-25` 并实现 legacy `initialize` / `notifications/initialized`，
是让其他客户端**原生**连上的唯一途径。本次不做，原因：

- 需要修改 ADR §16.1 的既有决策（该节明确禁止把非 2026-07-28 行为标注为兼容）；
- 需要新增一整条 legacy 请求路径及其自检，`McpServerCheck` 的固定合同要相应扩展；
- 扩大未认证接口面 —— 当前每个 gate 都是拒绝面，放宽任何一个都要重走 ADR §4.2 的风险论证；
- **最关键**：目前没有任何一个客户端的实测数据证明"只差这一步"。

**重启条件**（满足任一）：

- 实测确认某个用户实际在用的客户端，除协议版本外其余全部就绪；
- 官方 SDK 的 2026-07-28 支持转 GA 且主流客户端完成升级，届时 R6 的价值反而下降。

**过渡期**：R3 的 HTTP 通道就是这些客户端的可用路径，能力无损，只是不出现在客户端的工具列表里。

## 5. 需要同步修改的 ADR-0001 章节

| 章节 | 改动 |
| --- | --- |
| §1 决策摘要 | "其他符合 MCP `2026-07-28` 的原生客户端仅提供 best-effort 兼容"后补一句：不符合该版本的客户端通过 §16.1 的 HTTP 通道使用，能力等价、授权边界不变 |
| §16.1 协议 adapter | 补一段"客户端无关的 HTTP 通道"：只需 5 个 header，`_meta` 非强制；并记录本次已评估且拒绝了双时代兼容（R6），附重启条件 |
| §17.3 E2E | 明确"已验证"仅指 Codex Desktop / CLI；新增一条验收：R3 文档中的 `curl` 必须可原样执行 |
| 新增小节 | Skill 分发路径合同：`~/.claude/skills/`、`~/.agents/skills/`、`~/.codex/skills/`；说明这些是标准路径而非某一客户端的私有约定 |

## 6. 其他执行项

- `_config.yml` 的 `exclude` 加入 `docs/requirements/` —— `docs/**.md` 会被 Jekyll 发布成站点页面，
  过程性需求文档不应进 `sitemap.xml`（`skills/` 已因同类理由被排除）。
- `CLAUDE.md` / `AGENTS.md` 的 gotcha 列表补一条：skill 安装路径是跨工具标准，
  不要按客户端逐个新增按钮。

## 7. 已知偏差（本次不修）

ADR §16.1 要求每个 request 的 `params._meta` 至少包含
`io.modelcontextprotocol/protocolVersion` 与 `io.modelcontextprotocol/clientCapabilities`，
但 `McpServer` 实测不校验 `_meta`。R3 依赖当前这个宽松行为。
补校验会使 R3 的 `curl` 变长，且没有安全收益（`_meta` 是不可信的客户端自报信息，ADR §1 已如此定性）。
处理方式应是**把 ADR 改成与实现一致**，而不是加校验 —— 但这属于独立决策，不在本次范围。
