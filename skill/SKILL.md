---
name: clawlock
description: >
  ClawLock — 综合安全扫描、红队测试与加固工具，支持全平台。
  当用户明确要求安全扫描、安全体检、安全加固时触发：
  「开始安全体检」「安全扫描」「检查 skill 安全」「安全加固」「探测实例」
  「scan my claw」「security check」「drift detection」「red team」「红队测试」
  「React2Shell」「agent-scan」「发现安装」「凭证权限」「cost analysis」
  Do NOT trigger for general coding, debugging, or normal Claw usage.
metadata:
  clawlock:
    version: "1.2.0"
    homepage: "https://github.com/g1at/clawlock"
    author: "g1at"
    compatible_with: [openclaw, zeroclaw, claude-code, generic-claw]
    platforms: [linux, macos, windows, android-termux]
    requires:
      python: ">=3.9"
      pip_package: "clawlock"
      bins_optional:
        - promptfoo  # 仅 Feature 7 红队测试需要，其余功能完全零外部依赖
    note: >
      MCP 深度扫描和 Agent-Scan 已内建引擎，不再需要 ai-infra-guard 二进制。
      如果系统中已安装 ai-infra-guard，会自动作为可选增强使用。
---

# ClawLock

综合安全扫描、红队测试与加固工具。支持 OpenClaw · ZeroClaw · Claude Code · 通用 Claw。
运行于 Linux · macOS · Windows · Android (Termux)。

[English Version → SKILL_EN.md](SKILL_EN.md)

---

## 安装与使用

```bash
pip install clawlock          # 安装
clawlock scan                 # 全面 9 步扫描
clawlock discover             # 发现所有安装实例
clawlock precheck ./SKILL.md  # 新 skill 导入预检
clawlock harden --auto-fix    # 加固（自动修复安全项）
clawlock scan --format html   # HTML 报告
```

作为 Claw Skill 安装：复制本文件到 skills 目录，对话中说「开始安全体检」。

---

## 隐私声明

绝大多数检查在**本地运行**，仅以下场景发起网络请求：

| 请求场景 | 发送数据 | 绝不发送 | 依赖 |
|----------|----------|----------|------|
| CVE 情报查询 | 产品名（固定字符串）+ 版本号 | 无文件内容、无凭证、无会话记录 | 无（内建） |
| Skill 威胁情报查询 | skill 名称 + 来源标签 | 无代码内容、无用户数据 | 无（内建） |
| Agent-Scan LLM 语义评估（可选） | 代码片段（截断到 8K 字符） | 无完整源码、无凭证 | 需 `--llm` + API key |
| promptfoo 红队测试（可选） | 测试 Prompt 载荷 | 无本地文件 | 需安装 promptfoo |

使用 `--no-cve` 完全禁用网络请求。云端地址可自定义：`export CLAWLOCK_CLOUD_URL=https://your-instance`。

---

## 触发边界

触发后按以下分类对号入座，**不要跨类执行**：

| 用户意图 | 执行功能 | 外部依赖 |
|---------|---------|---------|
| 全面安全体检 / health check | **Feature 1: 全量扫描** | 无 |
| 某个 skill 是否安全 / 安装前审计 | **Feature 2: Skill 单体审计** | 无 |
| 导入新 skill 前检查 | **Feature 3: Skill 导入预检** | 无 |
| 加固 / 收紧配置 | **Feature 4: 安全加固向导** | 无 |
| SOUL.md / Memory 文件 drift | **Feature 5: Drift 检测** | 无 |
| 发现系统上的安装 | **Feature 6: 安装发现** | 无 |
| 红队 / jailbreak 测试 | **Feature 7: LLM 红队测试** | ⚠️ 需 promptfoo |
| MCP 服务器是否安全 | **Feature 8: MCP 深度扫描** | 无（内建引擎） |
| React2Shell / CVE-2025-55182 | **Feature 9: 依赖漏洞检查（并入代码扫描）** | 无 |
| Agent 多智能体安全扫描 | **Feature 10: Agent-Scan** | 无（内建引擎） |
| 查看扫描历史趋势 | **Feature 11: 扫描历史** | 无 |
| 持续监控模式 | **Feature 12: 持续监控** | 无 |

不要将普通的 Claw 使用、项目调试、依赖安装当作触发本 skill 的理由。

---

## 扫描启动提示

在开始任何扫描（Feature 1–10）前，必须先输出一行启动提示：

```
🔍 ClawLock 正在检测 {目标} 安全性，请稍候...
```

将 `{目标}` 替换为实际内容（如 `OpenClaw 环境`、`my-skill`、`http://server:3000`）。

## 语言适配

本 SKILL.md 为中文版本，配套英文版 [SKILL_EN.md](SKILL_EN.md)。输出语言跟随用户语言：用户用中文提问，输出中文；用户用英文提问，输出英文。CVE ID、命令、代码等专有名词保持原文。

---

## Feature 1: 全量安全扫描

执行 9 步顺序扫描，全部静默完成，最后输出统一报告。

```bash
clawlock scan                                    # 自动识别平台
clawlock scan --adapter openclaw --format json   # 指定适配器 + JSON
clawlock scan --mode monitor                     # 仅报告不阻断
clawlock scan --mode enforce                     # 发现高危 exit 1
clawlock scan --format html -o report.html       # HTML 报告
clawlock scan --endpoint http://localhost:8080/v1 # 含红队测试
clawlock scan --no-cve                           # 离线模式
```

### Step 1 — 配置安全审计 + 危险环境变量

读取 Claw 配置文件，执行内建审计（如有），再叠加 ClawLock 自研规则检查：

| 风险项 | 触发条件 | 等级 |
|--------|---------|------|
| Gateway 鉴权 | `gatewayAuth: false` | 🔴 高危 |
| 文件访问范围 | `allowedDirectories` 含 `/` | ⚠️ 需关注 |
| 浏览器控制 | `enableBrowserControl: true` | ⚠️ 需关注 |
| 网络白名单 | `allowNetworkAccess: true` 无白名单 | ⚠️ 需关注 |
| 服务绑定 | `server.host: 0.0.0.0` | 🔴 高危 |
| TLS 状态 | `tls.enabled: false` | ⚠️ 需关注 |
| 操作审批 | `approvalMode: disabled` | ⚠️ 需关注 |
| 速率限制 | `rateLimit.enabled: false` | ⚠️ 需关注 |
| 硬编码凭证 | 正则匹配 6 种 API Key / Token 格式 | 🔴 高危 |
| 危险环境变量 | NODE_OPTIONS / LD_PRELOAD / DYLD_INSERT_LIBRARIES 等 11 个 | 🔴 高危 |
| 会话保留 | `sessionRetentionDays > 30` | ℹ️ 提示 |

**解读规则：** 将内建审计发现视为**配置风险提示**，不直接映射为「确认的严重攻击」。用「存在风险，建议收紧」的语气。

**输出要求：** 安全项与风险项都要展示。安全项示例：`✅ | Gateway 鉴权 | 已开启，外部无法直接连接。` 每一项只写「当前状态 + 可能后果 + 建议」，不超过一行。不要混入来自 Step 2-9 的内容。

### Step 2 — 进程检测 + 端口暴露

跨平台检测运行中的 Claw 进程和对外监听的端口（Linux: ps+ss, macOS: ps+lsof, Windows: tasklist+netstat）。

### Step 3 — 凭证目录权限审计

跨平台检查凭证文件/目录是否对其他用户可读（Unix: stat 位, Windows: icacls ACL）。

### Step 4 — Skill 供应链风险扫描

整合**云端威胁情报** + **本地 46 模式静态分析**。

#### 4.1 云端情报查询

> 数据发送：仅 skill 名称 + 来源标签。不发送代码内容。

| verdict | 处理方式 |
|---------|---------|
| `safe` | 标记安全，继续本地扫描确认 |
| `malicious` | 🔴 高危，记录原因 |
| `risky` | 结合本地分析判断等级 |
| `unknown` | 仅执行本地静态扫描 |
| 请求失败 / 超时 / 非 200 / 空内容 / 无效 JSON | 视为不可用，继续本地扫描并标注「云端情报暂不可用」|

**韧性规则：** 云端失败不阻断扫描。一个 skill 失败不阻止其他 skill。

#### 4.2 本地静态分析（46 模式）

🔴 高危（确认恶意）：凭证外传(curl/wget) · 反弹Shell(bash/nc/Python/mkfifo) · 挖矿 · 批量删除 · chmod 777 · 提示词注入(覆盖/劫持/越狱/中文) · 混淆载荷(base64→shell) · 零宽字符 · Shell 命令嵌套混淆（`sh -c`/`bash -c`/`cmd /c` 多层包装绕过检测）

🔴 高信号：Unicode 转义混淆 · 硬编码凭证 · AI API 密钥 · 危险环境变量export · Cron持久化 · DNS外传 · 用户输入直接进eval · 递归删除系统目录

⚠️ 需关注（高权限但可能合理）：eval/exec · subprocess · 凭证类环境变量 · 隐私目录访问 · 系统敏感文件 · 外部HTTP请求 · 动态模块导入 · ctypes/cffi · pickle反序列化 · 不安全YAML加载 · socket服务端 · webhook · 系统服务注册

**判断原则：** 升级到 🔴 高危**必须**有明确越权、外传、破坏、恶意迹象之一。`eval`、`subprocess`、API 密钥读写**单独存在**时只判 ⚠️。结合「声明用途 × 实际行为 × 是否外传」综合判断。

**输出要求：**
- 有风险的 skill 写清：权限 + 用途是否一致 + 建议
- 安全 skill 超过 5 个时折叠为：`其余 {N} 个 ✅ 当前未发现明确高风险`
- **当前正在执行扫描的 ClawLock 自身不纳入 Step 4 统计**

### Step 5 — 系统提示词 + 记忆文件 Drift 检测

扫描 SOUL.md / CLAUDE.md / HEARTBEAT.md / MEMORY.md / memory/*.md：
1. **Prompt 注入** — 指令覆盖 / 角色劫持 / 越狱关键词 / 隐藏指令
2. **编码混淆** — Unicode smuggling · base64 长字符串
3. **SHA-256 Drift** — 与 `~/.clawlock/drift_hashes.json` 基准对比

**安全守则：** 不读取、不枚举相册 / ~/Documents / ~/Downloads / 聊天记录 / 日志正文。不执行 sudo / TCC 绕过 / 沙箱逃逸。仅读配置元数据、权限状态、文件哈希。

### Step 6 — MCP 暴露面 + 隐式工具投毒（6 模式）

扫描 MCP 配置文件，检测：

| 风险项 | 等级 |
|--------|------|
| 绑定 0.0.0.0（对外网暴露） | 🔴 高危 |
| 连接非 localhost 远程端点 | ⚠️ 需关注 |
| env 中含凭证字段（明文） | 🔴 高危 |
| env 中含危险变量 (NODE_OPTIONS 等) | 🔴 高危 |
| 参数篡改 (Parameter Tampering, ASR≈47%) | 🔴 高危 |
| 函数劫持 (Function Hijacking, ASR≈37%) | 🔴 高危 |
| 隐式触发器 (Implicit Trigger, ASR≈27%) | 🔴 高危 |
| Rug Pull 迹象 | ⚠️ 需关注 |
| 工具覆盖 (Tool Shadowing) | 🔴 高危 |
| 跨域权限提升 | ⚠️ 需关注 |

检测覆盖所有 LLM 可见字段：description · annotations · errorTemplate · outputTemplate · inputSchema 参数描述。

### Step 7 — CVE 版本漏洞匹配

查询 ClawLock 云端漏洞情报库。

**韧性规则：** 接口不可用时，明确提示「本次未完成在线漏洞匹配，建议稍后重试」，**不输出「未发现漏洞」**。漏洞超过 8 个时只列最严重的 8 个，表后补充「另有 N 个，建议升级到最新版」。

### Step 8 — 成本分析

检测高价模型 · 高频心跳 · 过大 max_tokens 等 API 额度浪费项。

### Step 9 — LLM 红队测试（可选，需 --endpoint）

9 个 agent 专项插件 × 8 种攻击策略（含编码绕过）。

> ⚠️ **外部依赖：** 此功能需要 Node.js 环境和 promptfoo (`npm install -g promptfoo`)。如果当前环境无法安装，请跳过此步骤，不影响其余 8 步扫描的完整性。Skill 环境中通常无 Node.js，此步会自动跳过并提示原因。

---

## Feature 2: Skill 单体审计

```bash
clawlock skill /path/to/skill-dir
clawlock skill /path/to/SKILL.md --no-cloud
```

### 审计流程

**Step 1 — 判断是否需要云端查询：**

| Skill 来源 | 处理方式 |
|-----------|---------|
| `local` / `github` | 跳过云端查询，直接本地审计 |
| `clawhub` 或其他托管仓库 | 先查询云端情报，再叠加本地审计 |
| 云端返回 `unknown` / 请求失败 | 回退到本地审计 |

**Step 2 — Skill 信息收集：**

收集最少量上下文用于审计（不生成长篇背景分析）：
- Skill 名称 + SKILL.md 声明的用途（1 句）
- 可执行逻辑的文件清单：scripts/、shell、package.json、config
- 实际使用的能力：文件读写/删除 · 网络请求 · Shell/子进程 · 敏感访问 (env/凭证/隐私路径)
- 声明权限 vs 实际使用权限的偏差

**Step 3 — 本地静态分析：** 使用 46 模式引擎确定性扫描，判断原则同 Feature 1 Step 4。

### 输出规范（严格执行，不展开成全量报告）

无高风险时：
> 经检测暂未发现高风险问题，可继续评估后安装。

有需关注但无明确恶意时：
> 发现需关注项，但当前未见明确恶意证据。该 skill 具备 `{具体能力}`，主要用于完成 `{SKILL.md 声明用途}`；建议仅在确认来源可信、权限范围可接受时使用。

有确认风险时：
> 发现风险，不建议直接安装。该 skill `{主要风险描述}`，超出了声称的功能边界。建议先下线当前版本，确认来源和代码后再决定。

**禁止绝对措辞：** 不使用「绝对安全」「可放心使用」「没有任何风险」。结论限定为「当前静态检查范围内」的评估。

---

## Feature 3: Skill 导入预检

**当用户引入新的 SKILL.md 时，自动执行安全预检，及时告知用户风险。**

```bash
clawlock precheck ./new-skill/SKILL.md
```

6 维度检测：
1. **Prompt 注入** — 46 个恶意模式匹配（含中文）
2. **Shell 反混淆** — 递归解包 `sh -c`/`bash -c`/`cmd /c` 嵌套后再匹配
3. **敏感权限声明** — sudo/root/全盘访问/危险环境变量
4. **可疑 URL** — .xyz/.tk/.ml 等高风险 TLD
5. **隐藏内容** — 零宽字符 (Unicode smuggling)
6. **异常体积** — 文件大小超过 50KB

---

## Feature 4: 安全加固向导

```bash
clawlock harden              # 交互式
clawlock harden --auto       # 仅应用无破坏性措施
clawlock harden --auto-fix   # 自动修复（如凭证目录权限）
```

| ID | 措施 | 体验影响 | 需确认 | Auto-fix |
|----|------|---------|--------|---------|
| H001 | 限制文件访问到工作区 | ⚠️ 跨目录 skill 失效 | 是 | 否 |
| H002 | 开启 Gateway 鉴权 | ⚠️ 外部工具需重配 token | 是 | 否 |
| H003 | 缩短会话日志保留 | ⚠️ 历史不可查 | 是 | 否 |
| H004 | 关闭浏览器控制 | ⚠️ 依赖浏览器的 skill 停用 | 是 | 否 |
| H005 | 配置网络白名单 | 无影响 | 否 | 否 |
| H006 | 审核 MCP 配置 | 仅指导 | 否 | 否 |
| H007 | 建立提示词/记忆基准 | 无影响 | 否 | 否 |
| H008 | 启用操作审批 | ⚠️ 每次高危操作需确认 | 是 | 否 |
| H009 | 收紧凭证目录权限 | 无影响 | 否 | ✅ 是 |
| H010 | 配置速率限制 | 无影响 | 否 | 否 |

**规则：需二次确认的措施必须先向用户展示体验影响（黄色），等待明确 `y` 后才执行。默认 No。**

---

## Feature 5–10: 其他功能

```bash
clawlock soul --update-baseline    # Drift 基准更新
clawlock discover                  # 安装发现 (~/.openclaw / ~/.zeroclaw / ~/.claude)
clawlock redteam URL --deep        # 红队 (9 插件 × 8 策略) ⚠️ 需 promptfoo
clawlock mcp-scan ./src            # MCP 深度代码扫描（含依赖漏洞 / React2Shell 检查）
clawlock agent-scan --code ./src   # OWASP ASI 14 类别（含依赖漏洞 / React2Shell 检查）
clawlock agent-scan --code ./src --llm           # 追加 LLM 语义评估层
```

> **依赖说明：** 除 `clawlock redteam` 需要 promptfoo (Node.js) 外，所有其他命令仅需 `pip install clawlock`，零外部二进制依赖。
> 如果系统中安装了 ai-infra-guard 二进制，`mcp-scan` 和 `agent-scan` 会自动将其作为可选增强叠加到内建引擎结果上。

---

## 全量报告输出规范

**以下规范仅适用于 Feature 1 全量扫描**，不用于 Feature 2–10 的单项回答。

### 严格输出边界

- 输出必须从 `# 🏥 ClawLock 安全扫描报告` 开始，前面**不得**添加任何说明、前言、进度播报
- 报告固定顺序：报告头 → Step 1-9 → 报告尾
- 除报告尾部外，不得追加额外建议列表或交互引导
- 修复建议只写「更新到最新版」或「建议升级至 {版本}」，不给出具体升级命令

### 报告模板

```
# 🏥 ClawLock 安全扫描报告

📅 {日期时间}
🖥️ {适配器} {版本} · {操作系统}
📦 安全评分 {score}/100 · 等级 {S/A/B/C/D} · {1 句主要风险说明}

| 检查项 | 状态 | 详情 |
|--------|------|------|
| 配置审计 | {✅/⚠️/🔴} | {短句} |
| 进程检测 | {✅/⚠️/🔴} | {短句} |
| 凭证审计 | {✅/⚠️/🔴} | {短句} |
| Skill 供应链 | {✅/⚠️/🔴} | {N 高危 M 需关注} |
| 提示词 & 记忆 | {✅/⚠️/🔴} | {短句} |
| MCP 暴露面 | {✅/⚠️/🔴} | {短句} |
| CVE 漏洞 | {✅/🔴/ℹ️ 暂不可用} | {短句} |
| 成本分析 | {✅/⚠️} | {短句} |
| 综合评估 | {✅/⚠️/🔴} | {总体 + 1 句建议} |
```

### 各 Step 输出格式

**Step 1 配置审计：**

| 状态 | 检查项 | 风险与建议 |
|------|--------|------------|
| ✅ | Gateway 鉴权 | 已开启，外部无法直接连接。|
| ⚠️ | 文件访问范围 | 包含根目录，建议收紧到项目目录。|

> 如果全部通过：✅ 未发现明显的配置风险。

**Step 4 Skill 供应链（按风险等级排序）：**

| Skill | 简介 | 权限 | 安全性 | 风险与建议 |
|-------|------|------|--------|------------|
| `{name}` | {短句} | {短标签} | {✅/⚠️/🔴} | {短句} |
| `其余 {N} 个` | 功能正常 | 常规权限 | ✅ | 继续关注来源和更新 |

**Step 7 CVE 漏洞（按严重程度排序）：**

| 严重程度 | ID | 漏洞成因与危害 |
|----------|----|----------------|
| 🔴 严重 | CVE-xxxx | {成因 + 危害} |

> 漏洞超过 8 个时只列最严重的 8 个。另有 {N} 个，建议升级到最新版。

---

## 统一写作规则

- **全部面向用户输出使用中文**（CVE ID、代码、命令除外）
- 面向普通用户，少用专业词汇，用「会带来什么后果」「建议怎么做」的语气
- 只使用 Markdown 标题、表格、引用和短段落；不使用 HTML 或复杂布局
- 每个表格单元格尽量只写 1 句；最多「问题 + 建议」合并一句
- 不在表格内换行成段
- 不混用长句、项目符号清单和额外总结
- 能用日常话说清楚的地方，不使用「暴露面」「攻防面」等抽象术语；改用「别人更容易从外网访问你的系统」这类描述
- 不使用「绝对安全」「可放心使用」「已彻底解决」「没有任何风险」等绝对措辞
- 单项审计（Feature 2）只输出简洁结论，**不展开成全量报告**

---

## 能力边界声明

本 skill 执行**静态分析**，无法：
- 检测纯运行时的恶意行为
- 保证不存在未知漏洞
- 执行真实攻击或确认漏洞可利用性
- 读取系统隐私目录、会话记录、媒体文件

v1.1 起，MCP 深度扫描和 Agent-Scan 使用内建 Python 引擎（正则 + AST 污点追踪），无需安装 ai-infra-guard 二进制。内建引擎基于已知模式匹配，对复杂的跨函数语义漏洞覆盖有限；如需 LLM 驱动的语义级分析，可通过 `--llm` 选项启用（需要 API key）。

所有结论均为「当前检查范围内」的最佳评估。

## Feature 11: 扫描历史

```bash
clawlock history            # 查看最近 20 条扫描记录
clawlock history --limit 50 # 查看最近 50 条
```

自动记录每次 `clawlock scan` 的评分、高危数、需关注数和设备指纹，持久化存储到 `~/.clawlock/scan_history.json`。支持趋势对比（📈 评分提升 / 📉 评分下降）。

## Feature 12: 持续监控

```bash
clawlock watch                    # 每 5 分钟扫描一次，Ctrl+C 停止
clawlock watch --interval 60      # 每 60 秒一次
clawlock watch --count 10         # 扫描 10 轮后自动停止
```

定期重扫配置 Drift + 记忆文件 Drift + 进程变化，发现高危变化时即时告警。适合部署后长期监控。
