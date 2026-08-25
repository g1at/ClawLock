# ClawLock

[![PyPI](https://img.shields.io/pypi/v/clawlock.svg)](https://pypi.org/project/clawlock/)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20(Termux)-lightgrey.svg)]()

**ClawLock** 是一个面向 Claw 家族 AI Agent 部署环境的安全扫描、加固、MCP 源码审计与 ASI 兼容规则集扫描工具，支持 **OpenClaw**、**ZeroClaw**、**Claude Code** 以及兼容环境。

它同时面向专业安全人员和日常使用者：

- 以本地静态分析为主
- 可选接入在线 CVE / skill 情报
- 可选接入外部工具或 LLM 做更深层分析

## 核心特性

- **16 个 CLI 命令**，覆盖全量扫描、单 skill 审计、加固、历史、监控、MCP、供应链、运行时与动态分析
- **`clawlock scan` 的 8 个核心安全域并发执行**，外加一个可选红队阶段
- **Detection Core v2**：项目级多标签数据流、证据路径、能力链关联和 fail-closed 不完整状态
- **制品感知的 Skill 检查**：覆盖归档、嵌套归档、OOXML、wheel/JAR 与 `.pyc`，并生成受预算约束的证据台账
- **内建 MCP 深度与 live 引擎**：源码审计、协议清单、可信快照和 rug-pull 漂移检测
- **结构化供应链分析**：manifest、lockfile、安装钩子、外部指令图、SBOM 与 SLSA 来源证明
- **容器/运行时覆盖**：Dockerfile、Compose、Kubernetes，以及经明确授权、在固定只读镜像中执行的行为分析
- **内建 ClawLock ASI 14 兼容规则集**，支持按适配器检查配置、扫描代码和可选 LLM 语义分析
- **18 项交互式加固措施**，支持按平台过滤，并明确标注 UX 影响
- **支持 text / json / html 报告**，其中 HTML 适用于全量 `scan`
- **全局命令行语言自适应**：
  `CLAWLOCK_LANG=zh` 输出中文，其他情况输出英文
- **跨平台运行**：Linux、macOS、Windows、Android (Termux)

## 快速开始

```bash
pip install clawlock

clawlock --help                           # 查看命令帮助
clawlock scan                            # 全量安全扫描
clawlock discover                        # 发现本地 Claw 安装
clawlock precheck ./new-skill/SKILL.md   # 导入前预检 skill
clawlock skill /path/to/skill            # 审计单个 skill
clawlock soul                            # 检查 prompt / memory 漂移
clawlock harden                          # 交互式加固向导
clawlock harden --auto-fix               # 自动应用安全本地修复
clawlock harden --from-scan --auto-fix   # 仅修复上次扫描发现的问题
clawlock harden --auto-fix --verify      # 自动修复后验证结果
clawlock harden --rollback               # 撤销上一次自动修复
clawlock mcp-scan ./mcp-server/src       # MCP 源码深度扫描
clawlock mcp-live ./.mcp.json --server fs --execute --snapshot ./mcp.snapshot.json
clawlock supply-chain ./project          # manifest、锁文件、指令、SBOM、来源证明
clawlock runtime-scan ./deploy           # Dockerfile、Compose 与 Kubernetes 审计
clawlock dynamic-scan ./skill --image analyzer@sha256:<digest> \
  --entrypoint-json '["--","python","/workspace/main.py"]' --execute
clawlock agent-scan --code ./agent/src   # 独立执行 ClawLock ASI 兼容规则集扫描
clawlock scan --format html -o report.html
```

查看命令列表请使用 `clawlock --help`。

## CLI 语言规则

ClawLock 当前采用一条统一规则：

- `CLAWLOCK_LANG=zh`：输出中文
- 其他任意值，或未设置：输出英文

不同平台示例：

Windows PowerShell：

```powershell
$env:CLAWLOCK_LANG='zh'
clawlock scan
```

Windows CMD：

```bat
set CLAWLOCK_LANG=zh
clawlock scan
```

Linux / macOS / Android (Termux)：

```bash
export CLAWLOCK_LANG=zh
clawlock scan
```

这条规则会影响：

- `--help`
- 运行时进度提示和摘要
- 加固向导输出
- `scan / skill / precheck / soul / redteam / MCP / supply-chain / runtime / dynamic / agent-scan` 的文本输出

## Detection Core v2

Detection Core v2 不再把每个可疑关键词当作孤立命中，而是关联完整证据：

- **项目级多标签数据流**：跟踪不可信输入、密钥、文件路径、网络数据和下载内容经过别名、赋值、参数、返回值、封装函数及跨文件调用后的流向；结果包含 source-to-sink 证据路径与置信度。
- **制品恢复与证据台账**：在条目数、字节数、深度、压缩比和时间预算内安全检查 ZIP/TAR/wheel/JAR/OOXML、嵌套容器和可恢复的 `.pyc` 指令。路径穿越、链接、加密、重名、magic/扩展名不一致和源码/字节码不一致都会留在台账中。
- **能力链关联**：组合“敏感读取 → 对外写入”“下载 → 执行”“记忆写入 → 自启动”“不可信路径 → 写入/执行”等事件。攻击链会获得更高置信度，同时保留底层证据。
- **结构化供应链检查**：解析 manifest/lockfile、npm lifecycle、Python 构建后端、可变依赖、SBOM、递归外部指令、固定版本/摘要漂移和 in-toto/SLSA 声明；默认只记录远程指令引用，不主动获取。DSSE 签名只会标记为“存在”，没有独立验证策略时不会声称可信。
- **live 与运行态证据**：可对明确选择的 MCP Server 采集真实清单并与可信快照比较 tool/prompt/resource 漂移，也可审计部署定义或在固定容器中执行受限行为分析。

所有受预算约束的遍历都会报告是否完整完成。预算耗尽、解析失败、显式请求的工具不可用，或主动探测被拒绝，都是 **INCOMPLETE**，不能当作安全通过。

## 报告格式与退出模式

ClawLock 为不同使用场景提供 3 种报告格式：

| 格式 | 适用场景 | 说明 |
|------|----------|------|
| `text` | 本地终端查看 | 默认格式，适合安全人员直接阅读 |
| `json` | 自动化、CI、skill 与二次处理 | 适合被其他系统稳定消费 |
| `html` | 审计归档、复核与分享 | `scan` 会生成独立 HTML 文件；即使浏览器无法自动打开，也会明确打印保存路径 |

`scan` 同时提供两种执行模式：

| 模式 | 行为 | 适用场景 |
|------|------|----------|
| `monitor` | 只报告，不因发现问题而让本次运行失败 | 人工复核、探索性检查 |
| `enforce` | 严重/高危问题返回 `1`；请求的检查未完整执行时返回 `2` | CI 安全门禁与自动化执行 |

安全聚焦命令采用同一套便于自动化的退出约定：`0` 表示请求的分析已完整执行且没有严重/高危发现，`1` 表示报告了严重/高危发现，`2` 表示请求的分析 **INCOMPLETE**。遇到退出码 `2` 应检查 JSON 的 `status`、`complete` 与 finding metadata，不能按成功处理。

示例：

```bash
clawlock scan --format text
clawlock scan --format json --mode enforce -o report.json
clawlock scan --format html -o report.html
```

## 扫描管线

`clawlock scan` 会并发执行 8 个核心安全域，然后按条件追加一个红队阶段。

| 步骤 | 检查项 | 说明 |
|------|--------|------|
| 1 | 配置审计 | 按适配器检查配置，并检查高风险环境变量 |
| 2 | 进程暴露 | 检查运行中的进程和暴露监听 |
| 3 | 凭证审计 | 检查凭证文件与目录权限 |
| 4 | Skill 供应链 | 规则、制品台账、数据流、能力链、包清单与指令图分析 |
| 5 | Prompt 与记忆 | 检查 SOUL / prompt 漂移与 memory 文件 |
| 6 | MCP 暴露面 | 检查 MCP 配置与 poisoning 面 |
| 7 | CVE 匹配 | 默认启用腾讯在线 CVE 情报查询，可用 `--no-cve` 关闭 |
| 8 | Agent 安全 | `scan` 默认纳入适配器配置层 ASI 检查；代码层请额外使用 `agent-scan` |
| 9 | 红队测试（可选） | 仅在传入 `--endpoint` 且未设置 `--no-redteam` 时运行 |

## 依赖模型

### 1. 内建本地引擎

只需要：

```bash
pip install clawlock
```

不需要 Node.js、不需要外部扫描器二进制，也不需要 LLM API key，即可使用：

- 除在线 CVE 外的本地全量扫描能力
- skill 审计与导入前预检
- prompt / memory 漂移检查
- 加固
- 历史记录与 watch 模式
- MCP 深度扫描
- 制品、能力链、结构化供应链与运行时定义分析
- `scan` 默认纳入 Agent 配置层；代码层请使用 `agent-scan --code ...`

### 2. 无 API key 的在线情报

以下功能需要联网，但不需要用户提供 API key：

- `scan` 默认启用的腾讯 CVE 情报查询
- `clawlock skill` 中可选的 skill 云端情报

如果你想要完全本地运行，可以这样：

```bash
clawlock scan --no-cve --no-redteam
clawlock skill /path/to/skill --no-cloud
```

### 3. LLM 增强分析

`agent-scan` 可以叠加 Anthropic 或 OpenAI 兼容接口的语义分析层：

```bash
export ANTHROPIC_API_KEY=sk-ant-...
clawlock agent-scan --code ./src --llm
```

启用 `--llm` 后，选取的源码/配置片段会先脱敏并截断再发送。缺少密钥、请求失败或响应无法解析都会标记为“请求的检查未完成”，不会作为安全结果通过。建议使用环境变量，不要把密钥放进 `--token`，避免进入 shell 历史。

### 4. 可选外部工具

ClawLock 可以与外部工具协作，但只在代码实际接入的路径中使用它们：

| 工具 | 当前在 ClawLock 中的接入方式 | 何时使用 |
|------|------------------------------|----------|
| [promptfoo](https://github.com/promptfoo/promptfoo) | `clawlock redteam` / 可选红队阶段 | 需要用户显式安装、最好固定版本的 `promptfoo` 二进制。ClawLock 会分别生成用例和执行评测，默认禁用结果分享；不会通过 `npx` 自动下载并执行 `promptfoo@latest`。 |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `clawlock supply-chain PATH --osv` | 仅在显式启用后调用已经安装的二进制；显式请求但工具不可用时记为 INCOMPLETE。 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | `clawlock supply-chain PATH --gitleaks` | 仅在显式启用后调用已经安装的二进制；报告中的敏感内容会脱敏。 |
| Docker 或 Podman | `clawlock dynamic-scan` | 必须传 `--execute`、摘要固定的分析镜像、JSON argv 入口和非 host 网络策略；没有宿主机执行降级。 |

ClawLock 不会自动下载上述工具。MCP stdio 启动、远程 MCP 探测、可信快照替换、红队流量和容器执行都需要对应的显式授权参数；静态分析保持本地、被动执行。

## 命令总览

| 命令 | 用途 |
|------|------|
| `scan` | 执行全量安全扫描 |
| `discover` | 发现本地 Claw 安装 |
| `skill` | 审计单个 skill |
| `precheck` | 导入前预检新 skill |
| `soul` | 检查 prompt 与 memory 漂移 |
| `harden` | 运行交互式加固向导 |
| `redteam` | 运行 promptfoo 红队测试 |
| `mcp-scan` | 深度扫描 MCP 服务端源码 |
| `mcp-live` | 经授权采集 MCP 真实清单并检测可信快照漂移 |
| `supply-chain` | 审计依赖、安装钩子、指令图、SBOM 与 SLSA 来源证明 |
| `dynamic-scan` | 在固定只读 Docker/Podman 容器中执行受限行为分析 |
| `runtime-scan` | 静态审计 Dockerfile、Compose 与 Kubernetes 安全姿态，不执行部署 |
| `agent-scan` | 运行 ClawLock ASI 14 兼容规则集 |
| `history` | 查看最近扫描历史 |
| `watch` | 持续监控关键检查项变化 |
| `version` | 显示版本信息 |

## 安全加固

ClawLock 当前内置 **18 项加固措施**。

- `clawlock harden`：交互式模式
- `clawlock harden --auto`：应用安全、非破坏性的动作，并输出仅建议类项的人工指导
- `clawlock harden --auto-fix`：只执行真正安全的本地自动修复
- `clawlock harden --from-scan`：仅展示与最近一次扫描发现相关的加固措施
- `clawlock harden --auto-fix --verify`：自动修复后重新扫描验证效果
- `clawlock harden --rollback`：撤销上一次自动修复操作（从备份还原）

可自动修复的措施：

| ID | 措施 | 说明 |
|----|------|------|
| H003 | 缩短会话保留期 | 将配置文件中的 `sessionRetentionDays` 设为 7 |
| H007 | 建立提示词基线 | 为 SOUL.md / CLAUDE.md / MEMORY.md 记录 SHA-256 基线 |
| H008 | 启用审批模式 | 将配置文件中的 `approvalMode` 设为 `”always”` |
| H009 | 收紧凭证权限 | 对配置目录和凭证文件执行 `chmod 600`/`700` 或 `icacls` |

所有配置修改前会自动备份到 `~/.clawlock/backups/`。

其他行为：

- 加固向导会把措施分成 **现在可安全应用 / 仅建议 / 需要确认** 三组展示
- 有 UX 影响的措施在交互模式下仍然需要明确确认
- 仅指导类措施不会再被误报成”已完成”

## 多平台支持

| 功能 | Linux | macOS | Windows | Android (Termux) |
|------|:-----:|:-----:|:-------:|:----------------:|
| 全量扫描管线 | 是 | 是 | 是 | 是 |
| 进程检测 | `ps aux` | `ps aux` | `tasklist` | `ps -e` |
| 端口暴露检查 | `ss` / `netstat` | `lsof -iTCP` | `netstat -ano` | `ss` / `netstat` |
| 权限审计 | Unix `stat` | Unix `stat` | `icacls` ACL | Unix `stat` |
| 权限自动修复 | `chmod` | `chmod` | `icacls` | `chmod` |
| 持久化检测 | cron / 用户级 `systemd` | `LaunchAgents` / `launchctl` | `schtasks` / `RunOnce` | `.termux/boot` / `termux-job-scheduler` |
| 加固引导 | 按平台适配 | 按平台适配 | 按平台适配 | 按平台适配 |

## 作为 Claw Skill 使用

把 `skill/SKILL.md` 复制到你的 Claw skills 目录后，就可以在 Claw 对话中触发安全工作流。

详细说明：

- [skill/SKILL.md](skill/SKILL.md)（中文）
- [skill/SKILL_EN.md](skill/SKILL_EN.md)（英文）

示例：

```bash
mkdir -p ~/.openclaw/skills/clawlock
cp skill/SKILL.md ~/.openclaw/skills/clawlock/
```

## CI/CD 示例

```yaml
- name: ClawLock security gate
  run: |
    pip install clawlock
    clawlock scan --no-cve --no-redteam --format json --mode enforce > report.json
```

## 开发

```bash
git clone https://github.com/g1at/clawlock.git
cd clawlock
pip install -e ".[dev]"
pytest tests/test_clawlock.py -v    # 110 tests
```

## 贡献

适合扩展的主要位置：

- `clawlock/scanners/__init__.py`
- `clawlock/scanners/mcp_deep.py`
- `clawlock/scanners/agent_scan.py`
- `clawlock/hardening/__init__.py`
- `clawlock/reporters/__init__.py`

## 致谢

衷心感谢以下开源项目对 ClawLock 的启发和增强：

- **[promptfoo](https://github.com/promptfoo/promptfoo)** — ClawLock 红队工作流的重要灵感来源。promptfoo 的声明式配置模型、对越狱与注入场景的广泛覆盖，以及面向 OWASP 的评测思路，都对 ClawLock 的端点红队设计产生了很大启发。感谢 promptfoo 团队打造了如此出色的 LLM 评测平台。

## 许可证

ClawLock 采用 [Apache License 2.0](LICENSE) 和 [MIT License](LICENSE) 双许可证，你可以任选其一使用。
