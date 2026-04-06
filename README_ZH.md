# ClawLock

[![PyPI](https://img.shields.io/pypi/v/clawlock.svg)](https://pypi.org/project/clawlock/)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20(Termux)-lightgrey.svg)]()

**ClawLock** 是一个面向 Claw 家族 AI Agent 部署环境的安全扫描、加固、MCP 源码审计与 OWASP ASI Agent 扫描工具，支持 **OpenClaw**、**ZeroClaw**、**Claude Code** 以及兼容环境。

它同时面向专业安全人员和日常使用者：

- 以本地静态分析为主
- 可选接入在线 CVE / skill 情报
- 可选接入外部工具或 LLM 做更深层分析

## 核心特性

- **12 个 CLI 命令**，覆盖全量扫描、单 skill 审计、加固、历史、监控、MCP 扫描和 Agent-Scan
- **`clawlock scan` 的 8 个核心安全域并发执行**，外加一个可选红队阶段
- **内建 MCP 深度扫描引擎**，基于正则和 AST，覆盖 14 个风险类别
- **内建 OWASP ASI 14 Agent-Scan**，支持配置检查、代码扫描和可选 LLM 语义分析
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
clawlock mcp-scan ./mcp-server/src       # MCP 源码深度扫描
clawlock agent-scan --code ./agent/src   # 独立执行 OWASP ASI Agent 扫描
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
- `scan / skill / precheck / soul / redteam / mcp-scan / agent-scan` 的文本输出

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
| `enforce` | 发现严重/高危问题时返回退出码 `1` | CI 安全门禁与自动化执行 |

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
| 4 | Skill 供应链 | 本地规则检测危险 skill 与安装逻辑 |
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

### 4. 可选外部工具

ClawLock 可以与外部工具协作，但只在代码实际接入的路径中使用它们：

| 工具 | 当前在 ClawLock 中的接入方式 | 何时使用 |
|------|------------------------------|----------|
| [promptfoo](https://github.com/promptfoo/promptfoo) | `clawlock redteam` / 可选红队阶段 | 对在线端点执行红队测试时；ClawLock 可直接调用 `promptfoo`，也可通过 `npx` 间接运行 |
| [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | `clawlock mcp-scan` 的可选增强层 | 仅当本机已安装该二进制，且同时提供 `--model` 与 `--token` 时 |

当前 **`agent-scan` 不会调用 AI-Infra-Guard**；它使用的是 ClawLock 自带引擎，以及可选的直接 LLM 分析层。

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
| `agent-scan` | 运行 OWASP ASI Agent 扫描 |
| `history` | 查看最近扫描历史 |
| `watch` | 持续监控关键检查项变化 |
| `version` | 显示版本信息 |

## 安全加固

ClawLock 当前内置 **18 项加固措施**。

- `clawlock harden`：交互式模式
- `clawlock harden --auto`：应用安全、非破坏性的动作，并输出仅建议类项的人工指导
- `clawlock harden --auto-fix`：只执行真正安全的本地自动修复

当前需要特别注意：

- 加固向导会把措施分成 **现在可安全应用 / 仅建议 / 需要确认** 三组展示
- 目前只有 **`H009`** 会真正执行本地自动修复
- `H009` 会收紧支持的配置目录以及 `.npmrc`、`.pypirc`、`.netrc` 等常见家目录凭证文件权限
- 有 UX 影响的措施在交互模式下仍然需要明确确认
- 仅指导类措施不会再被误报成“已完成”

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
pytest tests/test_clawlock.py -v    # 104 tests
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
- **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)**（腾讯朱雀实验室）— ClawLock 受益于 AI-Infra-Guard 相关的漏洞情报工作，以及更广泛的 AI 基础设施安全研究。ClawLock 的 MCP 隐式工具投毒检测覆盖，也参考了 MCP-ITP 研究（[arXiv:2601.07395](https://arxiv.org/abs/2601.07395)）中的思路。感谢在 AI 系统安全领域持续推进务实而有价值的研究工作。

## 许可证

ClawLock 采用 [Apache License 2.0](LICENSE) 和 [MIT License](LICENSE) 双许可证，你可以任选其一使用。
