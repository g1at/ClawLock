# 🔒 ClawLock

[![PyPI](https://img.shields.io/pypi/v/clawlock.svg)](https://pypi.org/project/clawlock/)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-59%2F59-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/平台-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android-lightgrey.svg)]()

**ClawLock** 是一个综合安全扫描、红队测试与加固工具，覆盖 Claw 家族全平台：**OpenClaw**、**ZeroClaw**、**Claude Code** 及兼容产品——原生支持 **Linux**、**macOS**、**Windows** 和 **Android (Termux)**。

面向安全团队和个人开发者——一条命令安装，秒级扫描，交互式加固。

## 核心亮点

- **75+ 条检测规则**，覆盖 9 步扫描：配置审计、供应链、Prompt 注入、MCP 工具投毒、CVE、凭证审计、成本分析等
- **内建 MCP 深度扫描引擎** — 28+ 模式覆盖 14 个风险类别 + Python AST 污点追踪，零外部依赖
- **内建 OWASP ASI 14 Agent-Scan** — 3 层检测架构（配置分析 + 代码模式 + 可选 LLM 语义评估）
- **13 个 CLI 命令** — 从全量扫描到单 Skill 审计
- **4 个平台适配器** — 自动识别 OpenClaw / ZeroClaw / Claude Code，或回退到通用模式
- **全平台兼容** — 在 Linux、macOS、Windows、Android (Termux) 上无需额外配置即可运行
- **交互式加固** — 影响功能的操作带 UX 影响声明，需要用户明确确认
- **零必须依赖** — 只需要 Python，开箱即用

## 快速开始

```bash
pip install clawlock

clawlock scan                              # 全面 9 步安全扫描
clawlock discover                          # 发现系统上所有 Claw 安装实例
clawlock precheck ./new-skill/SKILL.md     # 导入新 Skill 前预检
clawlock skill /path/to/skill              # 审计单个 Skill
clawlock soul                              # SOUL.md + 记忆文件 Drift 检测
clawlock harden --auto-fix                 # 交互式加固（自动修复安全项）
clawlock mcp-scan ./mcp-server/src         # MCP Server 源码深度扫描
clawlock agent-scan --code ./agent/src     # OWASP ASI 14 类别 Agent 安全扫描
clawlock scan --format html -o report.html # 输出 HTML 报告
```

## 扫描管线

| 步骤 | 检查项 | 说明 |
|------|--------|------|
| 1 | 配置审计 + 危险环境变量 | 按适配器检查配置 + NODE_OPTIONS/LD_PRELOAD 等 |
| 2 | 进程检测 + 端口暴露 | 运行中的 Claw 进程 + 0.0.0.0 监听检测 |
| 3 | 凭证目录权限审计 | 凭证文件和目录的访问权限检查 |
| 4 | Skill 供应链 (46 模式) | 反弹 Shell、凭证外传、Prompt 注入、DNS 外传、零宽字符 |
| 5 | 提示词 + 记忆文件 Drift | SOUL/CLAUDE/HEARTBEAT/MEMORY.md 的 SHA-256 基准对比 |
| 6 | MCP 暴露面 + 6 种工具投毒 | 参数篡改、函数劫持、Rug Pull、Tool Shadowing |
| 7 | CVE 漏洞匹配 | 云端漏洞情报库（589+ CVEs，43 个 AI 框架） |
| 8 | 成本分析 | 高价模型、高频心跳、过大的 Token 限制 |
| 9 | LLM 红队测试（可选） | 9 插件 × 8 策略 |

## 依赖架构：三层设计

ClawLock 的设计理念很明确：**绝大多数用户只需 `pip install clawlock` 就够了**。高级能力面向专业用户，通过安装可选工具解锁。

### 第一层：零依赖（覆盖 90%+ 使用场景）

以下所有功能仅需 `pip install clawlock`——不需要 Node.js、不需要外部二进制、不需要 API key：

- 完整 9 步扫描（配置、进程、凭证、供应链、SOUL.md drift、MCP 暴露面、CVE、成本）
- MCP Server 源码深度扫描（`clawlock mcp-scan`）— 内建 Python 正则 + AST 污点追踪引擎
- OWASP ASI 14 Agent-Scan（`clawlock agent-scan --code`）— 内建静态配置 + 代码模式分析
- Skill 审计、预检、加固、安装发现、扫描历史、持续监控
- React2Shell 检测

### 第二层：LLM 增强（仅需 API key）

配置 Anthropic 或 OpenAI 的 API key 后，可在内建引擎基础上叠加语义级分析：

```bash
export ANTHROPIC_API_KEY=sk-ant-...
clawlock agent-scan --code ./src --llm           # 叠加 LLM 语义评估层
```

不需要任何外部二进制——ClawLock 通过 Python 直接调用 LLM API。

### 第三层：专业增强（可选外部工具）

安全专业人员如需最大化覆盖，可以安装以下两个优秀的开源项目来增强 ClawLock 的能力。**ClawLock 会自动检测它们的存在并使用——无需额外配置。**

| 工具 | 增强内容 | 安装方式 | 适用场景 |
|------|---------|---------|---------|
| **[promptfoo](https://github.com/promptfoo/promptfoo)** | LLM 红队测试：50+ 漏洞插件，自适应越狱攻击（树搜索、渐进升级、多轮对话），OWASP/NIST/MITRE 合规映射，可视化攻击面板 | `npm install -g promptfoo` | 需要对在线 Agent 端点做系统性红队测试，覆盖全面的攻击手法 |
| **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** | ReAct agent 驱动的 MCP 代码分析（跨函数语义推理、多语言支持），6 子 agent 协作 Agent-Scan，多轮对话式攻击模拟 | [下载二进制](https://github.com/Tencent/AI-Infra-Guard/releases) | 需要 LLM 驱动的深度语义分析，超越模式匹配的 MCP Server 代码审计 |

**工作原理：** 运行 `mcp-scan` 或 `agent-scan` 时，内建引擎始终先执行。如果系统中安装了 `ai-infra-guard` 且通过 `--model`/`--token` 提供了 LLM API 凭证，ClawLock 会自动将其作为增强层调用，把结果追加到内建引擎的输出中。`clawlock redteam` 同理，有 `promptfoo` 就用，没有就提示安装。不需要特殊标志——安装工具即可使用。

### 内建引擎 vs 外部工具有什么区别？

| 维度 | ClawLock 内建 | + AI-Infra-Guard | + promptfoo |
|------|:-:|:-:|:-:|
| **成本** | 免费 | LLM API 费用 | LLM API 费用 |
| **速度** | <1 秒 | 5-15 分钟 | 5-15 分钟 |
| **确定性** | 100% 可复现 | 非确定性 (LLM) | 非确定性 (LLM) |
| **语言覆盖** | Python + JS/TS | 任何语言 | 不涉及（测试端点） |
| **分析深度** | 模式匹配 + AST | 跨函数语义推理 | 自适应多轮攻击 |
| **CI/CD 友好** | ✅ 零配置 | 需 API key | 需 Node.js + API key |
| **离线可用** | ✅（配合 `--no-cve`） | ❌ | ❌ |

对绝大多数用户而言，第一层已经足够。第二、三层适合需要 LLM 驱动的深度分析的专业场景。

## 多平台支持

| 功能 | Linux | macOS | Windows | Android (Termux) |
|------|:-----:|:-----:|:-------:|:----------------:|
| 完整扫描管线 | ✅ | ✅ | ✅ | ✅ |
| 进程检测 | `ps aux` | `ps aux` | `tasklist` | `ps -e` |
| 端口暴露检查 | `ss`/`netstat` | `lsof -iTCP` | `netstat -ano` | `ss`/`netstat` |
| 凭证权限审计 | Unix `stat` | Unix `stat` | `icacls` ACL | Unix `stat` |
| 权限自动修复 | `chmod` | `chmod` | `icacls` | `chmod` |

## 安全加固

10 项加固措施，每项带有明确的 UX 影响说明。影响功能的措施需要用户明确输入 `y` 确认。使用 `--auto-fix` 自动修复无破坏性项。

## 致谢

衷心感谢以下开源项目对 ClawLock 的启发和增强：

- **[promptfoo](https://github.com/promptfoo/promptfoo)** — ClawLock 红队测试能力的基石。promptfoo 的声明式配置体系、全面的越狱/注入测试框架和 OWASP 合规映射都是业界顶级。感谢 promptfoo 团队打造了如此出色的 LLM 评测平台。
- **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)**（腾讯朱雀实验室）— ClawLock 集成了 AI-Infra-Guard 的 CVE 漏洞情报 API（覆盖 589+ 个漏洞、43 个 AI 框架）。ClawLock 的 MCP 隐式工具投毒检测模式受到 MCP-ITP 研究（arXiv:2601.07395）的启发。感谢在 AI 基础设施安全领域的开创性工作。

## 作为 Claw Skill 使用

将 `skill/SKILL.md` 复制到 Claw skills 目录，在 Agent 对话中说「开始安全体检」即可触发。作为 Skill 使用时，所有第一层功能开箱即用。

```bash
mkdir -p ~/.openclaw/skills/clawlock && cp skill/SKILL.md ~/.openclaw/skills/clawlock/
```

## 项目结构

```
clawlock/
├── scanners/
│   ├── __init__.py         # 75 条检测规则，覆盖 9 个扫描类别
│   ├── mcp_deep.py         # 内建 MCP 深度扫描引擎 (28+ 模式 + AST)
│   └── agent_scan.py       # 内建 OWASP ASI 14 引擎 (3 层)
├── integrations/
│   ├── __init__.py         # 云端情报、成本分析、React2Shell、可选增强器
│   └── promptfoo.py        # LLM 红队测试封装（9 插件 × 8 策略）
├── adapters/               # 平台适配层（4 个 Claw 适配器）
├── hardening/              # 10 项加固措施 + UX 影响声明
├── reporters/              # Rich 终端 + JSON + HTML 报告
├── utils/                  # 跨平台抽象层（Windows / Mac / Linux / Android）
└── __main__.py             # Typer CLI（14 个命令）
```

## CI/CD 集成

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
pytest tests/ -v     # 59 个测试
```

## 贡献

欢迎贡献！以下方向尤其欢迎：

- 新增检测模式 → `scanners/__init__.py`
- MCP 扫描模式 → `scanners/mcp_deep.py`
- ASI 检测规则 → `scanners/agent_scan.py`
- 新增平台适配器 → `adapters/__init__.py`
- 新增加固措施 → `hardening/__init__.py`

## 许可证

ClawLock 采用 [Apache License 2.0](LICENSE) 和 [MIT License](LICENSE) 双重许可。你可以自由选择其中任一许可证。
