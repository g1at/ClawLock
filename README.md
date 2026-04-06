# ClawLock

[![PyPI](https://img.shields.io/pypi/v/clawlock.svg)](https://pypi.org/project/clawlock/)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20(Termux)-lightgrey.svg)]()

**ClawLock** is a security scanner, hardening wizard, MCP source auditor, and OWASP ASI agent scanner for Claw-family AI agent deployments. It supports **OpenClaw**, **ZeroClaw**, **Claude Code**, and compatible environments.

It is designed for both professional security users and everyday operators:

- Local-first static analysis with built-in engines
- Optional online CVE / skill intelligence
- Optional external-tool and LLM enhancement when you want deeper coverage

## Highlights

- **12 CLI commands** covering full scan, single-skill audit, hardening, history, watch mode, MCP scan, and Agent-Scan
- **8 concurrent core security domains** in `clawlock scan`, plus an optional red-team stage
- **Built-in MCP deep scan engine** with regex + AST analysis across 14 risk categories
- **Built-in OWASP ASI 14 Agent-Scan** with config analysis, code scanning, and optional LLM assessment
- **Interactive hardening** with 18 measures, platform-aware filtering, and explicit UX-impact disclosure
- **JSON, text, and HTML reports** for the full `scan` workflow
- **Global CLI language adaptation**:
  `CLAWLOCK_LANG=zh` uses Chinese, and every other case uses English
- **Cross-platform support** for Linux, macOS, Windows, and Android (Termux)

## Quick Start

```bash
pip install clawlock

clawlock --help                           # Show command help
clawlock scan                            # Full security scan
clawlock discover                        # Discover local Claw installations
clawlock precheck ./new-skill/SKILL.md   # Pre-check a new skill
clawlock skill /path/to/skill            # Audit one skill
clawlock soul                            # Check prompt + memory drift
clawlock harden                          # Interactive hardening wizard
clawlock harden --auto-fix               # Apply safe local auto-fixes
clawlock mcp-scan ./mcp-server/src       # MCP source-code deep scan
clawlock agent-scan --code ./agent/src   # Standalone OWASP ASI agent scan
clawlock scan --format html -o report.html
```

Running `clawlock` with no subcommand prints the brand logo. Use `clawlock --help` for the command list.

## CLI Language

ClawLock uses one simple global rule:

- `CLAWLOCK_LANG=zh`: Chinese
- Any other value, or not set: English

Examples by platform:

Windows PowerShell:

```powershell
$env:CLAWLOCK_LANG='zh'
clawlock scan
```

Windows CMD:

```bat
set CLAWLOCK_LANG=zh
clawlock scan
```

Linux / macOS / Android (Termux):

```bash
export CLAWLOCK_LANG=zh
clawlock scan
```

This applies to:

- `--help`
- runtime progress and summaries
- hardening wizard output
- scan / skill / precheck / soul / redteam / mcp-scan / agent-scan text output

## Report Formats And Exit Modes

ClawLock uses three report formats for different workflows:

| Format | Best for | Notes |
|--------|----------|-------|
| `text` | Local terminal review | Default format for security operators |
| `json` | Automation, CI, skills, and secondary processing | Best choice when another system needs structured output |
| `html` | Review, sharing, and archived reports | `scan` writes a standalone report file and prints the saved path even if a browser cannot be opened automatically |

`scan` also uses two execution modes:

| Mode | Behavior | Best for |
|------|----------|----------|
| `monitor` | Report only; does not fail the run on findings | Manual review and exploratory checks |
| `enforce` | Returns exit code `1` on critical/high findings | CI gates and automated enforcement |

Examples:

```bash
clawlock scan --format text
clawlock scan --format json --mode enforce -o report.json
clawlock scan --format html -o report.html
```

## Scan Pipeline

`clawlock scan` runs 8 core security domains in parallel, then optionally runs a red-team stage.

| Step | Check | What it does |
|------|-------|--------------|
| 1 | Config audit | Adapter-aware config checks plus risky environment-variable checks |
| 2 | Process exposure | Running processes and exposed listeners |
| 3 | Credential audit | Permission review for credential files and directories |
| 4 | Skill supply chain | Local pattern detection for dangerous skills and setup logic |
| 5 | Prompt and memory | SOUL / prompt drift plus memory-file checks |
| 6 | MCP exposure | MCP config and poisoning-surface checks |
| 7 | CVE matching | Tencent cloud CVE intelligence lookup, enabled by default unless `--no-cve` |
| 8 | Agent security | Included in `scan` with adapter config ASI checks; use `agent-scan` for code-layer review |
| 9 | Red Team (optional) | Runs only when `--endpoint` is provided and `--no-redteam` is not used |

## Dependency Model

### 1. Built-in local engine

Works with just:

```bash
pip install clawlock
```

No Node.js, no external scanner binary, and no LLM API key are required for:

- full local scan pipeline except online CVE lookup
- skill audit and precheck
- prompt / memory drift checks
- hardening
- history and watch mode
- MCP deep scan
- `scan` includes the Agent-Scan config layer; use `agent-scan --code ...` for code-layer review

### 2. Online intelligence without API keys

These features are network-backed but do not require a user API key:

- `scan` CVE matching through the Tencent advisory endpoint
- optional skill cloud intelligence during `clawlock skill`

If you want a fully local run, use:

```bash
clawlock scan --no-cve --no-redteam
clawlock skill /path/to/skill --no-cloud
```

### 3. LLM-enhanced analysis

`agent-scan` can add an optional semantic layer with Anthropic or OpenAI-compatible APIs:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
clawlock agent-scan --code ./src --llm
```

### 4. Optional external tools

ClawLock can optionally integrate with external tools, but only in the paths where code actually uses them:

| Tool | Current integration in ClawLock | When it is used |
|------|---------------------------------|-----------------|
| [promptfoo](https://github.com/promptfoo/promptfoo) | `clawlock redteam` / optional scan red-team stage | When you run red-team tests against a live endpoint; ClawLock can use `promptfoo` directly or via `npx` |
| [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Optional enhancer for `clawlock mcp-scan` | Only when the binary is installed and you also provide `--model` and `--token` |

`AI-Infra-Guard` is **not** currently used as an external enhancer for `agent-scan`; `agent-scan` uses ClawLock's built-in engine plus the optional direct LLM layer.

## Command Overview

| Command | Purpose |
|---------|---------|
| `scan` | Run the full security scan |
| `discover` | Discover local Claw installations |
| `skill` | Audit one skill |
| `precheck` | Precheck a new skill before import |
| `soul` | Check prompt and memory drift |
| `harden` | Run the interactive hardening wizard |
| `redteam` | Run promptfoo red-team tests |
| `mcp-scan` | Deep-scan MCP server source code |
| `agent-scan` | Run the OWASP ASI agent scan |
| `history` | Show recent scan history |
| `watch` | Watch key checks for changes |
| `version` | Show version info |

## Hardening

ClawLock currently ships **18 hardening measures**.

- `clawlock harden`: interactive mode
- `clawlock harden --auto`: applies safe non-interactive actions and prints guidance for recommendation-only items
- `clawlock harden --auto-fix`: only performs real safe local auto-fixes

Important current behavior:

- The wizard groups measures into **Safe to apply now**, **Recommended only**, and **Needs confirmation**
- Only **`H009`** performs an actual local auto-fix today
- `H009` tightens permissions on supported config directories and common home credential files such as `.npmrc`, `.pypirc`, and `.netrc`
- UX-impacting measures still require explicit confirmation in interactive mode
- Guidance-only measures are no longer reported as if they were applied

## Multi-Platform Support

| Feature | Linux | macOS | Windows | Android (Termux) |
|---------|:-----:|:-----:|:-------:|:----------------:|
| Full scan pipeline | Yes | Yes | Yes | Yes |
| Process detection | `ps aux` | `ps aux` | `tasklist` | `ps -e` |
| Port exposure check | `ss` / `netstat` | `lsof -iTCP` | `netstat -ano` | `ss` / `netstat` |
| Permission audit | Unix `stat` | Unix `stat` | `icacls` ACL | Unix `stat` |
| Permission auto-fix | `chmod` | `chmod` | `icacls` | `chmod` |
| Persistence detection | cron / user `systemd` | `LaunchAgents` / `launchctl` | `schtasks` / `RunOnce` | `.termux/boot` / `termux-job-scheduler` |
| Hardening guidance | Platform-aware | Platform-aware | Platform-aware | Platform-aware |

## Use as a Claw Skill

Copy `skill/SKILL.md` into your Claw skills directory, then trigger the security workflow from your Claw conversation.

Detailed guides:

- [skill/SKILL.md](skill/SKILL.md) (Chinese)
- [skill/SKILL_EN.md](skill/SKILL_EN.md) (English)

Example:

```bash
mkdir -p ~/.openclaw/skills/clawlock
cp skill/SKILL.md ~/.openclaw/skills/clawlock/
```

## CI/CD Example

```yaml
- name: ClawLock security gate
  run: |
    pip install clawlock
    clawlock scan --no-cve --no-redteam --format json --mode enforce > report.json
```

## Development

```bash
git clone https://github.com/g1at/clawlock.git
cd clawlock
pip install -e ".[dev]"
pytest tests/test_clawlock.py -v    # 104 tests
```

## Contributing

Useful areas to extend:

- `clawlock/scanners/__init__.py`
- `clawlock/scanners/mcp_deep.py`
- `clawlock/scanners/agent_scan.py`
- `clawlock/hardening/__init__.py`
- `clawlock/reporters/__init__.py`

## Acknowledgements

We are deeply grateful to these open-source projects whose work inspires and enhances ClawLock:

- **[promptfoo](https://github.com/promptfoo/promptfoo)** — A major inspiration behind ClawLock's red-team workflow. promptfoo's declarative configuration model, broad jailbreak and injection coverage, and OWASP-oriented evaluation approach helped shape how ClawLock thinks about endpoint red-team testing. Thank you to the promptfoo team for building such a versatile LLM evaluation platform.
- **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** by Tencent Zhuque Lab — ClawLock benefits from the advisory work and broader AI infrastructure security research around AI-Infra-Guard. Our MCP implicit tool poisoning coverage is also informed by the MCP-ITP research ([arXiv:2601.07395](https://arxiv.org/abs/2601.07395)). Thank you for advancing practical security research for AI systems.

## License

ClawLock is dual-licensed under [Apache License 2.0](LICENSE) and [MIT License](LICENSE). You may choose either license.
