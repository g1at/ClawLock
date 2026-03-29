# 🔒 ClawLock

[![PyPI](https://img.shields.io/pypi/v/clawlock.svg)](https://pypi.org/project/clawlock/)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-59%2F59-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android-lightgrey.svg)]()

**ClawLock** is a comprehensive security scanner, red-teamer, and hardening toolkit for Claw-based AI agent deployments. It supports **OpenClaw**, **ZeroClaw**, **Claude Code**, and compatible platforms — running natively on **Linux**, **macOS**, **Windows**, and **Android (Termux)**.

Built for both security teams and individual developers — install with one command, scan in seconds, harden interactively.

## Highlights

- **75+ detection rules** across 9 scan steps covering config, supply chain, prompt injection, MCP tool poisoning, CVE, credential audit, cost analysis, and more
- **Built-in MCP deep scan engine** — 28+ patterns across 14 risk categories + Python AST taint tracking, zero external dependency
- **Built-in OWASP ASI 14 Agent-Scan** — 3-layer detection (config + code patterns + optional LLM assessment)
- **13 CLI commands** — from full scan to single-skill audit
- **4 platform adapters** — auto-detects OpenClaw, ZeroClaw, Claude Code, or falls back to generic
- **Cross-OS support** — runs on Linux, macOS, Windows, and Android (Termux) with zero platform-specific setup
- **Interactive hardening** with UX impact disclosure — dangerous changes require explicit confirmation
- **Zero required dependencies** beyond Python — everything works out of the box

## Quick Start

```bash
pip install clawlock

clawlock scan                              # Full 9-step security scan
clawlock discover                          # Find all Claw installations
clawlock precheck ./new-skill/SKILL.md     # Pre-check new skill
clawlock skill /path/to/skill              # Single skill audit
clawlock soul                              # SOUL.md + memory drift
clawlock harden --auto-fix                 # Auto-fix safe items
clawlock mcp-scan ./mcp-server/src         # MCP Server source code deep scan
clawlock agent-scan --code ./agent/src     # OWASP ASI 14-category Agent-Scan
clawlock scan --format html -o report.html # HTML report
```

## Scan Pipeline

| Step | Check | What It Does |
|------|-------|-------------|
| 1 | Config audit + risky env vars | Per-adapter rules + NODE_OPTIONS/LD_PRELOAD detection |
| 2 | Process detection + port exposure | Running processes + 0.0.0.0 listeners |
| 3 | Credential directory audit | File/directory permissions on credential stores |
| 4 | Skill supply chain (46 patterns) | Reverse shells, credential exfil, prompt injection, DNS exfil, zero-width chars |
| 5 | SOUL.md + memory file drift | SHA-256 baseline comparison for SOUL/CLAUDE/HEARTBEAT/MEMORY.md |
| 6 | MCP exposure + 6 tool poisoning | Parameter tampering, function hijacking, rug pull, tool shadowing |
| 7 | CVE matching | Cloud vulnerability intelligence (589+ CVEs, 43 AI frameworks) |
| 8 | Cost analysis | Expensive models, high-frequency heartbeats |
| 9 | LLM red-team (optional) | 9 plugins × 8 strategies via promptfoo |

## Dependencies: Three Tiers

ClawLock is designed with a clear dependency philosophy: **most users need nothing beyond `pip install clawlock`**. Advanced capabilities are available for professional users who install optional tools.

### Tier 1: Zero-Dependency (covers 90%+ use cases)

Everything below works with just `pip install clawlock` — no Node.js, no external binaries, no API keys:

- Full 9-step scan (config, processes, credentials, supply chain, SOUL.md drift, MCP exposure, CVE, cost)
- MCP Server source code deep scan (`clawlock mcp-scan`) — built-in Python regex + AST taint tracking engine
- OWASP ASI 14 Agent-Scan (`clawlock agent-scan --code`) — built-in static config + code pattern analysis
- Skill audit, pre-check, hardening, discovery, history, watch mode
- React2Shell detection

### Tier 2: LLM-Enhanced (needs API key only)

With an Anthropic or OpenAI API key, unlock semantic-level analysis on top of the built-in engine:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
clawlock agent-scan --code ./src --llm           # Add LLM semantic assessment layer
```

No external binary needed — ClawLock calls the LLM API directly via Python.

### Tier 3: Professional (optional external tools)

For security professionals who want maximum coverage, two excellent open-source projects can be installed to enhance ClawLock's capabilities. **ClawLock auto-detects their presence and uses them when available — no configuration needed.**

| Tool | What It Adds | Install | When You Need It |
|------|-------------|---------|-----------------|
| **[promptfoo](https://github.com/promptfoo/promptfoo)** | LLM red-team testing: 50+ vulnerability plugins, adaptive jailbreak attacks (tree search, crescendo, multi-turn), OWASP/NIST/MITRE compliance mapping, visual attack dashboard | `npm install -g promptfoo` | Systematic red-team testing of a live agent endpoint with comprehensive attack coverage |
| **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** | ReAct agent-driven MCP code analysis (cross-function semantic reasoning, multi-language), 6-sub-agent collaborative Agent-Scan, multi-turn dialogue attack simulation | [Download binary](https://github.com/Tencent/AI-Infra-Guard/releases) | LLM-powered deep semantic analysis of MCP Server source code beyond pattern matching |

**How it works:** When `mcp-scan` or `agent-scan` runs, the built-in engine always executes first. If `ai-infra-guard` is installed AND `--model`/`--token` are provided, ClawLock automatically invokes it as an enhancement layer. Similarly, `clawlock redteam` delegates to `promptfoo` when available. No special flags needed — just install the tools and ClawLock uses them.

### What's the difference?

| Dimension | ClawLock Built-in | + AI-Infra-Guard | + promptfoo |
|-----------|:-:|:-:|:-:|
| **Cost** | Free | LLM API tokens | LLM API tokens |
| **Speed** | <1 second | 5-15 minutes | 5-15 minutes |
| **Determinism** | 100% reproducible | Non-deterministic (LLM) | Non-deterministic (LLM) |
| **Language coverage** | Python + JS/TS | Any language | N/A (tests endpoints) |
| **Analysis depth** | Pattern matching + AST | Cross-function semantic reasoning | Adaptive multi-turn attacks |
| **CI/CD friendly** | ✅ Zero-config | Needs API key | Needs Node.js + API key |
| **Offline capable** | ✅ (with `--no-cve`) | ❌ | ❌ |

## Multi-Platform Support

| Feature | Linux | macOS | Windows | Android (Termux) |
|---------|:-----:|:-----:|:-------:|:-----------------:|
| Full scan pipeline | ✅ | ✅ | ✅ | ✅ |
| Process detection | `ps aux` | `ps aux` | `tasklist` | `ps -e` |
| Port exposure check | `ss`/`netstat` | `lsof -iTCP` | `netstat -ano` | `ss`/`netstat` |
| Credential permission audit | Unix `stat` | Unix `stat` | `icacls` ACL | Unix `stat` |
| Permission auto-fix | `chmod` | `chmod` | `icacls` | `chmod` |

## Hardening

10 hardening measures with UX impact disclosure. Measures that affect functionality require explicit `y` confirmation. Use `--auto-fix` to automatically apply non-breaking fixes.

## Acknowledgements

We are deeply grateful to these open-source projects whose work inspires and enhances ClawLock:

- **[promptfoo](https://github.com/promptfoo/promptfoo)** — The foundation of ClawLock's red-team capabilities. promptfoo's declarative config system, comprehensive jailbreak/injection testing framework, and OWASP compliance mapping are best-in-class. Thank you to the promptfoo team for building such a versatile LLM evaluation platform.
- **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** by Tencent Zhuque Lab — ClawLock integrates AI-Infra-Guard's CVE advisory API (589+ vulnerabilities across 43 AI frameworks). Our MCP implicit tool poisoning detection patterns are informed by the MCP-ITP research (arXiv:2601.07395). Thank you for pioneering work in AI infrastructure security.

## Use as a Claw Skill

Copy `skill/SKILL.md` into your Claw skills directory, then say "security scan" in your Agent conversation. When used as a Skill, all Tier 1 features work out of the box.

```bash
mkdir -p ~/.openclaw/skills/clawlock && cp skill/SKILL.md ~/.openclaw/skills/clawlock/
```

## Architecture

```
clawlock/
├── scanners/
│   ├── __init__.py         # 75 detection rules across 9 scan categories
│   ├── mcp_deep.py         # Built-in MCP deep scan engine (28+ patterns + AST)
│   └── agent_scan.py       # Built-in OWASP ASI 14 engine (3 layers)
├── integrations/
│   ├── __init__.py         # Cloud intel, cost, React2Shell, optional enhancers
│   └── promptfoo.py        # LLM red-team wrapper (9 plugins × 8 strategies)
├── adapters/               # Platform abstraction (4 Claw adapters)
├── hardening/              # 10 measures with UX impact disclosure
├── reporters/              # Rich terminal + JSON + HTML
├── utils/                  # Cross-platform abstraction (Windows/Mac/Linux/Android)
└── __main__.py             # Typer CLI (13 commands)
```

## CI/CD Integration

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
pytest tests/ -v     # 59 tests
```

## Contributing

Contributions welcome! See areas of interest:

- New detection patterns → `scanners/__init__.py`
- MCP scan patterns → `scanners/mcp_deep.py`
- ASI detection rules → `scanners/agent_scan.py`
- New platform adapters → `adapters/__init__.py`
- New hardening measures → `hardening/__init__.py`

## License

ClawLock is dual-licensed under [Apache License 2.0](LICENSE) and [MIT License](LICENSE). You may choose either license at your option.
