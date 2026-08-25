# ClawLock

[![PyPI](https://img.shields.io/pypi/v/clawlock.svg)](https://pypi.org/project/clawlock/)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20(Termux)-lightgrey.svg)]()

**ClawLock** is a security scanner, hardening wizard, MCP source auditor, and ASI compatibility-profile agent scanner for Claw-family AI agent deployments. It supports **OpenClaw**, **ZeroClaw**, **Claude Code**, and compatible environments.

It is designed for both professional security users and everyday operators:

- Local-first static analysis with built-in engines
- Optional online CVE / skill intelligence
- Optional external-tool and LLM enhancement when you want deeper coverage

## Highlights

- **16 CLI commands** covering full scan, single-skill audit, hardening, history, watch mode, MCP, supply-chain, runtime, and dynamic analysis
- **8 concurrent core security domains** in `clawlock scan`, plus an optional red-team stage
- **Detection Core v2** with project-level multi-label dataflow, evidence paths, capability-chain correlation, and fail-closed incomplete states
- **Artifact-aware Skill inspection** for archives, nested archives, OOXML documents, wheels/JARs, and `.pyc`, backed by a bounded evidence ledger
- **Built-in MCP deep and live engines** for source audit, protocol inventory, trusted snapshots, and rug-pull drift detection
- **Structured supply-chain analysis** for manifests, lockfiles, install hooks, external instruction graphs, SBOMs, and SLSA provenance
- **Container/runtime coverage** for Dockerfile, Compose, Kubernetes, and explicitly authorized behavior analysis in a pinned read-only image
- **Built-in ClawLock ASI 14 compatibility profile** with adapter-scoped config analysis, code scanning, and optional LLM assessment
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
clawlock harden --from-scan --auto-fix   # Fix only issues found in last scan
clawlock harden --auto-fix --verify      # Auto-fix then verify the result
clawlock harden --rollback               # Undo the last auto-fix
clawlock mcp-scan ./mcp-server/src       # MCP source-code deep scan
clawlock mcp-live ./.mcp.json --server fs --execute --snapshot ./mcp.snapshot.json
clawlock supply-chain ./project          # Manifests, locks, instructions, SBOM, provenance
clawlock runtime-scan ./deploy           # Dockerfile, Compose, and Kubernetes audit
clawlock dynamic-scan ./skill --image analyzer@sha256:<digest> \
  --entrypoint-json '["--","python","/workspace/main.py"]' --execute
clawlock agent-scan --code ./agent/src   # Standalone ClawLock ASI compatibility scan
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
- scan / skill / precheck / soul / redteam / MCP / supply-chain / runtime / dynamic / agent-scan text output

## Detection Core v2

Detection Core v2 correlates evidence instead of treating every suspicious token as an isolated hit:

- **Project-level multi-label dataflow** tracks untrusted input, secrets, file paths, network data, and downloaded content through aliases, assignments, arguments, returns, wrappers, and cross-file calls. Findings include source-to-sink evidence paths and confidence.
- **Artifact recovery with an evidence ledger** safely inspects ZIP/TAR/wheel/JAR/OOXML content, nested containers, and recoverable `.pyc` instructions under entry, byte, depth, ratio, and time budgets. Path traversal, links, encryption, duplicate names, magic/extension mismatch, and source/bytecode mismatch remain visible in the ledger.
- **Capability-chain correlation** joins events such as sensitive read → external write, download → execute, memory write → autorun, and untrusted path → write/execute. This raises confidence for meaningful attack chains while retaining the underlying evidence.
- **Structured supply-chain checks** parse manifests and lockfiles, npm lifecycle hooks, Python build backends, mutable dependencies, SBOMs, recursive instruction references, pin/hash drift, and in-toto/SLSA statements. Remote instructions are recorded but not fetched by default. A DSSE signature is reported as present but is never called trusted without an independent verification policy.
- **Live and runtime evidence** can inventory an explicitly selected MCP server, compare a trusted snapshot for tool/prompt/resource drift, audit deployment definitions, or run bounded behavior analysis in a pinned container.

Every bounded traversal reports whether it completed. A budget limit, parser failure, unavailable explicitly requested tool, or refused active probe is **INCOMPLETE**, not a clean pass.

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
| `monitor` (default) | Report only; does not fail the run on findings | Manual review and exploratory checks |
| `enforce` | Returns `1` on critical/high findings and `2` when a requested check is incomplete | CI gates and automated enforcement (pass `--mode enforce`) |

Security focus commands use the same machine-friendly exit contract: `0` means the requested analysis completed without critical/high findings, `1` means critical/high findings were reported, and `2` means the requested analysis was **INCOMPLETE**. Review JSON `status`, `complete`, and finding metadata instead of treating exit `2` as success.

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
| 4 | Skill supply chain | Pattern, artifact-ledger, dataflow, capability-chain, package, and instruction-graph analysis |
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
- artifact, capability-chain, structured supply-chain, and runtime-definition analysis
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

When `--llm` is enabled, selected source/config snippets are redacted and truncated before being sent. A missing key, failed request, or unparseable response is reported as an incomplete requested check rather than a clean result. Prefer environment variables over `--token` so secrets do not enter shell history.

### 4. Optional external tools

ClawLock can optionally integrate with external tools, but only in the paths where code actually uses them:

| Tool | Current integration in ClawLock | When it is used |
|------|---------------------------------|-----------------|
| [promptfoo](https://github.com/promptfoo/promptfoo) | `clawlock redteam` / optional scan red-team stage | Requires an explicitly installed, preferably pinned `promptfoo` binary. ClawLock generates tests and evaluates them in separate steps with result sharing disabled; it never downloads `promptfoo@latest` through `npx`. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `clawlock supply-chain PATH --osv` | Runs only an already installed binary after explicit opt-in; an unavailable requested adapter is INCOMPLETE. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | `clawlock supply-chain PATH --gitleaks` | Runs only an already installed binary after explicit opt-in; reported secret material is redacted. |
| Docker or Podman | `clawlock dynamic-scan` | Requires `--execute`, a digest-pinned analyzer image, a JSON argv entrypoint, and a non-host network policy. There is no host-execution fallback. |

ClawLock never auto-downloads any of these tools. Live MCP stdio launch, remote MCP probing, trusted snapshot replacement, red-team traffic, and container execution require their corresponding explicit authorization flags. Static analysis remains local and passive.

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
| `mcp-live` | Collect an authorized MCP inventory and detect trusted-snapshot drift |
| `supply-chain` | Audit dependencies, install hooks, instruction graphs, SBOMs, and SLSA provenance |
| `dynamic-scan` | Run bounded behavior analysis in a pinned read-only Docker/Podman container |
| `runtime-scan` | Audit Dockerfile, Compose, and Kubernetes security posture without deployment |
| `agent-scan` | Run the ClawLock ASI 14 compatibility profile |
| `history` | Show recent scan history |
| `watch` | Watch key checks for changes |
| `version` | Show version info |

## Hardening

ClawLock currently ships **18 hardening measures**.

- `clawlock harden`: interactive mode
- `clawlock harden --auto`: applies safe non-interactive actions and prints guidance for recommendation-only items
- `clawlock harden --auto-fix`: only performs real safe local auto-fixes
- `clawlock harden --from-scan`: show only measures relevant to the latest scan findings
- `clawlock harden --auto-fix --verify`: auto-fix then re-scan to confirm the fix worked
- `clawlock harden --rollback`: undo the last auto-fix action (restores from backup)

Auto-fixable measures:

| ID | Measure | What it does |
|----|---------|--------------|
| H003 | Shorten session retention | Sets `sessionRetentionDays` to 7 in config files |
| H007 | Create prompt baseline | Records SHA-256 baselines for SOUL.md / CLAUDE.md / MEMORY.md |
| H008 | Enable approval mode | Sets `approvalMode` to `"always"` in config files |
| H009 | Tighten credential permissions | `chmod 600`/`700` or `icacls` on config dirs and credential files |

All config modifications are backed up to `~/.clawlock/backups/` before changes are made.

Other behavior:

- The wizard groups measures into **Safe to apply now**, **Recommended only**, and **Needs confirmation**
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
pytest tests/test_clawlock.py -v    # 110 tests
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

## License

ClawLock is dual-licensed under [Apache License 2.0](LICENSE) and [MIT License](LICENSE). You may choose either license.
