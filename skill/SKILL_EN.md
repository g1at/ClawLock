---
name: clawlock
description: >
  ClawLock — Comprehensive security scanner, red-teamer & hardening toolkit.
  Trigger when the user explicitly requests a security scan, health check,
  hardening, or skill audit:
  "security scan" "health check" "check skill safety" "harden my claw"
  "drift detection" "red team test" "React2Shell"
  "agent-scan" "discover installations" "credential audit" "cost analysis"
  Do NOT trigger for general coding, debugging, or normal Claw usage.
metadata:
  clawlock:
    version: "1.1.0"
    homepage: "https://github.com/g1at/clawlock"
    author: "g1at"
    compatible_with: [openclaw, zeroclaw, claude-code, generic-claw]
    platforms: [linux, macos, windows, android-termux]
    requires:
      python: ">=3.9"
      pip_package: "clawlock"
      bins_optional:
        - promptfoo  # Only needed for Feature 8 red-team; all other features are zero-dependency
    note: >
      MCP deep scan and Agent-Scan use built-in Python engines.
      ai-infra-guard binary is no longer required. If installed, it auto-enhances results.
---

# ClawLock

Comprehensive security scanner, red-teamer & hardening toolkit.
Supports OpenClaw · ZeroClaw · Claude Code · Generic Claw.
Runs on Linux · macOS · Windows · Android (Termux).

[中文版 → SKILL.md](SKILL.md)

---

## Installation & Usage

```bash
pip install clawlock          # Install
clawlock scan                 # Full 9-step scan
clawlock discover             # Find all installations
clawlock precheck ./SKILL.md  # Pre-check new skill
clawlock harden --auto-fix    # Harden (auto-fix safe items)
clawlock scan --format html   # HTML report
```

To use as a Claw Skill: copy this file to your skills directory, then say "security scan" in your Agent conversation.

---

## Privacy Disclosure

Most checks run **entirely locally**. Network requests are made only for:

| Request | Data Sent | Never Sent | Dependency |
|---------|-----------|------------|-----------|
| CVE advisory query | Product name (fixed string) + version | No file contents, no credentials | None (built-in) |
| Skill threat intel query | Skill name + source label | No code contents, no user data | None (built-in) |
| Agent-Scan LLM assessment (optional) | Code snippet (truncated to 8K chars) | No full source, no credentials | Requires `--llm` + API key |
| promptfoo red-team (optional) | Test prompt payloads | No local files | Requires promptfoo installed |

Use `--no-cve` to disable all network requests. Cloud URL is configurable: `export CLAWLOCK_CLOUD_URL=https://your-instance`.

---

## Trigger Boundary

After triggering, classify the request and stay narrow — **do not cross feature boundaries**:

| User Intent | Feature | External Dependency |
|-------------|---------|-------------------|
| Full security health check | **Feature 1: Full Scan** | None |
| Is this skill safe? / pre-install audit | **Feature 2: Single Skill Audit** | None |
| Check new skill before importing | **Feature 3: Skill Import Pre-check** | None |
| Harden / tighten config | **Feature 4: Hardening Wizard** | None |
| SOUL.md / memory file drift | **Feature 5: Drift Detection** | None |
| Find installations on this machine | **Feature 7: Discovery** | None |
| Red-team / jailbreak test | **Feature 8: LLM Red-Team** | ⚠️ Requires promptfoo |
| MCP server security | **Feature 9: MCP Deep Scan** | None (v1.1 built-in engine) |
| React2Shell / CVE-2025-55182 | **Feature 10: Dependency CVE checks (integrated into code scans)** | None |
| Multi-agent security scan | **Feature 11: Agent-Scan** | None (v1.1 built-in engine) |
| View scan history trends | **Feature 12: Scan History** | None |
| Continuous monitoring | **Feature 13: Watch Mode** | None |
| Continuous monitoring mode | **Feature 13: Watch Mode** |

Do not treat normal Claw usage, debugging, or dependency installation as reasons to trigger this skill.

---

## Scan Start Prompt

Before starting any scan (Features 1–11), output a single startup line:

```
🔍 ClawLock scanning {target} for security issues, please wait...
```

Replace `{target}` with the actual target (e.g. `OpenClaw environment`, `my-skill`, `http://server:3000`).

## Language Adaptation

This is the English version. The Chinese version is at [SKILL.md](SKILL.md). Output language follows the user's language: if the user writes in English, respond in English; if in Chinese, respond in Chinese. CVE IDs, commands, and code remain as-is.

---

## Feature 1: Full Security Scan

Runs 9 sequential steps silently, then outputs a unified report.

```bash
clawlock scan                                    # Auto-detect platform
clawlock scan --adapter openclaw --format json   # Specify adapter + JSON
clawlock scan --mode monitor                     # Report only, no exit code
clawlock scan --mode enforce                     # Exit 1 on critical/high
clawlock scan --format html -o report.html       # HTML report
clawlock scan --endpoint http://localhost:8080/v1 # Include red-team
clawlock scan --no-cve                           # Fully offline
```

### Step 1 — Config Audit + Risky Env Vars

Reads Claw config files, runs built-in audit (if available), then applies ClawLock's own rules:

| Risk | Trigger | Level |
|------|---------|-------|
| Gateway auth | `gatewayAuth: false` | 🔴 Critical |
| File access scope | `allowedDirectories` contains `/` | ⚠️ Medium |
| Browser control | `enableBrowserControl: true` | ⚠️ Medium |
| Network allowlist | `allowNetworkAccess: true` without domain list | ⚠️ Medium |
| Service binding | `server.host: 0.0.0.0` | 🔴 High |
| TLS status | `tls.enabled: false` | ⚠️ Medium |
| Approval mode | `approvalMode: disabled` | ⚠️ Medium |
| Rate limiting | `rateLimit.enabled: false` | ⚠️ Medium |
| Hardcoded secrets | Regex matching 6 API key/token formats | 🔴 Critical |
| Risky env vars | NODE_OPTIONS / LD_PRELOAD / DYLD_INSERT_LIBRARIES (11 vars) | 🔴 High |
| Session retention | `sessionRetentionDays > 30` | ℹ️ Info |

**Interpretation rule:** Treat built-in audit findings as **configuration risk hints**, not as confirmed attacks. Use language like "there is a risk, recommend tightening".

**Output rules:** Show both passing and failing items. Passing example: `✅ | Gateway auth | Enabled, external access requires credentials.` Each item = one sentence: status + impact + recommendation. Do not mix in findings from Steps 2-9.

### Step 2 — Process Detection + Port Exposure

Cross-platform detection of running Claw processes and externally exposed ports (Linux: ps+ss, macOS: ps+lsof, Windows: tasklist+netstat).

### Step 3 — Credential Directory Audit

Cross-platform check for overly permissive credential files/directories (Unix: stat bits, Windows: icacls ACL).

### Step 4 — Skill Supply Chain (46 patterns)

Combines **cloud threat intelligence** + **local 46-pattern static analysis**.

#### 4.1 Cloud Intelligence

> Data sent: only skill name + source label. No code content sent.

| Verdict | Action |
|---------|--------|
| `safe` | Mark safe, continue local scan for confirmation |
| `malicious` | 🔴 Critical, record reason |
| `risky` | Combine with local analysis to determine level |
| `unknown` | Local static scan only |
| Request failed / timeout / non-200 / empty / invalid | Treat as unavailable, continue local scan, note "cloud intel unavailable" |

**Resilience rules:** Cloud failure does not block the scan. One skill failure does not stop others.

#### 4.2 Local Static Analysis (46 patterns)

🔴 Critical (confirmed malicious): credential exfil (curl/wget) · reverse shell (bash/nc/Python/mkfifo) · crypto mining · destructive deletion · chmod 777 · prompt injection (override/hijack/jailbreak/Chinese) · obfuscated payloads (base64→shell) · zero-width chars

🔴 High signal: Unicode escape obfuscation · hardcoded credentials · AI API keys · dangerous env var export · cron persistence · DNS exfiltration · user input into eval · recursive deletion of system dirs

⚠️ Medium (elevated but potentially legitimate): eval/exec · subprocess · credential env vars · privacy directory access · system sensitive files · external HTTP requests · dynamic imports · ctypes/cffi · pickle deserialization · unsafe YAML · socket server · webhooks · service registration

**Judgment principle:** Escalate to 🔴 only with clear evidence of unauthorized access, exfiltration, destruction, or malicious intent. `eval`, `subprocess`, API key access **alone** = ⚠️ only. Combine "declared purpose × actual behavior × exfiltration path" for judgment.

**Output rules:**
- Risky skills: show permissions + purpose consistency + recommendation
- Safe skills >5: fold into `Remaining {N} ✅ No critical issues found`
- **ClawLock itself is excluded from Step 4 results**

### Step 5 — SOUL.md + Memory File Drift

Scans SOUL.md / CLAUDE.md / HEARTBEAT.md / MEMORY.md / memory/*.md:
1. **Prompt injection** — instruction override / role hijack / jailbreak keywords
2. **Encoding obfuscation** — Unicode smuggling, long base64 strings
3. **SHA-256 drift** — baseline comparison against `~/.clawlock/drift_hashes.json`

**Safety guardrails:** Do not read, enumerate, or summarize actual contents of albums, ~/Documents, ~/Downloads, chat history, or log files. Do not use sudo or sandbox escape attempts. Only read config metadata, permission states, and file hashes.

### Step 6 — MCP Exposure + Implicit Tool Poisoning (6 patterns)

Scans MCP config files for:

| Risk | Level |
|------|-------|
| Bound to 0.0.0.0 (external exposure) | 🔴 Critical |
| Remote non-localhost endpoint | ⚠️ Medium |
| Plaintext credentials in env | 🔴 High |
| Risky env vars in env (NODE_OPTIONS etc.) | 🔴 High |
| Parameter Tampering (ASR≈47%) | 🔴 Critical |
| Function Hijacking (ASR≈37%) | 🔴 High |
| Implicit Trigger (ASR≈27%) | 🔴 Critical |
| Rug Pull indicators | ⚠️ Medium |
| Tool Shadowing | 🔴 High |
| Cross-origin Escalation | ⚠️ Medium |

Detection covers all LLM-visible fields: description · annotations · errorTemplate · outputTemplate · inputSchema parameter descriptions.

### Step 7 — CVE Vulnerability Matching

Queries ClawLock cloud vulnerability intelligence.

**Resilience rules:** If the API is unavailable, clearly state "online CVE matching was not completed for this run, recommend retrying later". **Never claim "zero vulnerabilities found"** when intelligence is unavailable. Show max 8 most severe CVEs; note remaining count below table.

### Step 8 — Cost Analysis

Detect expensive models, high-frequency heartbeats, oversized max_tokens.

### Step 9 — LLM Red-Team (optional, requires --endpoint)

9 agent-specific plugins × 8 attack strategies (including encoding bypass).

> ⚠️ **External dependency:** This feature requires Node.js and promptfoo (`npm install -g promptfoo`). If the current environment cannot install it, skip this step — the remaining 8 scan steps remain fully functional. In Skill environments where Node.js is typically unavailable, this step auto-skips with an explanation.

---

## Feature 2: Single Skill Audit

```bash
clawlock skill /path/to/skill-dir
clawlock skill /path/to/SKILL.md --no-cloud
```

### Audit Workflow

**Step 1 — Determine whether cloud lookup applies:**

| Skill Source | Handling |
|-------------|---------|
| `local` / `github` | Skip cloud lookup, go straight to local audit |
| `clawhub` or other managed registry | Query cloud intel first, then overlay local audit |
| Cloud returns `unknown` / request fails | Fall back to local audit |

**Step 2 — Skill information collection:**

Collect minimum context for audit (do not generate lengthy background analysis):
- Skill name + SKILL.md declared purpose (1 sentence)
- Files with executable logic: scripts/, shell files, package.json, configs
- Actual capabilities used: file read/write/delete · network access · shell/subprocess · sensitive access (env/credentials/privacy paths)
- Declared permissions vs actually used permissions gap

**Step 3 — Local static analysis:** Uses 46-pattern deterministic engine. Judgment principles same as Feature 1 Step 4.

### Output format (strict — do not expand into full report)

Safe:
> No critical issues found in the current static check. You may proceed with evaluation before installing.

Elevated but no malicious evidence:
> Attention items found, but no clear malicious evidence. This skill has `{specific capabilities}` used for `{declared purpose}`. Recommended only with confirmed trusted source and acceptable permission scope.

Confirmed risk:
> Risk found, not recommended for installation. This skill `{main risk description}`, exceeding its declared functionality.

**No absolute wording:** Never use "absolutely safe", "safe to use", "no risk whatsoever". Conclusions are limited to "within current static check scope".

---

## Feature 3: Skill Import Pre-check

**Automatically checks new SKILL.md for security risks before import, notifying the user immediately.**

```bash
clawlock precheck ./new-skill/SKILL.md
```

5-dimension detection:
1. **Prompt injection** — 46 malicious patterns (including Chinese)
2. **Sensitive permissions** — sudo/root/full disk/dangerous env vars
3. **Suspicious URLs** — .xyz/.tk/.ml high-risk TLDs
4. **Hidden content** — Zero-width characters (Unicode smuggling)
5. **Abnormal size** — File exceeds 50KB

---

## Feature 4: Hardening Wizard

```bash
clawlock harden              # Interactive
clawlock harden --auto       # Non-breaking measures only
clawlock harden --auto-fix   # Auto-fix (e.g. credential dir permissions)
```

| ID | Measure | UX Impact | Confirm | Auto-fix |
|----|---------|-----------|---------|---------|
| H001 | Restrict file access to workspace | ⚠️ Cross-dir skills break | Yes | No |
| H002 | Enable Gateway auth | ⚠️ External tools need token | Yes | No |
| H003 | Shorten session retention | ⚠️ History unavailable | Yes | No |
| H004 | Disable browser control | ⚠️ Browser-dependent skills stop | Yes | No |
| H005 | Configure network allowlist | None | No | No |
| H006 | Audit MCP config | Guidance only | No | No |
| H007 | Establish drift baseline | None | No | No |
| H008 | Enable approval mode | ⚠️ Each dangerous op needs confirm | Yes | No |
| H009 | Tighten credential dir perms | None | No | ✅ Yes |
| H010 | Configure rate limiting | None | No | No |

**Rule: Measures requiring confirmation must display the UX impact in yellow, then wait for explicit `y`. Default is No.**

---

## Features 5–11: Additional Capabilities

```bash
clawlock soul --update-baseline    # Update drift baseline
clawlock discover                  # Discovery (~/.openclaw, ~/.zeroclaw, ~/.claude)
clawlock redteam URL --deep        # Red-team (9 plugins × 8 strategies) ⚠️ requires promptfoo
clawlock mcp-scan ./src            # MCP deep code scan (includes dependency CVE checks)
clawlock agent-scan --code ./src   # OWASP ASI 14 categories (includes dependency CVE checks)
clawlock agent-scan --code ./src --llm           # Add LLM semantic assessment layer
```

> **Dependency note:** All commands except `clawlock redteam` require only `pip install clawlock` — zero external binaries needed.
> If ai-infra-guard binary is installed on the system, `mcp-scan` and `agent-scan` will automatically use it as an optional enhancement on top of the built-in engine results.

---

## Full Report Output Specification

**The following applies ONLY to Feature 1 full scan**. Do not use for Feature 2-11 single-item responses.

### Strict Output Boundary

- Output must start from `# 🏥 ClawLock Security Scan Report` — no preamble, no progress narration
- Fixed order: report header → Steps 1-9 → report footer
- Do not append extra recommendation lists or interactive prompts after the footer
- Remediation advice: only "upgrade to latest version" — no specific commands

### Report Template

```
# 🏥 ClawLock Security Scan Report

📅 {datetime}
🖥️ {adapter} {version} · {OS}
📦 Score {score}/100 · {1-sentence risk summary}

| Check | Status | Details |
|-------|--------|---------|
| Config audit | {✅/⚠️/🔴} | {short} |
| Process detection | {✅/⚠️/🔴} | {short} |
| Credential audit | {✅/⚠️/🔴} | {short} |
| Skill supply chain | {✅/⚠️/🔴} | {N high M medium} |
| Prompts & memory | {✅/⚠️/🔴} | {short} |
| MCP exposure | {✅/⚠️/🔴} | {short} |
| CVE matching | {✅/🔴/ℹ️ unavailable} | {short} |
| Cost analysis | {✅/⚠️} | {short} |
| Overall | {✅/⚠️/🔴} | {overall + 1-sentence recommendation} |
```

### Per-Step Output Format

**Step 1 Config Audit:**

| Status | Check | Risk & Recommendation |
|--------|-------|-----------------------|
| ✅ | Gateway auth | Enabled, external access requires credentials. |
| ⚠️ | File access scope | Includes root directory, recommend restricting to project directory. |

> All passing: ✅ No obvious configuration risks found.

**Step 4 Skill Supply Chain (sorted by risk level):**

| Skill | Purpose | Permissions | Safety | Risk & Recommendation |
|-------|---------|-------------|--------|----------------------|
| `{name}` | {short} | {tags} | {✅/⚠️/🔴} | {short} |
| `Remaining {N}` | Normal | Standard | ✅ | Monitor source and updates |

**Step 7 CVE (sorted by severity):**

| Severity | ID | Cause & Impact |
|----------|----|----------------|
| 🔴 Critical | CVE-xxxx | {cause + impact} |

> More than 8: show top 8. Note: {N} more, recommend upgrading.

---

## Unified Writing Rules

- All user-facing output in the **user's language** (CVE IDs, code, commands excepted)
- Target audience: general users. Use "what could happen" and "what to do" language
- Use only Markdown headings, tables, blockquotes, and short paragraphs
- Each table cell: max 1 sentence; at most "problem + recommendation" merged
- No line breaks within table cells
- No mixing of long sentences, bullet lists, and extra summaries
- Use everyday descriptions instead of abstract security jargon
- No absolute wording: "absolutely safe", "no risk", "fully resolved"
- Single-item audits (Feature 2): concise conclusion only, **never expand into full report**

---

## Capability Boundaries

This skill performs **static analysis + remote probing**. It cannot:
- Detect purely runtime malicious behavior
- Guarantee the absence of unknown vulnerabilities
- Execute real attacks or confirm exploitability
- Read system privacy directories, session records, or media files

Since v1.1, MCP deep scan and Agent-Scan use built-in Python engines (regex + AST taint tracking) with no external binary dependencies. The built-in engines detect known patterns; for complex cross-function semantic vulnerabilities, enable the LLM assessment layer via `--llm` (requires API key).

All conclusions represent best-effort assessment within current check scope.

## Feature 12: Scan History

```bash
clawlock history            # View last 20 scan records
clawlock history --limit 50 # View last 50
```

Automatically records score, critical/warning counts, and device fingerprint for every `clawlock scan` run. Persistent storage at `~/.clawlock/scan_history.json`. Supports trend comparison (📈 improving / 📉 degrading).

## Feature 13: Watch Mode

```bash
clawlock watch                    # Scan every 5 minutes, Ctrl+C to stop
clawlock watch --interval 60      # Every 60 seconds
clawlock watch --count 10         # Stop after 10 rounds
```

Periodically re-scans config drift + memory file drift + process changes. Alerts immediately when critical changes are detected. Suitable for long-term post-deployment monitoring.
