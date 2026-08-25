"""
ClawLock v2.6.0 core scanners — Finding model, config audit, skill supply-chain (55+ patterns),
SOUL.md + memory file drift, MCP exposure + 6 tool poisoning patterns, process detection,
credential directory audit, installation discovery, risky env vars, skill precheck.
"""

from __future__ import annotations
import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from ..adapters import AdapterSpec, load_config, run_cmd
from ..i18n import t

CRIT = "critical"
HIGH = "high"
WARN = "medium"
INFO = "info"

# Map any incoming level string (from external tools, audit output, agent
# scanners, etc.) to one of the four canonical levels. Keeping this in one
# place stops the rest of the codebase from having to defend against random
# spellings like "warning" / "review" / "Severe".
_LEVEL_ALIASES: Dict[str, str] = {
    "critical": CRIT, "crit": CRIT, "severe": CRIT, "fatal": CRIT,
    "high": HIGH, "error": HIGH, "err": HIGH,
    "medium": WARN, "warn": WARN, "warning": WARN,
    "review": WARN, "moderate": WARN, "mid": WARN,
    "info": INFO, "low": INFO, "informational": INFO,
    "ok": INFO, "passed": INFO, "none": INFO,
}


def normalize_level(level: str) -> str:
    """Return one of CRIT / HIGH / WARN / INFO for any input string."""
    if not level:
        return INFO
    return _LEVEL_ALIASES.get(str(level).lower().strip(), INFO)


@dataclass
class Finding:
    scanner: str
    level: str
    title: str
    detail: str
    location: str = ""
    snippet: str = ""
    remediation: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.level = normalize_level(self.level)


@dataclass
class ConfigRule:
    """Single source of truth for static config audit rules.

    A rule is consumed by ``scan_config`` (filtered by ``adapters``) and / or
    by the OWASP-ASI agent scanner (filtered by ``asi is not None``). Keeping
    the registry shared lets ``measure_ids`` and ``asi`` tags travel with the
    rule rather than living in lookup tables that drift out of sync.
    """

    key: str
    check: Callable[[Any], bool]
    level: str
    title: str
    detail: str
    remediation: str = ""
    adapters: List[str] = field(default_factory=list)  # empty == universal
    measure_ids: List[str] = field(default_factory=list)
    asi: Optional[str] = None


@dataclass(frozen=True)
class SkillPatternRule:
    """Typed rule for new Skill detectors with stable machine metadata."""

    rule_id: str
    pattern: str
    level: str
    title: str
    detail: str
    category: str
    confidence: str = "high"


_ERROR_LOG_MAX_BYTES = 1024 * 1024  # 1 MiB before rotation


def _log_scanner_error(label: str, exc: BaseException) -> None:
    """Append a traceback for `label` to ~/.clawlock/error.log with rotation.

    When the log exceeds 1 MiB it is rotated to error.log.1 (overwriting any
    previous rotation) so heavy users do not accumulate unbounded files.
    """
    import traceback as _tb
    from datetime import datetime as _dt

    try:
        log_dir = Path.home() / ".clawlock"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "error.log"
        if log_path.exists() and log_path.stat().st_size > _ERROR_LOG_MAX_BYTES:
            rotated = log_dir / "error.log.1"
            try:
                if rotated.exists():
                    rotated.unlink()
                log_path.rename(rotated)
            except Exception:
                # Rotation is best-effort; if it fails just keep appending.
                pass
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n--- {_dt.now().isoformat()} {label} ---\n")
            fh.write(_tb.format_exc())
    except Exception:
        pass


def _scanner_error_finding(label: str, exc: BaseException) -> "Finding":
    """Build a WARN finding describing a scanner crash and persist a traceback.

    Used by the scan orchestrator so a failing scanner is visible in the
    report instead of silently producing zero findings. Scanner name is
    "internal" so reporters can opt these out of security scoring.
    """
    _log_scanner_error(label, exc)
    return Finding(
        scanner="internal",
        level=WARN,
        title=t(f"扫描器异常：{label}", f"Scanner failed: {label}"),
        detail=t(
            f"{type(exc).__name__}: {exc}. 详见 ~/.clawlock/error.log",
            f"{type(exc).__name__}: {exc}. See ~/.clawlock/error.log for details.",
        ),
        remediation=t(
            "查看 ~/.clawlock/error.log 中的完整堆栈，并向 ClawLock 反馈。",
            "Inspect ~/.clawlock/error.log for the full traceback and report the issue to ClawLock.",
        ),
    )


CONFIG_RULES: List[ConfigRule] = [
    # ── Adapter-scoped rules (no ASI tag — surfaced by ``scan_config``) ──
    ConfigRule(
        key="gatewayAuth",
        check=lambda v: not v,
        level=CRIT,
        title=t("Gateway 鉴权未开启", "Gateway auth not enabled"),
        detail=t("任何能访问端口的人可直接连接 agent。", "Anyone with port access can connect to the agent directly."),
        remediation=t("设置 gatewayAuth: true 并配置 token。", "Set gatewayAuth: true and configure a token."),
        adapters=["openclaw"],
        measure_ids=["H002"],
    ),
    ConfigRule(
        key="allowedDirectories",
        check=lambda v: isinstance(v, list) and "/" in v,
        level=HIGH,
        title=t("文件访问范围包含根目录", "File access scope includes root directory"),
        detail=t("skill 可读写系统任意文件。", "Skills can read/write any file on the system."),
        remediation=t("收紧到项目目录。", "Restrict to the project directory."),
        adapters=["openclaw"],
        measure_ids=["H001"],
    ),
    ConfigRule(
        key="enableBrowserControl",
        check=lambda v: v is True,
        level=WARN,
        title=t("已开启浏览器控制权限", "Browser control enabled"),
        detail=t("agent 可控制本地浏览器会话。", "Agent can control local browser sessions."),
        remediation=t("设置 enableBrowserControl: false。", "Set enableBrowserControl: false."),
        adapters=["openclaw"],
        measure_ids=["H004"],
    ),
    ConfigRule(
        key="allowNetworkAccess",
        check=lambda v: v is True,
        level=WARN,
        title=t("网络访问未配置白名单", "Network access has no allowlist"),
        detail=t("skill 可向任意地址发起请求。", "Skills can make requests to any address."),
        remediation=t("配置 allowedNetworkDomains 白名单。", "Configure allowedNetworkDomains allowlist."),
        adapters=["openclaw"],
        measure_ids=["H005"],
    ),
    ConfigRule(
        key="sessionRetentionDays",
        check=lambda v: isinstance(v, int) and v > 30,
        level=INFO,
        title=t("会话日志保留时间过长", "Session log retention too long"),
        detail=t("超过 30 天。", "Exceeds 30 days."),
        remediation=t("设置 sessionRetentionDays: 7。", "Set sessionRetentionDays: 7."),
        adapters=["openclaw"],
        measure_ids=["H003"],
    ),
    ConfigRule(
        key="auth.enabled",
        check=lambda v: not v,
        level=CRIT,
        title=t("ZeroClaw 鉴权未开启", "ZeroClaw auth not enabled"),
        detail=t("服务端口未设置认证。", "Service port has no authentication."),
        remediation=t("启用 auth.enabled: true。", "Enable auth.enabled: true."),
        adapters=["zeroclaw"],
        measure_ids=["H002"],
    ),
    ConfigRule(
        key="filesystem.allowedPaths",
        check=lambda v: isinstance(v, list) and any(p in ("/", "~") for p in v),
        level=HIGH,
        title=t("文件访问范围过宽", "File access scope too broad"),
        detail=t("allowedPaths 包含根路径。", "allowedPaths includes root path."),
        remediation=t("限制到项目路径。", "Restrict to the project path."),
        adapters=["zeroclaw"],
        measure_ids=["H001"],
    ),
    ConfigRule(
        key="permissions.allow",
        check=lambda v: isinstance(v, list) and any("**" in str(p) for p in v),
        level=WARN,
        title=t("权限使用通配符 **", "Permissions use ** wildcard"),
        detail=t("settings.json 中存在 ** 通配符。", "** wildcard found in settings.json."),
        remediation=t("替换为具体路径。", "Replace with specific paths."),
        adapters=["claude-code"],
        measure_ids=["H001"],
    ),
    ConfigRule(
        key="server.host",
        check=lambda v: v in ("0.0.0.0", "::", "*"),
        level=HIGH,
        title=t("服务绑定到所有网络接口", "Service bound to all network interfaces"),
        detail=t("外部网络可能直接访问。", "External networks may access directly."),
        remediation=t("绑定到 127.0.0.1。", "Bind to 127.0.0.1."),
        measure_ids=["H006"],
    ),
    ConfigRule(
        key="tls.enabled",
        check=lambda v: v in (False, "disabled", None),
        level=WARN,
        title=t("TLS/HTTPS 未启用", "TLS/HTTPS not enabled"),
        detail=t("通信未加密。", "Communication is not encrypted."),
        remediation=t("启用 TLS。", "Enable TLS."),
    ),
    ConfigRule(
        key="approvalMode",
        check=lambda v: v in (False, "none", "disabled", None),
        level=WARN,
        title=t("操作审批未启用", "Operation approval not enabled"),
        detail=t("高危操作无需确认。", "High-risk operations require no confirmation."),
        remediation=t("启用审批模式。", "Enable approval mode."),
        measure_ids=["H008"],
    ),
    ConfigRule(
        key="rateLimit.enabled",
        check=lambda v: v in (False, None, "disabled"),
        level=WARN,
        title=t("未配置速率限制", "Rate limiting not configured"),
        detail=t("可被暴力破解或滥用，可能导致 API 额度耗尽。", "Vulnerable to brute force or abuse; may exhaust API quota."),
        remediation=t("为 Gateway 配置请求速率限制。", "Configure request rate limiting for the Gateway."),
        measure_ids=["H010"],
    ),
    # ── ASI-scoped rules (surfaced only by ``scan_agent_config``) ──
    ConfigRule(
        key="tools.exec.security",
        check=lambda v: v in (None, "allow", ""),
        level=CRIT,
        title=t("执行策略未限制", "Execution policy unrestricted"),
        detail=t("tools.exec.security 未设为 deny/allowlist，agent 可执行任意命令。", "tools.exec.security is not set to deny/allowlist; agent can execute arbitrary commands."),
        remediation=t("设为 security: deny 或 security: allowlist。", "Set security: deny or security: allowlist."),
        asi="ASI-01",
    ),
    ConfigRule(
        key="tools.exec.ask",
        check=lambda v: v in (None, "off", "never"),
        level=HIGH,
        title=t("命令执行无需审批", "Command execution requires no approval"),
        detail=t("tools.exec.ask 未开启，命令执行不弹审批提示。", "tools.exec.ask is not enabled; command execution does not prompt for approval."),
        remediation=t("设为 ask: always 或 ask: on-miss。", "Set ask: always or ask: on-miss."),
        asi="ASI-01",
        measure_ids=["H008"],
    ),
    ConfigRule(
        key="gateway.auth.token",
        check=lambda v: not v,
        level=CRIT,
        title=t("Gateway 无认证", "Gateway has no authentication"),
        detail=t("未配置 gateway.auth.token/password，服务端口完全开放。", "gateway.auth.token/password not configured; service port is fully open."),
        remediation=t("设置强随机 gateway.auth.token。", "Set a strong random gateway.auth.token."),
        asi="ASI-05",
        measure_ids=["H002"],
    ),
    ConfigRule(
        key="gateway.bind",
        check=lambda v: v and v not in ("loopback", "127.0.0.1", "localhost"),
        level=HIGH,
        title=t("Gateway 绑定非回环地址", "Gateway bound to non-loopback address"),
        detail=t("Gateway 暴露到网络，增加攻击面。", "Gateway is exposed to the network, increasing attack surface."),
        remediation=t("设为 bind: loopback 或通过 SSH/Tailscale 隧道访问。", "Set bind: loopback or access via SSH/Tailscale tunnel."),
        asi="ASI-05",
        measure_ids=["H006"],
    ),
    ConfigRule(
        key="tools.browser.enabled",
        check=lambda v: v is True,
        level=WARN,
        title=t("浏览器控制已开启", "Browser control is enabled"),
        detail=t("Agent 可操控浏览器，带来 cookie 窃取等风险。", "Agent can control the browser, risking cookie theft and more."),
        remediation=t("仅在需要时开启。", "Enable only when needed."),
        asi="ASI-09",
        measure_ids=["H004"],
    ),
    ConfigRule(
        key="tools.sessions.visibility",
        check=lambda v: v in (None, "all"),
        level=WARN,
        title=t("会话可见性过宽", "Session visibility too broad"),
        detail=t("会话工具可跨会话访问对话内容。", "Session tools can access conversation content across sessions."),
        remediation=t("设为 visibility: self 或 visibility: tree。", "Set visibility: self or visibility: tree."),
        asi="ASI-09",
    ),
    ConfigRule(
        key="agents.defaults.sandbox.mode",
        check=lambda v: v in (None, "off", ""),
        level=HIGH,
        title=t("沙箱模式未开启", "Sandbox mode not enabled"),
        detail=t("Agent 直接在宿主环境执行，无容器隔离。", "Agent runs directly on host without container isolation."),
        remediation=t("设为 sandbox.mode: docker。", "Set sandbox.mode: docker."),
        asi="ASI-11",
    ),
    ConfigRule(
        key="agents.defaults.sandbox.docker.network",
        check=lambda v: v and v != "none",
        level=WARN,
        title=t("沙箱容器有网络访问", "Sandbox container has network access"),
        detail=t("沙箱网络未隔离，容器可访问网络。", "Sandbox network not isolated; container can access the network."),
        remediation=t("设为 docker.network: none。", "Set docker.network: none."),
        asi="ASI-11",
    ),
    ConfigRule(
        key="commands.ownerDisplay",
        check=lambda v: v in (None, "visible", ""),
        level=WARN,
        title=t("所有者信息暴露在提示词中", "Owner information exposed in prompts"),
        detail=t("所有者身份可能被第三方模型提供者看到。", "Owner identity may be visible to third-party model providers."),
        remediation=t("设为 ownerDisplay: hash 并配置 ownerDisplaySecret。", "Set ownerDisplay: hash and configure ownerDisplaySecret."),
        asi="ASI-12",
    ),
    ConfigRule(
        key="hooks.allowRequestSessionKey",
        check=lambda v: v is True,
        level=HIGH,
        title=t("Hook 允许指定 sessionKey", "Hook allows specifying sessionKey"),
        detail=t("外部可通过 hook 定向路由消息到指定会话。", "External parties can route messages to specific sessions via hooks."),
        remediation=t("设为 allowRequestSessionKey: false。", "Set allowRequestSessionKey: false."),
        asi="ASI-08",
    ),
]
SECRET_PATTERNS = [
    ("sk-(?!ant-)[A-Za-z0-9]{20,}", "OpenAI API Key"),
    ("ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    ("github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT"),
    ("gh(?:o|u)_[A-Za-z0-9]{20,}", "GitHub OAuth/User Token"),
    ("tp-[A-Za-z0-9._-]{16,}", "Xiaomi MiMo Token Plan API Key"),
    ("xoxb-[0-9]{10,}", "Slack Token"),
    ("xoxp-[0-9A-Za-z-]{10,}", "Slack User Token"),
    ("AKIA[0-9A-Z]{16}", "AWS Key"),
    ("AIza[0-9A-Za-z\\-_]{35}", "Google API Key"),
    ("-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key"),
    ("sk-ant-[A-Za-z0-9\\-]{20,}", "Anthropic API Key"),
]
_COMPILED_SECRET_PATTERNS = [(re.compile(p), label) for p, label in SECRET_PATTERNS]

RISKY_ENV_VARS = [
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "LD_LIBRARY_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
    "NODE_PATH",
    "ELECTRON_RUN_AS_NODE",
]


def _get_nested(d: dict, dotpath: str):
    cur = d
    for p in dotpath.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


_MAX_NESTED_DEPTH = 50  # caps recursive walks; legit configs are <10 deep

# Shared limits for untrusted Skill packages.  Track B demonstrated the value
# of scanning extensionless/unusual text files, but its prototype sliced only
# after ``read_text()`` and therefore still loaded an entire oversized file.
# The mainline implementation performs bounded binary reads instead.
_SKILL_MAX_FILE_BYTES = 2 * 1024 * 1024
_SKILL_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_SKILL_MAX_FILES = 2000
_SKILL_MAX_LINE_CHARS = 4_096
_SKILL_PRUNED_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv"}
)
_SKILL_BINARY_EXTENSIONS = frozenset(
    {
        ".7z",
        ".a",
        ".avi",
        ".bin",
        ".bmp",
        ".bz2",
        ".class",
        ".dat",
        ".db",
        ".dll",
        ".dylib",
        ".eot",
        ".exe",
        ".flac",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".mkv",
        ".mov",
        ".mp3",
        ".mp4",
        ".node",
        ".o",
        ".ogg",
        ".otf",
        ".pdf",
        ".png",
        ".pyc",
        ".pyo",
        ".rar",
        ".so",
        ".sqlite",
        ".tar",
        ".tgz",
        ".ttf",
        ".wav",
        ".wasm",
        ".webp",
        ".woff",
        ".woff2",
        ".xz",
        ".zip",
    }
)
_SKILL_BINARY_MAGIC_PREFIXES = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf'\x1c",
    b"Rar!\x1a\x07",
    b"\x7fELF",
    b"MZ",
    b"SQLite format 3\x00",
    b"\x00asm",
    b"\xca\xfe\xba\xbe",
    b"OTTO",
    b"wOFF",
    b"wOF2",
    b"BM",
    b"ID3",
    b"fLaC",
    b"OggS",
    b"RIFF",
)
_SKILL_LONG_LINE_ANCHOR_RE = re.compile(
    r"(?i)(?:https?://|curl|wget|powershell|invoke-|\biex\b|\bnc\b|netcat|"
    r"/dev/tcp|socket|subprocess|\brm\b|sudoers|authorized_keys|ld\.so\.preload|"
    r"/etc/passwd|\beval\b|\bexec\b|deserialize|unserialize|jsonpickle|"
    r"systemctl|crontab|schtasks|launchctl|token|secret|password|api[_-]?key|"
    r"base64|chmod|mkfs|tool_call|function_call|\bmcp\b|jailbreak|"
    r"ignore\s+(?:all\s+)?(?:previous|above))"
)


# ── BIP39 / wallet mnemonic detector ─────────────────────────────────────────
# A real BIP39 mnemonic is exactly 12 / 15 / 18 / 21 / 24 words, each drawn
# from the standardised 2048-word BIP39 English wordlist. We require every
# matched word to be in the wordlist — typos invalidate the BIP39 checksum
# anyway, so a "near-match" mnemonic is not a real threat, while strict
# membership eliminates almost all prose false positives.
_MNEMONIC_RE = re.compile(
    r"\b(?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}\b"
)
_BIP39_VALID_LENGTHS = frozenset({12, 15, 18, 21, 24})

_BIP39_WORDLIST: Optional[frozenset] = None


def _load_bip39_wordlist() -> frozenset:
    """Lazy-load the BIP39 English wordlist shipped beside this module."""
    global _BIP39_WORDLIST
    if _BIP39_WORDLIST is not None:
        return _BIP39_WORDLIST
    try:
        path = Path(__file__).parent / "bip39_english.txt"
        _BIP39_WORDLIST = frozenset(
            w.strip().lower()
            for w in path.read_text(encoding="utf-8").splitlines()
            if w.strip()
        )
    except Exception:
        _BIP39_WORDLIST = frozenset()
    return _BIP39_WORDLIST


def _looks_like_mnemonic(text: str) -> bool:
    """Return True when *text* contains a plausible BIP39 mnemonic span.

    A span qualifies only when:
      1. It contains 12 / 15 / 18 / 21 / 24 short lowercase words separated
         by single spaces (the five BIP39-permitted lengths).
      2. Every word is a member of the BIP39 English wordlist.

    Real mnemonics repeat words freely (the canonical test vector is 11×
    ``abandon`` + 1× ``about``), so uniqueness is intentionally not required.
    """
    match = _MNEMONIC_RE.search(text)
    if not match:
        return False
    words = match.group(0).split()
    if len(words) not in _BIP39_VALID_LENGTHS:
        return False
    wordlist = _load_bip39_wordlist()
    if not wordlist:
        # Wordlist file missing (e.g. broken install) — bail rather than
        # fall back to a weak heuristic that produces false positives.
        return False
    return all(w in wordlist for w in words)


def _check_mnemonic(obj: Any, path: str, depth: int = 0) -> List[Finding]:
    """Detect plausible wallet mnemonic phrases in any string value."""
    findings: List[Finding] = []
    if depth > _MAX_NESTED_DEPTH:
        return findings
    if isinstance(obj, dict):
        for k, v in obj.items():
            findings.extend(_check_mnemonic(v, f"{path}.{k}", depth + 1))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            findings.extend(_check_mnemonic(item, f"{path}[{i}]", depth + 1))
    elif isinstance(obj, str) and _looks_like_mnemonic(obj):
        findings.append(
            Finding(
                "credential",
                CRIT,
                t("配置中发现疑似助记词", "Suspected wallet mnemonic in config"),
                t(
                    f"在 {path} 中发现 12/18/24 个短词组成的连续序列，疑似 BIP39 钱包助记词。",
                    f"Found a continuous run of 12/18/24 short words at {path}; matches the shape of a BIP39 wallet mnemonic.",
                ),
                path,
                remediation=t(
                    "立即将助记词从配置中移除并视为已泄露，迁移到硬件钱包或安全密钥管理。",
                    "Remove the mnemonic from config immediately, treat it as compromised, and migrate to a hardware wallet or secrets manager.",
                ),
                metadata={"category": "WALLET"},
            )
        )
    return findings


def _check_secrets(obj: Any, path: str, depth: int = 0) -> List[Finding]:
    findings = []
    if depth > _MAX_NESTED_DEPTH:
        return findings
    if isinstance(obj, dict):
        for k, v in obj.items():
            findings.extend(_check_secrets(v, f"{path}.{k}", depth + 1))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            findings.extend(_check_secrets(item, f"{path}[{i}]", depth + 1))
    elif isinstance(obj, str):
        for compiled_pat, label in _COMPILED_SECRET_PATTERNS:
            if compiled_pat.search(obj):
                findings.append(
                    Finding(
                        "config",
                        CRIT,
                        t(f"配置中发现硬编码凭据: {label}", f"Hardcoded credential found: {label}"),
                        t(f"在 {path} 中发现疑似 {label}。", f"Suspected {label} found in {path}."),
                        path,
                        remediation=t("移除硬编码凭据，改用环境变量。", "Remove hardcoded credentials; use environment variables instead."),
                    )
                )
                break
    return findings


def _check_risky_env(config: dict, cfg_path: str) -> List[Finding]:
    """v1.1: Check for dangerous env vars (NODE_OPTIONS, LD_PRELOAD etc.) in skill/MCP config."""
    findings = []

    def _walk(obj, path, depth=0):
        if depth > _MAX_NESTED_DEPTH:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.upper() in RISKY_ENV_VARS:
                    findings.append(
                        Finding(
                            "config",
                            HIGH,
                            t(f"发现危险环境变量: {k}", f"Dangerous env var found: {k}"),
                            t(f"配置项 {path}.{k} 可被利用注入恶意代码。", f"Config key {path}.{k} can be exploited for code injection."),
                            f"{cfg_path}:{path}.{k}",
                            remediation=t(f"移除 {k} 或确认其值安全。", f"Remove {k} or verify its value is safe."),
                        )
                    )
                _walk(v, f"{path}.{k}", depth + 1)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]", depth + 1)

    _walk(config, "config")
    return findings


_AUDIT_LEVEL_KEYWORDS = {
    "CRITICAL": CRIT,
    "HIGH": HIGH,
    "WARN": WARN,
    "ERROR": HIGH,
}


def _parse_native_audit_findings(output: str, location: str) -> List[Finding]:
    findings: List[Finding] = []
    pending_level: Optional[str] = None
    last_finding: Optional[Finding] = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            pending_level = None
            last_finding = None
            continue

        upper = line.upper()
        if upper in _AUDIT_LEVEL_KEYWORDS:
            pending_level = _AUDIT_LEVEL_KEYWORDS[upper]
            last_finding = None
            continue

        if re.match(
            r"(?i)^found\s+\d+\s+(?:critical|high|warn|warning|info)\s+issue\(s\)\s+in\s+\d+\s+scanned\s+file\(s\)",
            line,
        ) or line.startswith(("Summary:", "Summary：")):
            pending_level = None
            last_finding = None
            continue

        if line.startswith(("Location:", "Location：")):
            if last_finding and (
                not last_finding.location or last_finding.location == location
            ):
                last_finding.location = line.split(":", 1)[-1].strip() or location
            continue

        if line.startswith(("Fix:", "Fix：")):
            if last_finding and not last_finding.remediation:
                last_finding.remediation = line.split(":", 1)[-1].strip()
            continue

        sev = pending_level
        if sev is None:
            for kw, lv in _AUDIT_LEVEL_KEYWORDS.items():
                if kw in upper:
                    sev = lv
                    break

        if sev is None and not any(
            (w in line.lower() for w in ("risk", "vuln", "exposed"))
        ):
            continue

        finding = Finding("config", sev or INFO, line[:120], line, location)
        findings.append(finding)
        last_finding = finding
        pending_level = None

    return findings


def scan_config(adapter: AdapterSpec) -> Tuple[List[Finding], Optional[str]]:
    findings: List[Finding] = []
    # A malformed config must fail the scan domain instead of becoming an
    # empty configuration that scores as clean.  The orchestrator converts
    # this exception into an explicit incomplete-scan diagnostic.
    config, cfg_path = load_config(adapter, strict=True)
    if adapter.audit_cmd:
        code, out, err = run_cmd(adapter.audit_cmd)
        if code == 0 and out:
            findings.extend(
                _parse_native_audit_findings(out, cfg_path or "builtin-audit")
            )
    for rule in CONFIG_RULES:
        # ``scan_config`` only fires non-ASI rules. ASI-tagged rules belong
        # to the agent scanner so they're not double-counted in reports.
        if rule.asi is not None:
            continue
        if rule.adapters and adapter.name not in rule.adapters:
            continue
        val = _get_nested(config, rule.key)
        if val is None:
            continue
        try:
            triggered = rule.check(val)
        except Exception:
            continue
        if not triggered:
            continue
        metadata: Dict[str, Any] = {}
        if rule.measure_ids:
            metadata["measure_ids"] = list(rule.measure_ids)
        findings.append(
            Finding(
                "config",
                rule.level,
                rule.title,
                rule.detail,
                f"config:{rule.key}",
                remediation=rule.remediation,
                metadata=metadata,
            )
        )
    findings.extend(_check_secrets(config, cfg_path or "config"))
    findings.extend(_check_risky_env(config, cfg_path or "config"))
    findings.extend(_check_mnemonic(config, cfg_path or "config"))
    return (findings, cfg_path)


def scan_processes(adapter: AdapterSpec) -> List[Finding]:
    """Detect running Claw processes + exposed ports (cross-platform)."""
    from ..utils import list_processes, list_listening_ports

    findings = []
    for proc in list_processes():
        for proc_name in adapter.process_names or [adapter.bin or ""]:
            if (
                proc_name
                and proc_name in proc.get("cmd", "")
                and ("clawlock" not in proc.get("cmd", ""))
            ):
                findings.append(
                    Finding(
                        "process",
                        INFO,
                        t(f"检测到运行中的进程: {proc_name}", f"Running process detected: {proc_name}"),
                        t(f"PID {proc['pid']}, 用户 {proc.get('user', 'N/A')}", f"PID {proc['pid']}, user {proc.get('user', 'N/A')}"),
                        f"ps:{proc['pid']}",
                    )
                )
                break
    for line in list_listening_ports():
        if any((p in line for p in ["18789", "18790", "3000", "8080"])):
            findings.append(
                Finding(
                    "process",
                    HIGH,
                    t("发现对外监听的高危端口", "High-risk port exposed to network"),
                    t(f"进程绑定 0.0.0.0: {line[:80]}", f"Process bound to 0.0.0.0: {line[:80]}"),
                    remediation=t("将监听地址改为 127.0.0.1。", "Change listen address to 127.0.0.1."),
                )
            )
    return findings


def discover_installations() -> List[Finding]:
    """Scan for all Claw product installations, configs, workspaces."""
    findings = []
    discovery_targets = {
        "OpenClaw": ["~/.openclaw", "~/.config/openclaw"],
        "ZeroClaw": ["~/.zeroclaw", "~/.config/zeroclaw"],
        "Claude Code": ["~/.claude", "~/.config/claude"],
    }
    found_any = False
    for product, paths in discovery_targets.items():
        for p in paths:
            d = Path(p).expanduser()
            if d.exists():
                found_any = True
                configs = list(d.glob("*.json")) + list(d.glob("*.yaml"))
                skills_dir = d / "skills"
                skill_count = (
                    len(list(skills_dir.iterdir())) if skills_dir.exists() else 0
                )
                sessions = d / "sessions"
                session_count = (
                    len(list(sessions.iterdir())) if sessions.exists() else 0
                )
                findings.append(
                    Finding(
                        "discovery",
                        INFO,
                        t(f"发现 {product} 安装: {d}", f"Found {product} installation: {d}"),
                        t(f"配置文件 {len(configs)} 个, Skills {skill_count} 个, 会话 {session_count} 个",
                          f"{len(configs)} config(s), {skill_count} skill(s), {session_count} session(s)"),
                        str(d),
                    )
                )
    from ..utils import find_all_binaries

    bins = find_all_binaries(
        ["openclaw", "zeroclaw", "claude", "promptfoo", "npx"]
    )
    for name, path in bins.items():
        if path:
            findings.append(
                Finding("discovery", INFO, t(f"发现工具: {name}", f"Tool found: {name}"), t(f"路径: {path}", f"Path: {path}"))
            )
    if not found_any:
        findings.append(
            Finding(
                "discovery",
                INFO,
                t("未发现已安装的 Claw 产品", "No Claw product installations found"),
                t("未在标准路径下找到安装目录。", "No installation directory found in standard paths."),
            )
        )
    return findings


def scan_credential_dirs(adapter: AdapterSpec) -> List[Finding]:
    """Audit credential directories and files for overly permissive access (cross-platform)."""
    from ..utils import check_file_permission, IS_WINDOWS

    findings = []
    fix_hint = t("使用 icacls 移除 Everyone/Users 访问权限", "Use icacls to remove Everyone/Users access") if IS_WINDOWS else "chmod 700"
    fix_hint_f = t("使用 icacls 限制为仅所有者访问", "Use icacls to restrict to owner-only access") if IS_WINDOWS else "chmod 600"
    for cred_path_str in adapter.credential_dirs:
        cred_path = Path(cred_path_str).expanduser()
        if not cred_path.exists():
            continue
        try:
            world_r, group_r, desc = check_file_permission(cred_path)
            if world_r:
                findings.append(
                    Finding(
                        "credential",
                        HIGH,
                        t(f"凭证目录权限过宽: {cred_path.name}", f"Credential dir too permissive: {cred_path.name}"),
                        t(f"目录 {cred_path} 对所有用户可读 ({desc})。", f"Directory {cred_path} is world-readable ({desc})."),
                        str(cred_path),
                        remediation=f"{fix_hint} {cred_path}",
                    )
                )
            elif group_r:
                findings.append(
                    Finding(
                        "credential",
                        WARN,
                        t(f"凭证目录对组用户可读: {cred_path.name}", f"Credential dir group-readable: {cred_path.name}"),
                        t(f"目录 {cred_path} 组可读 ({desc})。", f"Directory {cred_path} is group-readable ({desc})."),
                        str(cred_path),
                        remediation=f"{fix_hint} {cred_path}",
                    )
                )
            if cred_path.is_dir():
                for f in cred_path.iterdir():
                    if f.is_file() and f.suffix in (
                        ".json",
                        ".key",
                        ".pem",
                        ".token",
                        ".env",
                    ):
                        fw, _, fd = check_file_permission(f)
                        if fw:
                            findings.append(
                                Finding(
                                    "credential",
                                    HIGH,
                                    t(f"凭证文件权限过宽: {f.name}", f"Credential file too permissive: {f.name}"),
                                    t(f"文件 {f} 对所有用户可读 ({fd})。", f"File {f} is world-readable ({fd})."),
                                    str(f),
                                    remediation=f"{fix_hint_f} {f}",
                                )
                            )
        except Exception:
            pass
    return findings


# ---------------------------------------------------------------------------
# Shell command deobfuscation — recursively unwrap nested shell invocations
# so that pattern matching works on the *actual* payload.
# ---------------------------------------------------------------------------

# Matches: sh -c "...", bash -c '...', /bin/sh -c "...", cmd /c "...", etc.
_SHELL_WRAP_RE = re.compile(
    r"""(?:(?:/usr)?(?:/bin/)?(?:ba)?sh|dash|zsh|ksh)\s+-c\s+"""  # Unix shells
    r"""|cmd(?:\.exe)?\s+/[cC]\s+"""                              # Windows cmd
    r"""|powershell(?:\.exe)?\s+-(?:Command|c)\s+""",             # PowerShell
    re.VERBOSE,
)

# Matches the quoted payload after the shell -c invocation.
# Group 1: double-quoted, Group 2: single-quoted, Group 3: rest of line (unquoted).
_QUOTED_PAYLOAD_RE = re.compile(
    r"""(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|(.+))""",
)


def _unwrap_shell_commands(line: str, *, _depth: int = 0) -> List[str]:
    """Return a list of unwrapped inner commands from nested shell invocations.

    Given ``bash -c "sh -c 'rm -rf /'"`` returns ``['rm -rf /']`` (plus
    intermediate layers).  Max recursion depth is 5 to prevent pathological
    inputs from looping.
    """
    if _depth > 5:
        return []
    results: List[str] = []
    for m in _SHELL_WRAP_RE.finditer(line):
        rest = line[m.end():]
        pm = _QUOTED_PAYLOAD_RE.match(rest)
        if pm:
            payload = pm.group(1) or pm.group(2) or pm.group(3) or ""
            # Unescape basic sequences
            payload = payload.replace('\\"', '"').replace("\\'", "'")
            if payload:
                results.append(payload)
                # Recurse to handle deeper nesting
                results.extend(_unwrap_shell_commands(payload, _depth=_depth + 1))
    return results


MALICIOUS_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "curl\\b[^|&;#\\n]*\\$\\{?(?:HOME|TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIAL|ANTHROPIC_API_KEY|OPENAI_API_KEY)\\}?",
        CRIT,
        t("凭证外传 (curl)", "Credential exfiltration (curl)"),
        t("凭证通过 curl 发送到外部。", "Credentials sent externally via curl."),
    ),
    (
        "(?i)curl\\b[^|&;#\\n]*\\|\\s*(?:bash|sh)\\b",
        CRIT,
        t("下载即执行 (curl|shell)", "Download-and-execute (curl|shell)"),
        t("远程脚本通过 curl 下载后立即交给 shell 执行。", "Remote script downloaded with curl and executed immediately by a shell."),
    ),
    (
        "wget\\b[^|&;#\\n]*\\$\\{?(?:TOKEN|API_KEY|SECRET|PASSWORD)\\}?",
        CRIT,
        t("凭证外传 (wget)", "Credential exfiltration (wget)"),
        t("凭证通过 wget 发送到外部。", "Credentials sent externally via wget."),
    ),
    (
        "(?i)wget\\b[^|&;#\\n]*\\|\\s*(?:bash|sh)\\b",
        CRIT,
        t("下载即执行 (wget|shell)", "Download-and-execute (wget|shell)"),
        t("远程脚本通过 wget 下载后立即交给 shell 执行。", "Remote script downloaded with wget and executed immediately by a shell."),
    ),
    (
        "(?i)(?:Invoke-WebRequest|iwr)\\b[^|&;#\\n]*\\|\\s*(?:iex|Invoke-Expression)\\b",
        CRIT,
        t("下载即执行 (PowerShell)", "Download-and-execute (PowerShell)"),
        t("PowerShell 远程内容下载后立即通过 iex 执行。", "PowerShell downloads remote content and executes it immediately via iex."),
    ),
    (
        "bash\\s+-i\\s+>?&?\\s*/dev/tcp/",
        CRIT,
        t("反弹 Shell (bash /dev/tcp)", "Reverse shell (bash /dev/tcp)"),
        t("bash 反弹 shell。", "Bash reverse shell."),
    ),
    (
        "(?i)\\bnc\\b.{0,30}-e\\s+(?:/bin/(?:ba)?sh\\b|\\bsh\\b|\\bcmd(?:\\.exe)?\\b|\\bpowershell(?:\\.exe)?\\b)",
        CRIT,
        t("反弹 Shell (nc -e)", "Reverse shell (nc -e)"),
        t("netcat 反弹 shell。", "Netcat reverse shell."),
    ),
    (
        "python.{0,60}socket.{0,40}connect.{0,60}(?:subprocess|Popen)",
        CRIT,
        t("反弹 Shell (Python socket)", "Reverse shell (Python socket)"),
        t("Python socket+subprocess。", "Python socket+subprocess."),
    ),
    (
        "(?i)\\b(?:xmrig|stratum\\+tcp://|xmr\\.pool\\.|monero|coinhive)",
        CRIT,
        t("挖矿程序特征", "Cryptominer signature"),
        t("加密货币挖矿特征。", "Cryptocurrency mining signature detected."),
    ),
    (
        "(?i)(?:\\brm\\s+-rf\\s+(?:/root|/home|/etc|/var|/usr|~)\\b|\\b(?:rmdir|rd)\\s+/[sq]\\s+/[sq]\\s+[A-Za-z]:\\\\)",
        CRIT,
        t("危险批量删除", "Dangerous mass deletion"),
        t("rm -rf 或 rmdir /s /q 指向系统关键目录。", "rm -rf or rmdir /s /q targets critical system directories."),
    ),
    (
        "(?i)ignore\\s+(?:all\\s+)?(?:previous|above)\\s+instructions?",
        CRIT,
        t("提示词注入：覆盖指令", "Prompt injection: instruction override"),
        t("供应链 prompt injection。", "Supply-chain prompt injection."),
    ),
    (
        "(?i)you\\s+are\\s+now\\s+(?:a\\s+)?(?:different|new|another|unrestricted|uncensored)",
        CRIT,
        t("提示词注入：角色劫持", "Prompt injection: role hijacking"),
        t("重置 LLM 角色。", "LLM role reset attempt."),
    ),
    (
        "(?i)(?:show|print|reveal|dump|display|output)\\s+(?:your\\s+)?(?:system\\s+prompt|developer\\s+message|hidden\\s+instructions?|internal\\s+(?:rules|instructions))",
        HIGH,
        t("提示词注入：提取系统提示词", "Prompt injection: system prompt extraction"),
        t("尝试诱导模型输出系统提示词或内部规则。", "Attempts to coerce the model into revealing its system prompt or internal rules."),
    ),
    (
        "(?i)(?:do\\s+not|don't)\\s+(?:ask|request)\\s+(?:for\\s+)?(?:approval|confirmation|permission)|(?:assume|treat\\s+it\\s+as)\\s+(?:approval|permission)\\s+(?:is|was)\\s+(?:already\\s+)?granted",
        HIGH,
        t("提示词注入：审批绕过", "Prompt injection: approval bypass"),
        t("试图要求模型跳过审批/确认流程。", "Attempts to make the model skip approval or confirmation flows."),
    ),
    (
        "(?i)(?:before\\s+(?:replying|responding|answering)|without\\s+explaining)\\b.{0,80}\\b(?:call|invoke|run)\\s+(?:the\\s+)?tool\\b",
        WARN,
        t("强制优先调用工具", "Forced tool invocation before reply"),
        t("文本要求模型在回复前先执行工具调用。", "Text instructs the model to invoke a tool before replying."),
    ),
    (
        "(?i)(?:jailbreak|dan\\s+mode|developer\\s+mode|do\\s+anything\\s+now|skeleton\\s+key)",
        CRIT,
        t("越狱关键词", "Jailbreak keywords"),
        t("jailbreak / DAN / Skeleton Key。", "Jailbreak / DAN / Skeleton Key."),
    ),
    (
        "base64\\s+-d\\s*[|>]\\s*(?:bash|sh|python|\\$\\()",
        CRIT,
        t("混淆载荷 (base64→shell)", "Obfuscated payload (base64→shell)"),
        t("base64→shell 管道。", "base64→shell pipeline."),
    ),
    (
        "mkfifo\\s+.*\\bnc\\b",
        CRIT,
        t("命名管道反弹 Shell (mkfifo+nc)", "Named pipe reverse shell (mkfifo+nc)"),
        t("mkfifo+nc 组合反弹 shell。", "mkfifo+nc reverse shell combo."),
    ),
    (
        "(?i)(?:chmod\\s+(?:777|a\\+rwx)\\s+|\\bicacls\\b[^\\n]{0,80}/grant\\b[^\\n]{0,40}(?:Everyone|\\*S-1-1-0))",
        HIGH,
        t("危险权限变更", "Dangerous permission change"),
        t("chmod 777 或 icacls /grant Everyone 将文件设为全局可访问。", "chmod 777 or icacls /grant Everyone makes files world-accessible."),
    ),
    (
        "忽略(之前|上面|所有)(的)?(指令|规则|限制|约束)",
        CRIT,
        t("提示词注入：覆盖指令 (中文)", "Prompt injection: instruction override (Chinese)"),
        t("中文指令覆盖。", "Chinese instruction override."),
    ),
    (
        "(输出|显示|打印|泄露)(你的)?(系统提示|系统指令|内部规则)",
        HIGH,
        t("提示词注入：提取系统提示词 (中文)", "Prompt injection: system prompt extraction (Chinese)"),
        t("提取系统提示词。", "System prompt extraction attempt."),
    ),
    (
        "(不要|别)(再)?(请求|询问)(审批|确认|授权)|(默认|视为)(已经)?(获得|有)(审批|授权)",
        HIGH,
        t("提示词注入：审批绕过 (中文)", "Prompt injection: approval bypass (Chinese)"),
        t("试图要求模型跳过审批或视为已授权。", "Attempts to make the model skip approval or assume permission was granted."),
    ),
    (
        "(你现在是|从现在开始你是|扮演|假装)(一个)?",
        WARN,
        t("疑似角色劫持 (中文)", "Suspected role hijacking (Chinese)"),
        t("中文角色重定义指令。", "Chinese role redefinition instruction."),
    ),
    (
        "(?:\\\\u[0-9a-fA-F]{4}){6,}",
        HIGH,
        t("大量 Unicode 转义（疑似混淆）", "Excessive Unicode escapes (suspected obfuscation)"),
        t("Unicode 转义隐藏注入指令。", "Unicode escapes may hide injected instructions."),
    ),
    (
        "(?i)(?:password|secret|token|api_key|api-key)\\s*[=:]\\s*[\"\\'][^\\s\"\\']{12,}[\"\\']",
        HIGH,
        t("疑似硬编码凭证", "Suspected hardcoded credential"),
        t("代码中存在凭证字符串。", "Credential string found in code."),
    ),
    # Credential token patterns reuse SECRET_PATTERNS as single source of truth.
    (
        "|".join(f"(?:{pat})" for pat, _ in SECRET_PATTERNS),
        HIGH,
        t("疑似凭证/令牌", "Suspected credential or token"),
        t("发现与已知凭证格式匹配的字符串。", "String matching a known credential format was found."),
    ),
    (
        "(?i)(?:export|setenv|ENV)\\s+(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES)\\s*=",
        HIGH,
        t("设置危险环境变量", "Dangerous env var being set"),
        t("通过 export 设置可注入代码的环境变量。", "Env var set via export that enables code injection."),
    ),
    (
        "(?i)(?:\\bfsutil\\b|\\bformat\\b[^\\n]{0,20}[A-Za-z]:|\\bformat\\.com\\b|\\bdiskpart\\b|\\bmkfs(?:\\.[a-z0-9]+)?\\b|\\bdiskutil\\s+(?:erase|partition|zero|secure)|\\bwipefs\\b|\\bdd\\s+if=.*of=/dev/)",
        HIGH,
        t("磁盘级危险操作", "Disk-level dangerous operation"),
        t("磁盘格式化或低级写入操作。", "Disk formatting or low-level write operation."),
    ),
    (
        "(?i)crontab\\s+-.*(?:curl|wget|bash|python)",
        HIGH,
        t("Cron 持久化", "Cron persistence"),
        t("通过 crontab 写入持久化任务。", "Persistent task written via crontab."),
    ),
    (
        "(?i)\\bschtasks(?:\\.exe)?\\b[^\\n]{0,80}/create\\b",
        HIGH,
        t("计划任务持久化", "Scheduled task persistence"),
        t("通过 Windows 计划任务注册持久化执行。", "Registers persistence via Windows scheduled tasks."),
    ),
    (
        "(?i)(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run(?:Once)?",
        HIGH,
        t("注册表自启动持久化", "Registry autorun persistence"),
        t("写入 Windows Run/RunOnce 自启动注册表项。", "Writes to Windows Run/RunOnce autorun registry keys."),
    ),
    (
        "(?i)(?:systemctl\\s+enable|launchctl\\s+load|\\bsc(?:\\.exe)?\\s+create\\b|\\bNew-Service\\b)\\s+",
        WARN,
        t("注册系统服务", "System service registration"),
        t("注册持久化系统服务。", "Persistent system service registered."),
    ),
    (
        "(?i)(?:launchctl\\s+(?:load|bootstrap)|~/Library/LaunchAgents|/Library/LaunchAgents)",
        HIGH,
        t("LaunchAgent 持久化", "LaunchAgent persistence"),
        t("通过 macOS LaunchAgents 注册持久化任务。", "Registers persistence through macOS LaunchAgents."),
    ),
    (
        "(?i)(?:~?/\\.config/systemd/user|systemctl\\s+--user\\s+(?:enable|start))",
        WARN,
        t("用户级 systemd 持久化", "User-level systemd persistence"),
        t("检测到用户级 systemd 单元操作；需结合远程载荷或隐蔽执行上下文判断风险。", "Detected a user-level systemd unit operation; assess it together with remote-payload or covert-execution context."),
    ),
    (
        "(?i)(?:~?/\\.termux/boot|/data/data/com\\.termux/files/home/\\.termux/boot|\\btermux-job-scheduler\\b)",
        HIGH,
        t("Termux 持久化", "Termux persistence"),
        t("通过 Termux 启动脚本或 termux-job-scheduler 注册持久化任务。", "Registers persistence through Termux boot scripts or termux-job-scheduler."),
    ),
    (
        "(?i)\\b(?:mshta|regsvr32|rundll32|certutil|bitsadmin|wmic)(?:\\.exe)?\\b",
        HIGH,
        t("Windows LOLBin 执行链", "Windows LOLBin execution chain"),
        t("检测到常见 Windows LOLBin（系统自带执行器）调用。", "Detected use of common Windows LOLBins (built-in execution helpers)."),
    ),
    ("\\beval\\s*\\(", INFO, t("使用 eval()", "eval() usage"), t("动态代码执行。", "Dynamic code execution.")),
    ("\\bexec\\s*\\(", INFO, t("使用 exec()", "exec() usage"), t("exec() 执行任意代码。", "exec() executes arbitrary code.")),
    (
        "^(?!\\s*#)\\s*\\bsubprocess\\.(?:Popen|call|run|check_output)\\s*\\(",
        INFO,
        t("调用子进程", "Subprocess invocation"),
        t("执行系统子进程。", "System subprocess execution."),
    ),
    (
        "os\\.environ(?:\\.get)?\\s*[\\[(\"\\']+(?!CLAW_|SKILL_|APP_|PATH|HOME|USER|SHELL|TERM)[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)",
        WARN,
        t("读取凭证类环境变量", "Reading credential env var"),
        t("访问疑似凭证类环境变量。", "Accessing suspected credential environment variable."),
    ),
    (
        "(?:~|Path\\.home\\(\\))\\s*/\\s*(?:Documents|Desktop|Downloads|Pictures|Movies|Library)",
        WARN,
        t("访问用户隐私目录", "Accessing user private directory"),
        t("访问系统个人目录。", "Accessing user's personal directory."),
    ),
    (
        "(?i)open\\([\"\\'](?:/etc/passwd|/etc/shadow|~[/\\\\]\\.ssh[/\\\\]|~[/\\\\]\\.aws[/\\\\]credentials|[A-Za-z]:[/\\\\].*System32[/\\\\]config[/\\\\](?:SAM|SYSTEM|SECURITY))",
        HIGH,
        t("访问系统敏感文件", "Accessing sensitive system file"),
        t("读取敏感系统文件。", "Reading sensitive system file."),
    ),
    (
        "(?i)(?:requests|httpx|urllib|aiohttp)\\.(?:get|post|put|delete)\\s*\\(",
        INFO,
        t("外部网络请求", "External network request"),
        t("发起 HTTP 请求，确认目标是否可控。", "HTTP request made; verify target is not user-controlled."),
    ),
    (
        "(?i)(?:open|readFile|readFileSync|cat)\\s*\\(?[^\\n]*(?:\\.npmrc|\\.pypirc|\\.netrc)\\b",
        WARN,
        t("访问包管理器凭证文件", "Accessing package-manager credential file"),
        t("代码尝试访问 .npmrc / .pypirc / .netrc 等凭证文件。", "Code attempts to access .npmrc, .pypirc, .netrc, or similar credential files."),
    ),
    ("(?i)__import__\\s*\\(", WARN, t("动态模块导入", "Dynamic module import"), t("运行时动态导入。", "Runtime dynamic import.")),
    (
        "(?i)importlib\\.import_module\\s*\\([^\\n]*(?:input|user|arg|param|plugin|module)|\\brequire\\s*\\([^\\n]*(?:args|params|input|plugin|module)",
        HIGH,
        t("用户输入控制动态模块加载", "User input controls dynamic module loading"),
        t("动态导入或 require 的模块名可能来自用户输入。", "Dynamic import or require may be controlled by user input."),
    ),
    (
        "(?i)(?:ctypes|cffi)\\.",
        WARN,
        t("调用 C 外部函数", "C FFI invocation"),
        t("使用 ctypes/cffi 调用原生代码。", "Native code called via ctypes/cffi."),
    ),
    (
        "(?i)(?:pickle|marshal|shelve)\\.(?:load|loads)\\s*\\(",
        WARN,
        t("反序列化不可信数据", "Deserialization of untrusted data"),
        t("pickle/marshal 反序列化可执行任意代码。", "pickle/marshal deserialization can execute arbitrary code."),
    ),
    (
        "(?i)(?:yaml\\.(?:load|unsafe_load)\\s*\\()",
        WARN,
        t("不安全的 YAML 加载", "Unsafe YAML loading"),
        t("yaml.load 不指定 Loader 可执行任意代码。", "yaml.load without Loader can execute arbitrary code."),
    ),
    (
        "(?i)(?:compile|exec|eval)\\s*\\(.*(?:request|input|argv|stdin)",
        HIGH,
        t("用户输入直接进入代码执行", "User input passed to code execution"),
        t("用户可控输入直接传入 eval/exec/compile。", "User-controlled input passed directly to eval/exec/compile."),
    ),
    (
        "(?i)(?:os\\.chmod|os\\.chown)\\s*\\(.*(?:/etc/|/var/|\\bWindows\\b|\\bSystem32\\b|\\bProgram.Files\\b)",
        WARN,
        t("修改系统目录权限", "System directory permission change"),
        t("修改系统关键目录的权限。", "Modifying permissions of critical system directories."),
    ),
    (
        "(?i)(?:shutil\\.rmtree|os\\.removedirs)\\s*\\(.*(?:/home|/root|/etc|/var|\\bWindows\\b|\\bSystem32\\b|\\bProgram.Files\\b)",
        HIGH,
        t("递归删除系统目录", "Recursive system directory deletion"),
        t("递归删除系统关键目录。", "Recursive deletion of critical system directories."),
    ),
    (
        "(?i)socket\\.(?:bind|listen)\\s*\\(",
        WARN,
        t("创建网络服务端", "Network server creation"),
        t("skill 创建监听 socket。", "Skill creates a listening socket."),
    ),
    (
        "(?i)(?:atob|Buffer\\.from)\\s*\\([\"\\'][A-Za-z0-9+/=]{40,}",
        WARN,
        t("Base64 解码长字符串", "Base64 decoding long string"),
        t("解码可能包含隐藏指令的 base64。", "Decoding base64 that may contain hidden instructions."),
    ),
    (
        "(?i)String\\.fromCharCode\\s*\\(\\s*\\d+\\s*(?:,\\s*\\d+\\s*){5,}",
        WARN,
        t("fromCharCode 字符串构造", "fromCharCode string construction"),
        t("用 charCode 构造字符串可能隐藏指令。", "String built via charCode may hide instructions."),
    ),
    (
        "[\\u200b\\u200c\\u200d\\ufeff\\u2060]{2,}",
        HIGH,
        t("零宽字符序列", "Zero-width character sequence"),
        t("包含零宽字符，可能隐藏注入内容。", "Contains zero-width chars that may hide injected content."),
    ),
    (
        "(?i)(?:tool_call|function_call|tool_use).*(?:override|replace|shadow)",
        HIGH,
        t("工具覆盖意图", "Tool override intent"),
        t("代码中出现工具覆盖关键词。", "Tool override keywords found in code."),
    ),
    (
        "(?i)(?:mcp|server).*(?:proxy|forward|redirect).*(?:all|every)",
        HIGH,
        t("MCP 流量劫持意图", "MCP traffic hijacking intent"),
        t("可能劫持 MCP 通信。", "May hijack MCP communication."),
    ),
    (
        "(?i)(?:fetch|axios|request)\\s*\\([\"\\']https?://(?!localhost|127\\.)",
        INFO,
        t("向外部 URL 发送请求", "Request to external URL"),
        t("向非本地 URL 发起请求。", "Request to non-local URL."),
    ),
    (
        "(?i)\\bssh\\b[^\\n]{0,80}\\s-R\\s|\\bngrok\\b|\\bcloudflared\\b[^\\n]{0,40}\\btunnel\\b|\\bfrpc\\b",
        HIGH,
        t("外联隧道/反向代理", "Outbound tunnel or reverse proxy"),
        t("检测到反向隧道或外联代理工具，可能建立隐蔽通信通道。", "Detected a reverse tunnel or outbound proxy tool that may create a covert communication channel."),
    ),
    (
        "(?i)\\b(?:npx|uvx|pipx\\s+run|npm\\s+exec)\\b|\\bpip\\s+install\\s+git\\+https?://",
        INFO,
        t("运行时拉取外部依赖", "Runtime external dependency fetch"),
        t("运行时通过远程源拉取并执行外部依赖，存在供应链风险。", "Fetches and executes external dependencies at runtime, creating supply-chain risk."),
    ),
    (
        "(?i)(?:dns|nslookup|dig)\\s+.*\\$",
        HIGH,
        t("DNS 外传 (DNS exfiltration)", "DNS exfiltration"),
        t("通过 DNS 查询外传数据。", "Data exfiltration via DNS queries."),
    ),
    (
        "(?i)webhook[s]?\\s*[=:]\\s*[\"\\']https?://",
        WARN,
        t("配置了外部 Webhook", "External webhook configured"),
        t("数据可能通过 webhook 外传。", "Data may be exfiltrated via webhook."),
    ),
    (
        "(?i)\\bos\\.system\\s*\\(",
        INFO,
        t("调用 os.system()", "os.system() invocation"),
        t("通过 os.system 执行 shell 命令。", "Shell command executed via os.system."),
    ),
    (
        "(?i)\\b(?:child_process\\.(?:exec|execSync|spawn|spawnSync|execFile|fork)|\\brequire\\s*\\([\"\\']child_process[\"\\']\\))",
        INFO,
        t("调用 Node child_process", "Node child_process invocation"),
        t("通过 child_process 执行系统命令。", "System command executed via child_process."),
    ),
    (
        "(?i)powershell(?:\\.exe)?\\s+[^\\n]*-(?:EncodedCommand|enc|ec)\\b",
        HIGH,
        t("PowerShell 编码命令", "PowerShell encoded command"),
        t("使用 -EncodedCommand 执行 base64 编码的 PowerShell 命令，常用于混淆。", "Executes base64-encoded PowerShell via -EncodedCommand, commonly used for obfuscation."),
    ),
    (
        "(?i)\\breg(?:\\.exe)?\\s+add\\b",
        HIGH,
        t("写入 Windows 注册表", "Windows registry write"),
        t("通过 reg add 写入注册表，可能用于持久化或配置篡改。", "Writes to registry via reg add; may be used for persistence or config tampering."),
    ),
    (
        "(?:chr\\s*\\(\\s*\\d+\\s*\\)\\s*[+.]?\\s*){5,}",
        WARN,
        t("chr() 字符拼接（疑似混淆）", "chr() character concatenation (suspected obfuscation)"),
        t("使用多次 chr() 调用拼接字符串，可能隐藏恶意指令。", "Multiple chr() calls concatenating a string may hide malicious instructions."),
    ),
    # ── Wallet / mnemonic handling (BIP39, derivation paths, drainers) ──
    (
        r"(?i)(?:from\s+bip_utils|from\s+mnemonic\b|import\s+mnemonic\b|require\s*\(\s*['\"]bip39['\"]|from\s+eth_account(?:\.hdaccount)?|from\s+@scure/bip39\b|from\s+ethers(?:/wallet)?)",
        HIGH,
        t("引用钱包助记词库", "Imports a wallet mnemonic library"),
        t("代码引用 BIP39/HD 钱包库，处理可能涉及助记词或私钥。", "Code imports a BIP39 / HD-wallet library; likely handles mnemonics or private keys."),
    ),
    (
        r"(?i)\b(?:seed[_]?phrase|recovery[_]?phrase|mnemonic[_]?(?:words|phrase|seed)?|wallet[_]?seed)\s*[=:]",
        HIGH,
        t("代码处理钱包助记词", "Code handles wallet mnemonic"),
        t("出现 seed_phrase / recovery_phrase / mnemonic 等变量赋值，存在助记词泄漏风险。", "Variables like seed_phrase / recovery_phrase / mnemonic suggest mnemonic handling and potential leakage."),
    ),
    (
        r"\bm/44'?/(?:60|0|501|118|3)'?/\d+'?/\d+(?:'?/\d+)?",
        HIGH,
        t("BIP44 派生路径", "BIP44 derivation path"),
        t("出现常见 BIP44 派生路径（ETH/BTC/SOL 等），通常意味着私钥派生。", "Detected common BIP44 derivation path (ETH/BTC/SOL etc.); typically indicates private key derivation."),
    ),
    (
        r"(?i)\beth_sendTransaction\b[^\n]{0,200}[\"\']?to[\"\']?\s*[:=]\s*[\"\']0x[0-9a-fA-F]{40}[\"\']",
        CRIT,
        t("可能的钱包提币逻辑", "Potential wallet drain logic"),
        t("eth_sendTransaction 的目的地址硬编码，可能是提币 (drain) 攻击。", "eth_sendTransaction with a hardcoded destination address may indicate a drain attack."),
    ),
]

# Curated from Track B after reviewing both malicious and near-miss examples.
# These are narrow, high-intent primitives; benchmark-specific verdict and
# fixture-downweighting logic deliberately stays out of the main product.
CURATED_SKILL_RULES: List[SkillPatternRule] = [
    SkillPatternRule(
        "SKL-EXFIL-001",
        r"(?i)(?:curl\b[^\n]*(?:--data(?:-binary|-raw)?|--upload-file|-F|-T|--form)\b[^\n]*@?[^\n]*|wget\b[^\n]*(?:--post-file|--body-file)\b[^\n]*)(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.netrc|\.npmrc|\.pypirc|\.env\b|/etc/(?:passwd|shadow))",
        CRIT,
        t("敏感文件外传 (curl/wget 上传)", "Sensitive-file exfiltration (curl/wget upload)"),
        t("将密钥、凭证或环境文件直接上传到外部端点。", "Uploads a key, credential, or environment file directly to an external endpoint."),
        "EXFILTRATION",
    ),
    SkillPatternRule(
        "SKL-EXEC-001",
        r"(?i)(?:iex|Invoke-Expression)\s*\(\s*(?:(?:\(\s*)?(?:New-Object\s+Net\.WebClient|[^\n]*DownloadString)|(?:iwr|Invoke-WebRequest)\b)",
        CRIT,
        t("下载即执行 (PowerShell 函数式)", "Download-and-execute (PowerShell call form)"),
        t("PowerShell 通过 IEX/Invoke-Expression 直接执行远程下载内容。", "PowerShell executes remotely downloaded content through IEX/Invoke-Expression."),
        "EXECUTION",
    ),
    SkillPatternRule(
        "SKL-TUNNEL-001",
        r"(?i)(?:\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s+(?:/bin/(?:ba)?sh|cmd(?:\.exe)?)|\bsocat\b[^\n]*(?:EXEC|SYSTEM):[^\n]*(?:/bin/(?:ba)?sh|cmd(?:\.exe)?))",
        CRIT,
        t("反弹/绑定 Shell 执行链", "Reverse/bind shell execution chain"),
        t("网络工具把连接直接绑定到交互式 shell。", "A networking tool binds a connection directly to an interactive shell."),
        "TUNNEL",
    ),
    SkillPatternRule(
        "SKL-PRIVESC-001",
        r"(?i)(?:>>?\s*|tee\s+(?:-a\s+)?)/etc/sudoers(?:\.d(?:/[^\s]+)?)?\b",
        CRIT,
        t("写入 sudoers 提权", "Writes to sudoers for privilege escalation"),
        t("向 sudoers 或 sudoers.d 写入规则，可授予免密 root 权限。", "Writes a sudoers rule that can grant passwordless root access."),
        "PRIVESC",
    ),
    SkillPatternRule(
        "SKL-PERSIST-001",
        r"(?i)>>\s*(?:~|\$HOME|/root|/home/[^\s/]+)?/?\.ssh/authorized_keys\b",
        CRIT,
        t("SSH 后门 (写入 authorized_keys)", "SSH backdoor (authorized_keys write)"),
        t("向 authorized_keys 追加密钥，植入持久化远程访问。", "Appends a key to authorized_keys, planting persistent remote access."),
        "PERSISTENCE",
    ),
    SkillPatternRule(
        "SKL-PERSIST-002",
        r"(?i)(?:>>?\s*|tee\s+(?:-a\s+)?)/etc/ld\.so\.preload\b",
        CRIT,
        t("写入 ld.so.preload 持久化", "Writes ld.so.preload for persistence"),
        t("注入全局 LD_PRELOAD，使后续进程加载攻击者代码。", "Injects a global LD_PRELOAD so later processes load attacker code."),
        "PERSISTENCE",
    ),
    SkillPatternRule(
        "SKL-PRIVESC-002",
        r"(?i)echo\s+[^\n]*:0:0:[^\n]*>>?\s*/etc/passwd\b",
        HIGH,
        t("向 /etc/passwd 添加 UID 0 账户", "Adds a UID-0 account to /etc/passwd"),
        t("向账户数据库追加 root 等价后门账户。", "Appends a root-equivalent backdoor account to the account database."),
        "PRIVESC",
    ),
    SkillPatternRule(
        "SKL-RCE-001",
        r"(?i)(?:exec|eval)\s*\(\s*(?:os\.environ(?:\.get)?\s*[\[(]|process\.env\.)",
        CRIT,
        t("执行环境变量中的代码", "Executes code from an environment variable"),
        t("把环境变量内容直接传入 exec/eval，形成隐蔽载荷执行。", "Passes environment content directly to exec/eval, enabling covert payload execution."),
        "RCE",
    ),
    SkillPatternRule(
        "SKL-DESTRUCT-001",
        r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        CRIT,
        t("Fork 炸弹", "Fork bomb"),
        t("快速耗尽系统进程资源并导致拒绝服务。", "Rapidly exhausts process resources and causes denial of service."),
        "DESTRUCTION",
    ),
    SkillPatternRule(
        "SKL-RCE-002",
        r"(?i)(?:jsonpickle\.decode\s*\(\s*(?:req(?:uest)?|user|input|body|payload|data|(?:open|Path\s*\([^)]*\)\.open)\s*\([^)]*\)\s*\.read\s*\(\s*\))|[A-Za-z_$][\w$]*\.unserialize\s*\(\s*(?:req(?:uest)?|user|input|body|payload|data)|\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|_\$\$ND_FUNC\$\$_)",
        HIGH,
        t("不安全反序列化 (jsonpickle/node/PHP)", "Unsafe deserialization (jsonpickle/node/PHP)"),
        t("对不可信输入进行可执行反序列化，可能导致远程代码执行。", "Performs executable deserialization on untrusted input, which may lead to remote code execution."),
        "RCE",
    ),
    SkillPatternRule(
        "SKL-RCE-003",
        r"(?i)(?:ObjectInputStream\s*\([^\n]*\)\.readObject|XMLDecoder\s*\(|BinaryFormatter\s*\(\s*\)\.Deserialize)",
        HIGH,
        t("不安全反序列化 (Java/.NET)", "Unsafe deserialization (Java/.NET)"),
        t("Java/.NET 反序列化入口可能对不可信数据执行代码。", "A Java/.NET deserialization sink may execute code from untrusted data."),
        "RCE",
    ),
]

# Pattern categories — surfaced on every skill finding via Finding.metadata
# so reporters can group / filter by attack class. Each entry is matched
# (in order) against the pattern's bilingual title+detail text.  More specific
# rules come first; the first match wins.  Anything unmatched → "OTHER".
_PATTERN_CATEGORY_RULES: List[Tuple[str, str]] = [
    ("OBFUSCATION", r"零宽|zero[-\s]?width|fromCharCode|EncodedCommand|嵌套混淆|nested shell|chr\(\)|base64 解码|Base64 decoding|混淆|Unicode escape|Obfuscated payload"),
    ("WALLET", r"BIP\d{2}|mnemonic|seed phrase|助记词|钱包|wallet|derivation path|派生路径|drain|提币"),
    ("MINING", r"挖矿|cryptominer|xmrig|monero|coinhive|stratum"),
    ("TUNNEL", r"ngrok|cloudflared|frpc|tunnel|隧道|reverse shell|反弹\s*shell|Reverse\s*shell"),
    ("PERSISTENCE", r"cron|crontab|schtasks|RunOnce|LaunchAgent|systemd|persistence|持久化|Termux|计划任务|service registration|系统服务"),
    ("DESTRUCTION", r"rm -rf|rmtree|removedirs|批量删除|系统目录|system director|recursive deletion|Recursive.*deletion|Disk-level|mkfs|低级写入|permission change|chmod|chown|icacls|Dangerous permission"),
    ("SUPPLY_CHAIN", r"下载即执行|Download-and-execute|npx\b|uvx\b|pipx|pip\s+install\s+git|外部依赖|External dependency|runtime.*fetch"),
    ("CREDENTIAL", r"凭据|凭证|credential|TOKEN|API\s*Key|SECRET|/etc/passwd|/etc/shadow|\.ssh|\.aws|SAM|\.npmrc|\.pypirc|\.netrc|包管理器凭证"),
    ("EXFILTRATION", r"DNS exfiltration|webhook|外传|exfil"),
    ("INJECTION", r"prompt injection|jailbreak|role hijacking|越狱|提示词注入|角色劫持|system prompt|系统提示词|工具覆盖|tool override|hijack|tool invocation|invoke.*tool|env var.*(?:being )?set|export.*injection"),
    ("REGISTRY", r"reg add|registry write|注册表|HKLM|HKCU"),
    ("RCE", r"\beval\b|\bexec\b|importlib|动态模块|module loading|FFI|ctypes|deserializ|反序列化|YAML load|yaml\.load|Dynamic module|dynamic import|untrusted data"),
    ("LOLBIN", r"LOLBin|mshta|regsvr32|rundll32|certutil|bitsadmin|wmic"),
    ("MCP", r"\bMCP\b"),
    ("FILE_ACCESS", r"敏感文件|sensitive (?:system )?file|user private|用户隐私"),
    ("NETWORK", r"socket\.|listen|网络服务端|external URL|外部 URL|Network server|external network|外部网络"),
    ("EXECUTION", r"subprocess|child_process|os\.system|shell command|powershell"),
]
_COMPILED_PATTERN_CATEGORY_RULES = [
    (cat, re.compile(rule, re.I)) for cat, rule in _PATTERN_CATEGORY_RULES
]


def _classify_pattern(title: str, detail: str = "") -> str:
    text = f"{title}\n{detail}"
    for cat, regex in _COMPILED_PATTERN_CATEGORY_RULES:
        if regex.search(text):
            return cat
    return "OTHER"


_COMPILED_MALICIOUS_PATTERNS = [
    (
        re.compile(rule.pattern),
        rule.level,
        rule.title,
        rule.detail,
        rule.category,
        rule.rule_id,
        rule.confidence,
    )
    for rule in CURATED_SKILL_RULES
] + [
    (
        re.compile(p),
        level,
        title,
        detail,
        _classify_pattern(title, detail),
        "",
        "medium",
    )
    for p, level, title, detail in MALICIOUS_PATTERNS
]


_COMMENT_RE = re.compile(r"^\s*(?:#|//|/?\*|<!--)")


def _is_comment_line(line: str) -> bool:
    """Return True if the line looks like a code comment."""
    return bool(_COMMENT_RE.match(line))


# Categories that should still fire on lines that are purely inside a string
# literal (e.g. docstrings, triple-quoted comment blocks). Code-focused
# categories like RCE/EXECUTION/NETWORK are suppressed there because the
# string body is documentation, not executable code — but prompt injection,
# credentials, obfuscation, and mnemonic content embedded in a string ARE
# still meaningful threats and continue to fire.
_STRING_SAFE_CATEGORIES = frozenset({
    "INJECTION",
    "OBFUSCATION",
    "CREDENTIAL",
    "WALLET",
})


def _python_docstring_line_set(content: str) -> Set[int]:
    """Return 1-based line numbers that fall inside a Python bare-string
    expression (typically a module / class / function docstring or a
    triple-quoted comment block).

    Only standalone string-expression statements are masked. Embedded string
    literals inside other expressions — e.g. ``eval("…")`` or ``f"{x}"`` on
    the same line as a call — are intentionally NOT masked, so executable
    code on those lines is still scanned normally.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return set()

    doc_lines: Set[int] = set()
    for node in ast.walk(tree):
        for attr in ("body", "orelse", "finalbody"):
            body = getattr(node, attr, None)
            if not isinstance(body, list):
                continue
            for stmt in body:
                if (
                    isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                ):
                    start = stmt.lineno
                    end = getattr(stmt, "end_lineno", None) or start
                    doc_lines.update(range(start, end + 1))
    return doc_lines


def _skill_scan_diagnostic(title: str, detail: str, location: Path) -> Finding:
    return Finding(
        "internal",
        WARN,
        title,
        detail,
        str(location),
        remediation=t(
            "缩小或检查该 Skill 包后重新扫描；不要把不完整结果视为通过。",
            "Inspect or reduce the Skill package and scan again; do not treat an incomplete result as a pass.",
        ),
        metadata={"scan_status": "error", "component": "skill_walk"},
    )


def _discover_skill_text_files(
    skill_path: Path,
    findings: List[Finding],
) -> List[Path]:
    """Discover bounded, deterministic text candidates without following links."""
    if skill_path.is_symlink():
        try:
            resolved = skill_path.resolve(strict=True)
            resolved.relative_to(skill_path.parent.resolve())
        except ValueError:
            findings.append(
                Finding(
                    "skill",
                    HIGH,
                    t(
                        "[FILE_ACCESS] Skill 根符号链接逃逸所在目录",
                        "[FILE_ACCESS] Skill root symlink escapes its directory",
                    ),
                    t(
                        "Skill 入口本身是指向所在目录之外的符号链接，安装或执行时可能访问未声明的宿主文件。",
                        "The Skill entry itself is a symlink outside its containing directory and may access undeclared host files when installed or run.",
                    ),
                    str(skill_path),
                    remediation=t(
                        "移除外部符号链接，并对真实包路径单独执行扫描。",
                        "Remove the external symlink and scan the real package path explicitly.",
                    ),
                    metadata={
                        "category": "FILE_ACCESS",
                        "file": str(skill_path),
                        "rule_id": "SKL-FILE-001",
                        "confidence": "high",
                    },
                )
            )
        except OSError:
            pass
        findings.append(
            _skill_scan_diagnostic(
                t(
                    "Skill 根符号链接未被跟随",
                    "Skill root symlink was not followed",
                ),
                t(
                    "为避免越界读取，扫描器不会跟随作为包入口的符号链接。",
                    "The scanner does not follow a symlink used as the package entry, preventing out-of-scope reads.",
                ),
                skill_path,
            )
        )
        return []
    if skill_path.is_file():
        return [skill_path]

    root = skill_path.resolve()
    stack = [skill_path]
    files: List[Path] = []
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name.lower())
        except OSError as exc:
            findings.append(
                _skill_scan_diagnostic(
                    t("Skill 目录无法读取", "Skill directory could not be read"),
                    str(exc)[:300],
                    directory,
                )
            )
            continue

        child_dirs: List[Path] = []
        for entry in entries:
            if entry.is_symlink():
                try:
                    entry.resolve().relative_to(root)
                except (OSError, ValueError):
                    findings.append(
                        Finding(
                            "skill",
                            HIGH,
                            t(
                                "[FILE_ACCESS] Skill 符号链接逃逸包目录",
                                "[FILE_ACCESS] Skill symlink escapes its package",
                            ),
                            t(
                                "符号链接指向 Skill 根目录之外，安装或执行时可能访问未声明的宿主文件。",
                                "A symlink points outside the Skill root and may access undeclared host files when installed or run.",
                            ),
                            str(entry),
                            remediation=t(
                                "移除外部符号链接并把所需内容显式纳入包内。",
                                "Remove the external symlink and include required content explicitly in the package.",
                            ),
                            metadata={"category": "FILE_ACCESS", "file": str(entry)},
                        )
                    )
                # Never follow links, including links that currently resolve
                # inside the package; the real file will be scanned normally.
                continue
            try:
                is_dir = entry.is_dir()
                is_file = entry.is_file()
            except OSError as exc:
                findings.append(
                    _skill_scan_diagnostic(
                        t("Skill 路径无法检查", "Skill path could not be inspected"),
                        str(exc)[:300],
                        entry,
                    )
                )
                continue
            if is_dir:
                if entry.name not in _SKILL_PRUNED_DIRS:
                    child_dirs.append(entry)
                continue
            # Extensions are only hints.  A text script can be deliberately
            # named ``payload.png`` and still be executed by an interpreter;
            # actual binary content is rejected by bounded magic/NUL sniffing.
            if not is_file:
                continue
            if len(files) >= _SKILL_MAX_FILES:
                findings.append(
                    _skill_scan_diagnostic(
                        t("Skill 文件数量超过扫描上限", "Skill file count exceeds scan limit"),
                        t(
                            f"最多扫描 {_SKILL_MAX_FILES} 个文本文件。",
                            f"At most {_SKILL_MAX_FILES} text files are scanned.",
                        ),
                        skill_path,
                    )
                )
                return files
            files.append(entry)
        stack.extend(reversed(child_dirs))
    return files


def _read_skill_text_prefix(
    path: Path,
    limit: int,
) -> Tuple[Optional[str], bool, int]:
    """Return decoded prefix, truncation state, and bytes consumed."""
    with path.open("rb") as stream:
        probe = stream.read(min(limit + 1, 8192))
        is_utf16 = probe.startswith((b"\xff\xfe", b"\xfe\xff"))
        is_binary = (
            not is_utf16
            and (
                any(probe.startswith(magic) for magic in _SKILL_BINARY_MAGIC_PREFIXES)
                or b"\x00" in probe
                or (len(probe) >= 265 and probe[257:262] == b"ustar")
                or (len(probe) >= 12 and probe[4:8] == b"ftyp")
            )
        )
        if is_binary:
            return None, False, min(len(probe), limit)
        raw = probe
        if len(raw) < limit + 1:
            raw += stream.read(limit + 1 - len(raw))
    truncated = len(raw) > limit
    raw = raw[:limit]
    if is_utf16:
        return raw.decode("utf-16", errors="ignore"), truncated, len(raw)
    return raw.decode("utf-8-sig", errors="ignore"), truncated, len(raw)


def _skill_line_windows(line: str) -> List[Tuple[str, int]]:
    """Return bounded first/last and risk-anchor windows for one logical line.

    Running every regex over a multi-megabyte minified line can itself become a
    denial-of-service primitive.  Oversized lines are therefore sampled around
    their boundaries and a small number of cheap keyword anchors; the caller
    marks the overall scan incomplete instead of silently claiming full coverage.
    """
    if len(line) <= _SKILL_MAX_LINE_CHARS:
        return [(line, 0)]
    max_start = len(line) - _SKILL_MAX_LINE_CHARS
    starts = {0, max_start}
    first_anchors: List[int] = []
    last_anchors: List[int] = []
    for match in _SKILL_LONG_LINE_ANCHOR_RE.finditer(line):
        position = match.start()
        if len(first_anchors) < 3:
            first_anchors.append(position)
        last_anchors.append(position)
        if len(last_anchors) > 3:
            last_anchors.pop(0)
    for position in [*first_anchors, *last_anchors]:
        starts.add(max(0, min(max_start, position - (_SKILL_MAX_LINE_CHARS // 2))))
    return [
        (line[start : start + _SKILL_MAX_LINE_CHARS], start)
        for start in sorted(starts)
    ]


def _append_capability_graph_findings(
    content: str,
    *,
    location: str,
    skill_name: str,
    findings: List[Finding],
    seen: Set[str],
) -> None:
    """Synthesize evidence-linked attack chains from one logical source."""

    try:
        from .capabilities import analyze_capabilities

        analysis = analyze_capabilities(text=content, location=location)
    except Exception as exc:
        diagnostic = _scanner_error_finding(
            t("Skill 能力图分析", "Skill capability graph analysis"), exc
        )
        diagnostic.location = location
        diagnostic.metadata.update(
            {"scan_status": "error", "component": "capability_graph"}
        )
        findings.append(diagnostic)
        return

    if not analysis.graph.complete:
        findings.append(
            Finding(
                "internal",
                WARN,
                t("Skill 能力图分析不完整", "Skill capability graph analysis incomplete"),
                "; ".join(analysis.graph.diagnostics[:10]),
                location,
                metadata={"scan_status": "error", "component": "capability_graph"},
            )
        )
    for detection in analysis.detections:
        key = f"capability:{detection.rule_id}:{':'.join(detection.event_ids)}"
        if key in seen:
            continue
        seen.add(key)
        evidence_path = [event.to_dict() for event in detection.evidence_path]
        first = detection.evidence_path[0]
        last = detection.evidence_path[-1]
        line = last.line or first.line
        finding_location = f"{location}:{line}" if line else location
        findings.append(
            Finding(
                "capability_graph",
                detection.severity,
                f"[{detection.rule_id}] [{skill_name}] {detection.title}",
                detection.detail,
                finding_location,
                " → ".join(event.evidence[:100] for event in detection.evidence_path)[:300],
                remediation=t(
                    "拆断能力链，限制敏感数据可达性、外部目的地或执行权限。",
                    "Break the capability chain by restricting sensitive reachability, destinations, or execution authority.",
                ),
                metadata={
                    "rule_id": detection.rule_id,
                    "category": "COMPOSITE",
                    "skill": skill_name,
                    "confidence_score": detection.confidence,
                    "evidence_path": evidence_path,
                    **dict(detection.metadata),
                },
            )
        )


def _skill_supply_chain_findings(skill_path: Path) -> List[Finding]:
    """Run structured manifests plus a bounded transitive instruction graph."""

    from .supply_chain import build_instruction_graph, scan_supply_chain

    findings: List[Finding] = []
    if skill_path.is_dir():
        root = skill_path
        supply_target = root
        entries = [
            candidate
            for candidate in (
                root / "SKILL.md",
                root / "AGENTS.md",
                root / "CLAUDE.md",
            )
            if candidate.is_file()
        ]
    else:
        root = skill_path.parent
        structured_names = {
            "SKILL.md",
            "AGENTS.md",
            "CLAUDE.md",
            "package.json",
            "pyproject.toml",
            "requirements.txt",
        }
        supply_target = root if skill_path.name in structured_names else skill_path
        entries = [skill_path] if skill_path.suffix.lower() in {".md", ".txt"} else []

    report = scan_supply_chain(supply_target)
    for issue in report.issues:
        findings.append(
            Finding(
                "supply_chain",
                issue.severity,
                f"[{issue.rule_id}] {issue.title}",
                issue.detail,
                issue.location,
                issue.evidence,
                remediation=t(
                    "固定不可变版本/摘要，并审查安装期脚本与构建后端。",
                    "Pin immutable versions/digests and review install scripts and build backends.",
                ),
                metadata={
                    "rule_id": issue.rule_id,
                    "category": "SUPPLY_CHAIN",
                    "confidence_score": issue.confidence,
                    **dict(issue.metadata),
                },
            )
        )
    if not report.complete:
        findings.append(
            Finding(
                "internal",
                WARN,
                t("供应链清单分析不完整", "Supply-chain inventory incomplete"),
                "; ".join(report.diagnostics[:20]),
                str(supply_target),
                metadata={"scan_status": "error", "component": "supply_chain"},
            )
        )

    if entries:
        expected_hashes: Dict[str, str] = {}
        for candidate in (
            root / ".clawlock-instruction-hashes.json",
            root / ".clawlock" / "instruction-hashes.json",
        ):
            if not candidate.is_file():
                continue
            try:
                value = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    expected_hashes.update(
                        {str(key): str(digest) for key, digest in value.items()}
                    )
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                findings.append(
                    Finding(
                        "internal",
                        WARN,
                        t("外部指令哈希清单无法读取", "Instruction hash manifest could not be read"),
                        str(exc),
                        str(candidate),
                        metadata={
                            "scan_status": "error",
                            "component": "instruction_graph",
                        },
                    )
                )
        graph = build_instruction_graph(
            root,
            entries,
            expected_hashes=expected_hashes,
            remote_loader=None,
        )
        for issue in graph.issues:
            findings.append(
                Finding(
                    "instruction_graph",
                    issue.severity,
                    f"[{issue.rule_id}] {issue.title}",
                    issue.detail,
                    issue.location,
                    issue.evidence,
                    remediation=t(
                        "将指令固定到本地受审内容、SHA-256 或不可变 commit。",
                        "Pin instructions to reviewed local content, SHA-256, or an immutable commit.",
                    ),
                    metadata={
                        "rule_id": issue.rule_id,
                        "category": "EXTERNAL_INSTRUCTIONS",
                        "confidence_score": issue.confidence,
                        **dict(issue.metadata),
                    },
                )
            )
        if not graph.complete:
            findings.append(
                Finding(
                    "internal",
                    WARN,
                    t("传递指令图分析不完整", "Transitive instruction graph incomplete"),
                    "; ".join(graph.diagnostics[:20]),
                    str(root),
                    metadata={
                        "scan_status": "error",
                        "component": "instruction_graph",
                    },
                )
            )
    return findings


def _skill_runtime_security_findings(skill_path: Path) -> List[Finding]:
    """Audit deployment manifests shipped with a Skill without executing them."""

    from .runtime_security import audit_runtime_security

    if skill_path.is_file():
        name = skill_path.name.lower()
        if not (
            name.startswith(("dockerfile", "containerfile"))
            or name in {
                "compose.yaml",
                "compose.yml",
                "docker-compose.yaml",
                "docker-compose.yml",
            }
        ):
            return []
    report = audit_runtime_security(skill_path)
    findings: List[Finding] = []
    for issue in report.issues:
        kwargs = issue.as_finding_kwargs()
        kwargs["title"] = f"[{issue.rule_id}] {issue.title}"
        findings.append(Finding(**kwargs))
    return findings


def _skill_dataflow_findings(skill_path: Path) -> List[Finding]:
    """Run the shared project-level Python source-to-sink engine once per Skill."""

    from .dataflow import analyze_project, analyze_python_file
    from .dataflow_reporting import findings_from_dataflow

    if skill_path.is_file():
        if skill_path.suffix.lower() != ".py":
            return []
        result = analyze_python_file(skill_path)
        root = skill_path.parent
    else:
        result = analyze_project(skill_path)
        root = skill_path
    return findings_from_dataflow(result, scanner="skill_dataflow", root=root)


def _scan_virtual_skill_text(
    item: Any,
    *,
    skill_name: str,
    findings: List[Finding],
    seen: Set[str],
) -> None:
    """Run the ordinary Skill rule registry over safely recovered content.

    ``item`` is a :class:`artifacts.VirtualText`.  It is kept duck-typed here
    to avoid loading the artifact subsystem during lightweight module imports.
    Archive members and bytecode are never written to disk or executed.
    """

    virtual_path = str(item.path)
    content = str(item.text)
    item_kind = str(item.kind)
    source_metadata = dict(getattr(item, "metadata", {}) or {})
    py_doc_lines: Set[int] = (
        _python_docstring_line_set(content)
        if virtual_path.split("#", 1)[0].lower().endswith(".py")
        else set()
    )
    oversized_line_reported = False
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        if len(raw_line) > _SKILL_MAX_LINE_CHARS and not oversized_line_reported:
            findings.append(
                Finding(
                    "internal",
                    WARN,
                    t(
                        "制品内超长单行仅完成稀疏窗口扫描",
                        "Oversized artifact line received sparse-window scanning",
                    ),
                    t(
                        f"{virtual_path} 第 {line_number} 行超过 {_SKILL_MAX_LINE_CHARS} 个字符。",
                        f"Line {line_number} in {virtual_path} exceeds {_SKILL_MAX_LINE_CHARS} characters.",
                    ),
                    f"{virtual_path}:{line_number}",
                    metadata={
                        "scan_status": "error",
                        "component": "artifact_text_scan",
                        "artifact_kind": item_kind,
                    },
                )
            )
            oversized_line_reported = True
        is_comment = _is_comment_line(raw_line)
        in_py_docstring = line_number in py_doc_lines
        for line, column_offset in _skill_line_windows(raw_line):
            unwrapped = _unwrap_shell_commands(line)
            candidates = [(line, False), *((value, True) for value in unwrapped)]
            is_deobfuscated = False
            for candidate, was_deobfuscated in candidates:
                for (
                    compiled_pat,
                    level,
                    title,
                    detail,
                    category,
                    rule_id,
                    confidence,
                ) in _COMPILED_MALICIOUS_PATTERNS:
                    if is_comment and level != CRIT:
                        continue
                    if in_py_docstring and category not in _STRING_SAFE_CATEGORIES:
                        continue
                    match = compiled_pat.search(candidate)
                    if match is None:
                        continue
                    key = (
                        f"artifact:{compiled_pat.pattern}:{virtual_path}:{line_number}"
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    suffix = (
                        t(" (反混淆后发现)", " (found after deobfuscation)")
                        if was_deobfuscated
                        else ""
                    )
                    snippet_start = max(0, match.start() - 40)
                    snippet_end = min(
                        len(candidate), max(match.end() + 80, snippet_start + 120)
                    )
                    snippet = " ".join(
                        candidate[snippet_start:snippet_end].strip().splitlines()
                    )[:200]
                    metadata = {
                        "skill": skill_name,
                        "category": category,
                        "file": virtual_path,
                        "line": line_number,
                        "deobfuscated": was_deobfuscated,
                        "rule_id": rule_id,
                        "confidence": confidence,
                        "artifact": True,
                        "artifact_kind": item_kind,
                        **source_metadata,
                    }
                    if not was_deobfuscated:
                        metadata["column"] = column_offset + match.start() + 1
                    findings.append(
                        Finding(
                            "skill",
                            level,
                            f"[{category}] [{skill_name}] {title}{suffix}",
                            detail,
                            f"{virtual_path}:{line_number}",
                            snippet,
                            metadata=metadata,
                        )
                    )
                    if was_deobfuscated:
                        is_deobfuscated = True
            if unwrapped and is_deobfuscated:
                key = f"artifact:__obfuscation__:{virtual_path}:{line_number}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            "skill",
                            WARN,
                            t(
                                f"[OBFUSCATION] [{skill_name}] 制品内 Shell 命令嵌套混淆",
                                f"[OBFUSCATION] [{skill_name}] Nested shell obfuscation inside artifact",
                            ),
                            t(
                                f"检测到 {len(unwrapped)} 层 shell 包装。",
                                f"Detected {len(unwrapped)} layers of shell wrapping.",
                            ),
                            f"{virtual_path}:{line_number}",
                            line.strip()[:120],
                            remediation=t(
                                "审查解包后的实际命令。",
                                "Review the unwrapped command.",
                            ),
                            metadata={
                                "skill": skill_name,
                                "category": "OBFUSCATION",
                                "file": virtual_path,
                                "line": line_number,
                                "artifact": True,
                                "artifact_kind": item_kind,
                                "unwrapped_commands": unwrapped,
                            },
                        )
                    )


def scan_skill(skill_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    skill_name = skill_path.stem if skill_path.is_file() else skill_path.name
    files = _discover_skill_text_files(skill_path, findings)
    seen: set = set()
    total_bytes = 0
    for f in files:
        try:
            relative_name = (
                f.name if skill_path.is_file() else f.relative_to(skill_path).as_posix()
            )
        except ValueError:
            relative_name = f.name
        remaining = _SKILL_MAX_TOTAL_BYTES - total_bytes
        if remaining <= 0:
            findings.append(
                _skill_scan_diagnostic(
                    t("Skill 总读取量超过扫描上限", "Skill total read budget exceeded"),
                    t(
                        f"本次最多读取 {_SKILL_MAX_TOTAL_BYTES // (1024 * 1024)} MiB 文本。",
                        f"This scan reads at most {_SKILL_MAX_TOTAL_BYTES // (1024 * 1024)} MiB of text.",
                    ),
                    skill_path,
                )
            )
            break
        read_limit = min(_SKILL_MAX_FILE_BYTES, remaining)
        try:
            content, truncated, bytes_read = _read_skill_text_prefix(f, read_limit)
        except OSError as exc:
            findings.append(
                _skill_scan_diagnostic(
                    t("Skill 文件无法读取", "Skill file could not be read"),
                    str(exc)[:300],
                    f,
                )
            )
            continue
        total_bytes += bytes_read
        if content is None:
            continue
        if truncated:
            findings.append(
                _skill_scan_diagnostic(
                    t("Skill 文件仅完成前缀扫描", "Skill file was only partially scanned"),
                    t(
                        f"单文件最多读取 {read_limit // 1024} KiB，剩余内容未检查。",
                        f"Only the first {read_limit // 1024} KiB were read; remaining content was not inspected.",
                    ),
                    f,
                )
            )
        py_doc_lines: Set[int] = (
            _python_docstring_line_set(content) if f.suffix == ".py" else set()
        )
        oversized_line_reported = False
        for i, raw_line in enumerate(content.splitlines(), 1):
            if len(raw_line) > _SKILL_MAX_LINE_CHARS and not oversized_line_reported:
                findings.append(
                    _skill_scan_diagnostic(
                        t(
                            "Skill 超长单行仅完成稀疏窗口扫描",
                            "Skill oversized line received sparse-window scanning",
                        ),
                        t(
                            f"第 {i} 行超过 {_SKILL_MAX_LINE_CHARS} 个字符；已检查首尾与风险关键词附近窗口，其余内容未逐字符执行完整规则集。",
                            f"Line {i} exceeds {_SKILL_MAX_LINE_CHARS} characters; boundary and risk-keyword windows were checked, but the remaining content did not receive the full rule set.",
                        ),
                        f,
                    )
                )
                oversized_line_reported = True
            is_comment = _is_comment_line(raw_line)
            in_py_docstring = i in py_doc_lines
            for line, column_offset in _skill_line_windows(raw_line):
                # Build candidate windows: original + any unwrapped shell payloads.
                unwrapped = _unwrap_shell_commands(line)
                candidates = [(line, False), *((item, True) for item in unwrapped)]
                is_deobfuscated = False
                for candidate, was_deobfuscated in candidates:
                    for (
                        compiled_pat,
                        level,
                        title,
                        detail,
                        category,
                        rule_id,
                        confidence,
                    ) in _COMPILED_MALICIOUS_PATTERNS:
                        # Skip non-CRIT patterns on comment lines to reduce false positives.
                        if is_comment and level != CRIT:
                            continue
                        # Skip code-focused categories inside Python docstrings —
                        # they're documentation, not executable code. Threats that
                        # CAN actually live in a string body (prompt injection,
                        # credentials, obfuscation, mnemonics) still fire.
                        if in_py_docstring and category not in _STRING_SAFE_CATEGORIES:
                            continue
                        match = compiled_pat.search(candidate)
                        if match is None:
                            continue
                        key = f"{compiled_pat.pattern}:{f}:{i}"
                        if key in seen:
                            continue
                        seen.add(key)
                        suffix = (
                            t(" (反混淆后发现)", " (found after deobfuscation)")
                            if was_deobfuscated
                            else ""
                        )
                        snippet_start = max(0, match.start() - 40)
                        snippet_end = min(
                            len(candidate), max(match.end() + 80, snippet_start + 120)
                        )
                        snippet = " ".join(
                            candidate[snippet_start:snippet_end].strip().splitlines()
                        )[:200]
                        metadata = {
                            "skill": skill_name,
                            "category": category,
                            "file": str(f),
                            "line": i,
                            "deobfuscated": was_deobfuscated,
                            "rule_id": rule_id,
                            "confidence": confidence,
                        }
                        if not was_deobfuscated:
                            metadata["column"] = column_offset + match.start() + 1
                        findings.append(
                            Finding(
                                "skill",
                                level,
                                f"[{category}] [{skill_name}] {title}{suffix}",
                                detail,
                                f"{relative_name}:{i}",
                                snippet,
                                metadata=metadata,
                            )
                        )
                        if was_deobfuscated:
                            is_deobfuscated = True
                # If shell wrapping was detected and inner payloads were found,
                # emit an additional info-level finding about the obfuscation.
                if unwrapped and is_deobfuscated:
                    ob_key = f"__obfuscation__:{f}:{i}"
                    if ob_key not in seen:
                        seen.add(ob_key)
                        findings.append(
                            Finding(
                                "skill",
                                WARN,
                                t(
                                    f"[OBFUSCATION] [{skill_name}] Shell 命令嵌套混淆",
                                    f"[OBFUSCATION] [{skill_name}] Nested shell command obfuscation",
                                ),
                                t(
                                    f"检测到 {len(unwrapped)} 层 shell 包装，可能试图绕过静态检测。",
                                    f"Detected {len(unwrapped)} layers of shell wrapping; may attempt to bypass static analysis.",
                                ),
                                f"{relative_name}:{i}",
                                line.strip()[:120],
                                remediation=t(
                                    "审查解包后的实际命令。",
                                    "Review the unwrapped commands.",
                                ),
                                metadata={
                                    "skill": skill_name,
                                    "category": "OBFUSCATION",
                                    "file": str(f),
                                    "line": i,
                                    "unwrapped_commands": unwrapped,
                                },
                            )
                        )

        _append_capability_graph_findings(
            content,
            location=relative_name,
            skill_name=skill_name,
            findings=findings,
            seen=seen,
        )

    # The ordinary walker deliberately avoids binary content.  Run the
    # bounded artifact layer after it, then feed only virtual/recovered text
    # back through the exact same Skill rule registry.  Real text files have
    # already been scanned above and are skipped here to prevent duplicates.
    try:
        from .artifacts import inspect_artifacts

        artifact_result = inspect_artifacts(skill_path)
        ledger_rows = [
            {
                "path": entry.path,
                "status": entry.status,
                "kind": entry.kind,
                "reason": entry.reason,
                "critical": entry.critical,
                "metadata": entry.metadata,
            }
            for entry in artifact_result.ledger
        ]
        status_counts: Dict[str, int] = {}
        for row in ledger_rows:
            status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        ledger_digest = hashlib.sha256(
            json.dumps(
                ledger_rows,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        findings.append(
            Finding(
                "artifact_ledger",
                INFO,
                t(
                    f"制品检查清单：{artifact_result.status} / {len(ledger_rows)} 项",
                    f"Artifact inspection ledger: {artifact_result.status} / {len(ledger_rows)} entries",
                ),
                t(
                    f"扫描 {artifact_result.members_seen} 个对象，展开 {artifact_result.expanded_bytes} 字节。",
                    f"Inspected {artifact_result.members_seen} objects and expanded {artifact_result.expanded_bytes} bytes.",
                ),
                str(skill_path),
                metadata={
                    "component": "artifact_inspection",
                    "inspection_status": artifact_result.status,
                    "complete": artifact_result.complete,
                    "status_counts": status_counts,
                    "ledger_sha256": ledger_digest,
                    "ledger": ledger_rows,
                },
            )
        )
        findings.extend(
            Finding(**finding_kwargs)
            for finding_kwargs in artifact_result.as_finding_kwargs()
        )
        for item in artifact_result.texts:
            if (
                "!" not in item.path
                and not item.kind.startswith("pyc-")
                and item.kind != "xml-text"
            ):
                continue
            _scan_virtual_skill_text(
                item,
                skill_name=skill_name,
                findings=findings,
                seen=seen,
            )
            _append_capability_graph_findings(
                item.text,
                location=item.path,
                skill_name=skill_name,
                findings=findings,
                seen=seen,
            )
    except Exception as exc:
        diagnostic = _scanner_error_finding(
            t("Skill 制品检查", "Skill artifact inspection"), exc
        )
        diagnostic.location = str(skill_path)
        diagnostic.metadata.update(
            {"scan_status": "error", "component": "artifact_inspection"}
        )
        findings.append(diagnostic)

    try:
        findings.extend(_skill_supply_chain_findings(skill_path))
    except Exception as exc:
        diagnostic = _scanner_error_finding(
            t("Skill 供应链结构化分析", "Structured Skill supply-chain analysis"),
            exc,
        )
        diagnostic.location = str(skill_path)
        diagnostic.metadata.update(
            {"scan_status": "error", "component": "supply_chain"}
        )
        findings.append(diagnostic)

    try:
        findings.extend(_skill_runtime_security_findings(skill_path))
    except Exception as exc:
        diagnostic = _scanner_error_finding(
            t("Skill 运行时部署审计", "Skill runtime deployment audit"), exc
        )
        diagnostic.location = str(skill_path)
        diagnostic.metadata.update(
            {"scan_status": "error", "component": "runtime_security"}
        )
        findings.append(diagnostic)

    try:
        findings.extend(_skill_dataflow_findings(skill_path))
    except Exception as exc:
        diagnostic = _scanner_error_finding(
            t("Skill 项目级数据流分析", "Skill project-level data-flow analysis"), exc
        )
        diagnostic.location = str(skill_path)
        diagnostic.metadata.update(
            {"scan_status": "error", "component": "dataflow_v2"}
        )
        findings.append(diagnostic)

    try:
        from .capability_reporting import correlate_findings

        findings.extend(correlate_findings(findings, subject=str(skill_path)))
    except Exception as exc:
        diagnostic = _scanner_error_finding(
            t("Skill 聚合能力链分析", "Skill aggregate capability-chain analysis"), exc
        )
        diagnostic.location = str(skill_path)
        diagnostic.metadata.update(
            {"scan_status": "error", "component": "capability_graph"}
        )
        findings.append(diagnostic)
    return findings


def scan_all_skills(
    adapter: AdapterSpec, extra_dir: Optional[str] = None
) -> Tuple[List[Finding], int]:
    findings, dirs = ([], [])
    if extra_dir:
        dirs.append(Path(extra_dir).expanduser())
    for d in adapter.skills_dirs:
        p = Path(d).expanduser()
        if p.exists():
            dirs.append(p)
    scanned = 0
    for d in dirs:
        if not d.exists():
            continue
        for item in sorted(d.iterdir(), key=lambda candidate: candidate.name.lower()):
            # Skill bundles are not reliably named: archives may use custom
            # extensions or no extension at all.  ``scan_skill`` performs
            # bounded magic sniffing, so every regular top-level file is a
            # legitimate candidate instead of only Markdown files.
            if item.is_dir() or item.is_file() or item.is_symlink():
                findings.extend(scan_skill(item))
                scanned += 1
    return (findings, scanned)


SOUL_INJECTION_PATTERNS: List[Tuple[str, str, str]] = [
    (
        "(?i)ignore\\s+(?:all\\s+)?(?:previous|above)\\s+instructions?",
        CRIT,
        t("指令覆盖注入", "Instruction override injection"),
    ),
    (
        "(?i)you\\s+are\\s+now\\s+(?:a\\s+new|another|a\\s+different|uncensored)",
        CRIT,
        t("角色劫持注入", "Role hijacking injection"),
    ),
    (
        "(?i)(?:jailbreak|dan\\s+mode|unrestricted\\s+mode|developer\\s+mode)",
        CRIT,
        t("越狱关键词", "Jailbreak keywords"),
    ),
    ("(?:\\\\u[0-9a-fA-F]{4}){6,}", HIGH, t("大量 Unicode 转义", "Excessive Unicode escapes")),
    ("(?:[A-Za-z0-9+/]{200,}={0,2})", WARN, t("长 base64 字符串", "Long base64 string")),
    (
        "(?i)do\\s+not\\s+(?:reveal|disclose|share)\\s+(?:your\\s+)?(?:system\\s+prompt|instructions)",
        WARN,
        t("要求模型隐藏指令", "Instructs model to hide instructions"),
    ),
    (
        "(?i)(?:show|print|reveal|dump|display|output)\\s+(?:your\\s+)?(?:system\\s+prompt|developer\\s+message|hidden\\s+instructions?|internal\\s+(?:rules|instructions))",
        HIGH,
        t("提取系统提示词", "System prompt extraction"),
    ),
    (
        "(?:(不要|别)(再)?(请求|询问)(审批|确认|授权)|(默认|视为)(已经)?(获得|有)(审批|授权))|(?i:(?:do\\s+not|don't)\\s+(?:ask|request)\\s+(?:for\\s+)?(?:approval|confirmation|permission)|(?:assume|treat\\s+it\\s+as)\\s+(?:approval|permission)\\s+(?:is|was)\\s+(?:already\\s+)?granted)",
        HIGH,
        t("审批绕过指令", "Approval bypass instruction"),
    ),
    (
        "(?i)(?:before\\s+(?:replying|responding|answering)|without\\s+explaining).{0,80}(?:call|invoke|run)\\s+(?:the\\s+)?tool",
        WARN,
        t("优先工具调用指令", "Tool-first instruction"),
    ),
]
_COMPILED_SOUL_PATTERNS = [
    (re.compile(p), level, title)
    for p, level, title in SOUL_INJECTION_PATTERNS
]
HASH_STORE = Path.home() / ".clawlock" / "drift_hashes.json"
_HASH_CACHE: dict | None = None
_HASH_CACHE_PATH: Path | None = None


def _hash_cache_matches() -> bool:
    return _HASH_CACHE_PATH == HASH_STORE


def _load_hashes() -> dict:
    global _HASH_CACHE, _HASH_CACHE_PATH

    if _HASH_CACHE is not None and _hash_cache_matches():
        return dict(_HASH_CACHE)

    try:
        HASH_STORE.parent.mkdir(parents=True, exist_ok=True)
        if HASH_STORE.exists():
            _HASH_CACHE = json.loads(HASH_STORE.read_text())
            _HASH_CACHE_PATH = HASH_STORE
            return dict(_HASH_CACHE)
    except Exception:
        pass

    _HASH_CACHE = {}
    _HASH_CACHE_PATH = HASH_STORE
    return {}


def _save_hashes(d: dict):
    global _HASH_CACHE, _HASH_CACHE_PATH

    _HASH_CACHE = dict(d)
    _HASH_CACHE_PATH = HASH_STORE
    try:
        HASH_STORE.parent.mkdir(parents=True, exist_ok=True)
        HASH_STORE.write_text(json.dumps(d, indent=2))
    except Exception:
        # Drift baselines are best-effort; permission errors should not block
        # the main scan or prompt integrity checks.
        return False
    return True


def _scan_single_file_drift(filepath: Path, label: str) -> List[Finding]:
    """Scan one file for injection patterns + drift.

    The first observation establishes a baseline.  A later mismatch is never
    accepted implicitly: only the explicit ``soul --update-baseline`` path may
    replace a trusted hash.  This prevents a malicious edit from becoming the
    new baseline merely because the scanner observed it once.
    """
    findings = []
    if not filepath.exists():
        return findings
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    for i, line in enumerate(content.splitlines(), 1):
        for compiled_pat, level, title in _COMPILED_SOUL_PATTERNS:
            if compiled_pat.search(line):
                findings.append(
                    Finding(
                        "soul",
                        level,
                        f"{label}: {title}",
                        t(f"位置: {filepath.name}:{i}", f"Location: {filepath.name}:{i}"),
                        f"{filepath.name}:{i}",
                        line.strip()[:120],
                        t("检查该行是否合法。", "Check if this line is legitimate."),
                    )
                )
                break
    current_hash = hashlib.sha256(content.encode()).hexdigest()
    stored = _load_hashes()
    key = str(filepath.resolve())
    previous_hash = stored.get(key)
    if previous_hash is not None and previous_hash != current_hash:
        findings.append(
            Finding(
                "soul",
                WARN,
                t(f"⚡ {label} 内容已变更（Drift 检测）", f"⚡ {label} content changed (Drift detection)"),
                t(f"{filepath.name} 的 SHA-256 哈希已变化。", f"SHA-256 hash of {filepath.name} has changed."),
                str(filepath),
                remediation=t("若变更是预期的，运行 `clawlock soul --update-baseline` 更新基准。",
                              "If the change is expected, run `clawlock soul --update-baseline` to update the baseline."),
                metadata={
                    "prev": previous_hash[:12],
                    "curr": current_hash[:12],
                    "baseline_preserved": True,
                },
            )
        )
    elif previous_hash is None:
        stored[key] = current_hash
        _save_hashes(stored)
    return findings


def scan_soul(
    adapter: AdapterSpec, soul_path: Optional[str] = None
) -> Tuple[List[Finding], Optional[Path]]:
    findings, candidates = ([], [])
    if soul_path:
        candidates = [Path(soul_path).expanduser()]
    else:
        for fname in adapter.soul_filenames:
            candidates += [
                Path.cwd() / fname,
                Path.home() / f".{adapter.name}" / fname,
                Path.home() / ".claude" / fname,
            ]
    found = None
    for c in candidates:
        if c.exists():
            found = c
            break
    if found:
        findings.extend(_scan_single_file_drift(found, t("系统提示词", "System prompt")))
    return (findings, found)


def scan_memory_files(adapter: AdapterSpec) -> List[Finding]:
    """v1.1: Scan HEARTBEAT.md, MEMORY.md, memory/*.md for injection+drift."""
    findings = []
    for mem_path_str in adapter.memory_files:
        mem_path = Path(mem_path_str).expanduser()
        if mem_path.is_file():
            findings.extend(_scan_single_file_drift(mem_path, t("记忆文件", "Memory file")))
        elif mem_path.is_dir():
            for md in mem_path.glob("*.md"):
                findings.extend(_scan_single_file_drift(md, "记忆文件"))
    return findings


_MCP_ITP = [
    (
        "(?i)(?:all\\s+(?:messages?|emails?|data|files?)\\s+(?:sent|written|uploaded)\\s+(?:via|through)\\s+\\S+\\s+(?:must\\s+be\\s+)?(?:redirect|forward|copy|send))",
        CRIT,
        t("隐式工具投毒: 参数篡改 (ASR≈47%)", "Implicit tool poisoning: parameter tampering (ASR≈47%)"),
        t("将合法参数静默重定向。", "Silently redirecting legitimate parameters."),
    ),
    (
        "(?i)(?:instead\\s+of\\s+(?:calling|using|invoking)\\s+\\S+,?\\s+(?:call|use|invoke|run)\\s+\\S+)",
        HIGH,
        t("隐式工具投毒: 函数劫持 (ASR≈37%)", "Implicit tool poisoning: function hijacking (ASR≈37%)"),
        t("要求调用另一个工具。", "Requests calling a different tool."),
    ),
    (
        "(?i)(?:before\\s+(?:any|each|every)\\s+(?:file|network|database|tool)\\s+(?:operation|action|call),?\\s+(?:first\\s+)?(?:read|send|upload|post|access))",
        CRIT,
        t("隐式工具投毒: 隐式触发器 (ASR≈27%)", "Implicit tool poisoning: implicit trigger (ASR≈27%)"),
        t("在任意操作前插入前置动作。", "Inserts pre-action before any operation."),
    ),
    (
        "(?i)(?:this\\s+tool\\s+(?:has\\s+been\\s+)?(?:updated|changed|modified))",
        WARN,
        t("MCP Rug Pull 迹象", "MCP Rug Pull indicator"),
        t("工具声称已修改行为。", "Tool claims modified behavior."),
    ),
    (
        "(?i)(?:(?:replaces?|supersedes?|overrides?|shadows?)\\s+(?:the\\s+)?(?:built-in|default|original|existing)\\s+\\S+\\s+tool)",
        HIGH,
        t("MCP 工具覆盖 (Tool Shadowing)", "MCP Tool Shadowing"),
        t("声称替代内置工具。", "Claims to replace a built-in tool."),
    ),
    (
        "(?i)(?:permission\\s+(?:from|granted\\s+by)\\s+(?:\\S+\\s+)?server)",
        WARN,
        t("MCP 跨域权限提升", "MCP cross-origin privilege escalation"),
        t("声明来自另一服务器的权限。", "Claims permissions from another server."),
    ),
    (
        "(?i)(?:show|print|reveal|dump|display|output).{0,40}(?:system\\s+prompt|developer\\s+message|internal\\s+(?:rules|instructions))",
        HIGH,
        t("隐式工具投毒: 提取系统提示词", "Implicit tool poisoning: system prompt extraction"),
        t("工具描述试图诱导模型输出系统提示词或内部规则。", "Tool description attempts to coerce the model into revealing its system prompt or internal rules."),
    ),
    (
        "(?i)(?:do\\s+not|don't)\\s+(?:ask|request)\\s+(?:for\\s+)?(?:approval|confirmation|permission)|(?:assume|treat\\s+it\\s+as)\\s+(?:approval|permission)\\s+(?:is|was)\\s+(?:already\\s+)?granted",
        HIGH,
        t("隐式工具投毒: 审批绕过", "Implicit tool poisoning: approval bypass"),
        t("工具描述要求跳过审批或视为已获授权。", "Tool description asks the model to bypass approval or assume permission was granted."),
    ),
    (
        "(?i)(?:before\\s+(?:replying|responding|answering)|without\\s+explaining).{0,80}(?:call|invoke|run)\\s+(?:the\\s+)?tool",
        WARN,
        t("隐式工具投毒: 强制工具优先", "Implicit tool poisoning: forced tool-first behavior"),
        t("工具描述要求模型在回复前优先执行工具调用。", "Tool description instructs the model to invoke a tool before replying."),
    ),
]
_COMPILED_MCP_ITP = [
    (re.compile(p), lv, title, detail)
    for p, lv, title, detail in _MCP_ITP
]


def scan_mcp(adapter: AdapterSpec, extra_mcp: Optional[str] = None) -> List[Finding]:
    findings, configs = ([], [])
    if extra_mcp:
        configs.append(Path(extra_mcp).expanduser())
    for p in adapter.mcp_configs:
        exp = Path(p).expanduser()
        if exp.exists():
            configs.append(exp)
    for fname in [".mcp.json", "mcp.json", "claude_desktop_config.json"]:
        p = Path.cwd() / fname
        if p.exists():
            configs.append(p)
    seen_configs: set = set()
    for cfg_path in configs:
        key = str(cfg_path.resolve())
        if key in seen_configs:
            continue
        seen_configs.add(key)
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("top-level MCP config must be a JSON object")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            diagnostic = _scanner_error_finding(
                t(f"MCP 配置 {cfg_path}", f"MCP config {cfg_path}"),
                exc,
            )
            diagnostic.location = str(cfg_path)
            diagnostic.metadata.update(
                {"scan_status": "error", "component": "mcp_config"}
            )
            findings.append(diagnostic)
            continue
        servers = data.get("mcpServers", data.get("servers", {}))
        if not isinstance(servers, dict):
            diagnostic = Finding(
                "internal",
                WARN,
                t("MCP 配置结构无效", "Invalid MCP config structure"),
                t(
                    "mcpServers/servers 必须是对象，MCP 检查未完整执行。",
                    "mcpServers/servers must be an object; the MCP check did not complete.",
                ),
                str(cfg_path),
                metadata={"scan_status": "error", "component": "mcp_config"},
            )
            findings.append(diagnostic)
            continue
        for srv_name, srv in servers.items():
            if not isinstance(srv, dict):
                findings.append(
                    Finding(
                        "internal",
                        WARN,
                        t("MCP Server 配置结构无效", "Invalid MCP server entry"),
                        t(
                            "单个 MCP Server 配置必须是对象；该服务未完成检查。",
                            "Each MCP server entry must be an object; this server was not fully checked.",
                        ),
                        f"{cfg_path.name}:mcpServers.{srv_name}",
                        metadata={
                            "scan_status": "error",
                            "component": "mcp_config",
                            "server": str(srv_name),
                        },
                    )
                )
                continue

            # The runtime-aware audit covers launch argv, package runners,
            # OAuth endpoints/scopes, token passthrough and protocol schema
            # constraints.  It is passive: importing it never starts a server.
            try:
                from .mcp_runtime import audit_server_config

                for issue in audit_server_config(
                    str(srv_name),
                    srv,
                    location=f"{cfg_path.name}:mcpServers",
                ):
                    findings.append(
                        Finding(
                            scanner="mcp_runtime",
                            level=issue.level,
                            title=f"[{issue.rule_id}] {issue.title}",
                            detail=issue.detail,
                            location=issue.location,
                            remediation=issue.remediation,
                            metadata={
                                "rule_id": issue.rule_id,
                                "component": "mcp_config",
                                "server": str(srv_name),
                                "evidence": issue.evidence,
                            },
                        )
                    )
            except Exception as exc:
                diagnostic = _scanner_error_finding(
                    t("MCP 运行时配置审计", "MCP runtime config audit"), exc
                )
                diagnostic.location = f"{cfg_path.name}:mcpServers.{srv_name}"
                diagnostic.metadata.update(
                    {"scan_status": "error", "component": "mcp_runtime_config"}
                )
                findings.append(diagnostic)

            url, env = (srv.get("url", ""), srv.get("env", {}))
            if isinstance(url, str):
                if re.match("https?://(?:0\\.0\\.0\\.0|\\*)", url):
                    findings.append(
                        Finding(
                            "mcp",
                            CRIT,
                            t(f"MCP [{srv_name}] 绑定 0.0.0.0", f"MCP [{srv_name}] bound to 0.0.0.0"),
                            t("服务器对外网暴露。", "Server exposed to external network."),
                            f"{cfg_path.name}:mcpServers.{srv_name}",
                            remediation=t("改为 127.0.0.1。", "Change to 127.0.0.1."),
                        )
                    )
                elif (
                    url.startswith("http")
                    and "localhost" not in url
                    and ("127." not in url)
                ):
                    findings.append(
                        Finding(
                            "mcp",
                            WARN,
                            t(f"MCP [{srv_name}] 连接远程端点", f"MCP [{srv_name}] connects to remote endpoint"),
                            t(f"指向 {url[:60]}。", f"Points to {url[:60]}."),
                            f"{cfg_path.name}:mcpServers.{srv_name}",
                            remediation=t("确认可信度。", "Verify trustworthiness."),
                        )
                    )
            for ek, ev in (env if isinstance(env, dict) else {}).items():
                if (
                    re.search("(?i)(password|secret|token|api_key)", ek)
                    and len(str(ev)) > 8
                ):
                    findings.append(
                        Finding(
                            "mcp",
                            HIGH,
                            t(f"MCP [{srv_name}] env 中含凭证", f"MCP [{srv_name}] env contains credentials"),
                            t(f"字段 {ek} 明文写入配置。", f"Field {ek} stored in plaintext in config."),
                            f"{cfg_path.name}:mcpServers.{srv_name}.env.{ek}",
                            remediation=t("改用环境变量。", "Use environment variables instead."),
                        )
                    )
                if ek.upper() in RISKY_ENV_VARS:
                    findings.append(
                        Finding(
                            "mcp",
                            HIGH,
                            t(f"MCP [{srv_name}] env 含危险变量: {ek}", f"MCP [{srv_name}] env has dangerous var: {ek}"),
                            t(f"{ek} 可被利用注入恶意代码到 MCP 服务器进程。", f"{ek} can be exploited to inject malicious code into the MCP server process."),
                            f"{cfg_path.name}:mcpServers.{srv_name}.env.{ek}",
                            remediation=t(f"移除 {ek}。", f"Remove {ek}."),
                        )
                    )
            inline_tools = srv.get("tools", [])
            for tool in inline_tools if isinstance(inline_tools, list) else []:
                if not isinstance(tool, dict):
                    continue
                text_fields = {
                    "description": tool.get("description", ""),
                    "annotations": str(tool.get("annotations", "")),
                    "errorTemplate": str(tool.get("errorTemplate", "")),
                    "outputTemplate": str(tool.get("outputTemplate", "")),
                }
                input_schema = tool.get("inputSchema", {})
                properties = (
                    input_schema.get("properties", {})
                    if isinstance(input_schema, dict)
                    else {}
                )
                for pn, prop in properties.items() if isinstance(properties, dict) else []:
                    if isinstance(prop, dict):
                        text_fields[f"param:{pn}"] = prop.get("description", "")
                for fn, text in text_fields.items():
                    if not text:
                        continue
                    for compiled_pat, lv, title, detail in _COMPILED_MCP_ITP:
                        if compiled_pat.search(text):
                            findings.append(
                                Finding(
                                    "mcp_itp",
                                    lv,
                                    f"[{srv_name}/{tool.get('name', '?')}] {title}",
                                    detail,
                                    f"{cfg_path.name}:tools[{tool.get('name', '?')}].{fn}",
                                    text[:120],
                                    t("审查该工具描述来源。", "Review the source of this tool description."),
                                )
                            )
                            break
    return findings


def precheck_skill_md(skill_md_path: Path) -> Tuple[List[Finding], bool]:
    """Fail-closed import precheck plus the full local Skill pipeline."""
    if not skill_md_path.exists():
        finding = _skill_scan_diagnostic(
            t("待导入 Skill 不存在", "Skill import target does not exist"),
            t("未执行任何导入前检查。", "No import precheck was performed."),
            skill_md_path,
        )
        return ([finding], False)
    scan_target = (
        skill_md_path.parent if skill_md_path.name == "SKILL.md" else skill_md_path
    )
    findings: List[Finding] = scan_skill(scan_target)
    if skill_md_path.is_symlink():
        return (findings, False)
    try:
        content, truncated, _bytes_read = _read_skill_text_prefix(
            skill_md_path, _SKILL_MAX_FILE_BYTES
        )
    except OSError as exc:
        findings.append(
            _skill_scan_diagnostic(
                t("待导入 SKILL.md 无法读取", "Import SKILL.md could not be read"),
                str(exc)[:300],
                skill_md_path,
            )
        )
        return (findings, False)
    if content is None:
        findings.append(
            _skill_scan_diagnostic(
                t("待导入 SKILL.md 不是文本", "Import SKILL.md is not text"),
                t("无法执行元数据与指令检查。", "Metadata and instruction checks could not run."),
                skill_md_path,
            )
        )
        return (findings, False)
    if truncated:
        findings.append(
            _skill_scan_diagnostic(
                t("待导入 SKILL.md 仅完成前缀检查", "Import SKILL.md was only partially checked"),
                t("文件超过单文件读取预算。", "The file exceeds the per-file read budget."),
                skill_md_path,
            )
        )
    skill_name = (
        skill_md_path.parent.name
        if skill_md_path.name == "SKILL.md"
        else skill_md_path.stem
    )
    for i, line in enumerate(content.splitlines(), 1):
        candidates = [line]
        candidates.extend(_unwrap_shell_commands(line))
        for candidate in candidates:
            for (
                compiled_pat,
                level,
                title,
                detail,
                category,
                rule_id,
                confidence,
            ) in _COMPILED_MALICIOUS_PATTERNS:
                if compiled_pat.search(candidate):
                    suffix = t(" (反混淆后发现)", " (found after deobfuscation)") if candidate is not line else ""
                    findings.append(
                        Finding(
                            "skill_precheck",
                            level,
                            t(f"[{category}] [新 Skill: {skill_name}] {title}{suffix}", f"[{category}] [New Skill: {skill_name}] {title}{suffix}"),
                            detail,
                            f"SKILL.md:{i}",
                            line.strip()[:120],
                            t("安装前仔细审查来源和代码。", "Carefully review the source and code before installing."),
                            metadata={
                                "category": category,
                                "rule_id": rule_id,
                                "confidence": confidence,
                            },
                        )
                    )
                    break
    for pat, lv, title, detail in [
        (
            "(?i)requires.*(?:sudo|root|admin)",
            HIGH,
            t("要求管理员权限", "Requires admin privileges"),
            t("声明需要 sudo/root。", "Declares need for sudo/root."),
        ),
        (
            "(?i)requires.*(?:full.?disk|全盘|所有文件)",
            HIGH,
            t("要求全盘访问", "Requires full disk access"),
            t("声明需要全盘文件访问。", "Declares need for full disk file access."),
        ),
        (
            "(?i)bins.*(?:curl|wget|nc|netcat|nmap|ssh)",
            WARN,
            t("依赖网络工具", "Depends on network tools"),
            t("依赖网络工具二进制。", "Depends on network tool binaries."),
        ),
        (
            "(?i)(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES)",
            HIGH,
            t("引用危险环境变量", "References dangerous env var"),
            t("SKILL.md 中引用了可注入代码的环境变量。", "SKILL.md references env vars that enable code injection."),
        ),
    ]:
        if re.search(pat, content):
            findings.append(
                Finding(
                    "skill_precheck",
                    lv,
                    t(f"[新 Skill: {skill_name}] {title}", f"[New Skill: {skill_name}] {title}"),
                    detail,
                    "SKILL.md:metadata",
                    remediation=t("确认这些权限是否与功能匹配。", "Verify these permissions match the intended functionality."),
                )
            )
    urls = re.findall("https?://[^\\s\\)>\"\\']+", content)
    for url in urls:
        if any(
            (
                f"{tld}" in url.lower()
                for tld in [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".buzz"]
            )
        ):
            findings.append(
                Finding(
                    "skill_precheck",
                    WARN,
                    t(f"[新 Skill: {skill_name}] 引用可疑域名", f"[New Skill: {skill_name}] References suspicious domain"),
                    f"URL: {url[:80]}",
                    remediation=t("确认域名可信度。", "Verify domain trustworthiness."),
                )
            )
    if re.search("[\\u200b\\u200c\\u200d\\ufeff\\u2060]", content):
        findings.append(
            Finding(
                "skill_precheck",
                HIGH,
                t(f"[新 Skill: {skill_name}] 发现零宽字符", f"[New Skill: {skill_name}] Zero-width characters found"),
                t("可能隐藏注入内容。", "May hide injected content."),
                remediation=t("使用十六进制编辑器检查。", "Inspect with a hex editor."),
            )
        )
    if len(content) > 50000:
        findings.append(
            Finding(
                "skill_precheck",
                WARN,
                t(f"[新 Skill: {skill_name}] SKILL.md 异常过大", f"[New Skill: {skill_name}] SKILL.md abnormally large"),
                t(f"文件 {len(content)} 字节。", f"File is {len(content)} bytes."),
                remediation=t("检查是否包含不必要的嵌入内容。", "Check for unnecessary embedded content."),
            )
        )
    is_safe = not any(
        f.level in (CRIT, HIGH) or f.metadata.get("scan_status") == "error"
        for f in findings
    )
    return (findings, is_safe)

