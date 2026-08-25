"""Live MCP inventory, launch hardening, and rug-pull drift detection.

The core scanner is deliberately passive.  This module adds an *explicitly
consented* live layer without ever using a shell or auto-installing a server.
It understands streamable-HTTP and line-delimited stdio JSON-RPC well enough
to collect the security-relevant MCP surface (tools, prompts and resources),
normalise it, and compare it with a trusted snapshot.

Nothing in this file imports :mod:`clawlock.scanners` so the domain objects can
be reused by the CLI, tests, and third-party integrations without a circular
dependency.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit


MCP_PROTOCOL_VERSION = "2025-11-25"
_MAX_RPC_BYTES = 4 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024
_MAX_LIST_PAGES = 32
_MAX_LIST_ITEMS = 1_024
_MAX_CURSOR_CHARS = 1_024
_MAX_PROTOCOL_DEPTH = 8
_MAX_PROTOCOL_ITEMS = 1_024
_MAX_PROTOCOL_STRING = 8_192
_MAX_ERROR_CHARS = 1_024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class RuntimeIssue:
    rule_id: str
    level: str
    title: str
    detail: str
    location: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass(frozen=True)
class InventoryItem:
    kind: str
    name: str
    description: str = ""
    schema: Dict[str, Any] = field(default_factory=dict)
    annotations: Dict[str, Any] = field(default_factory=dict)
    uri: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    title: str = ""
    output_schema: Dict[str, Any] = field(default_factory=dict)
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    mime_type: str = ""
    size: Optional[int] = None
    icons: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    execution: Dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> Dict[str, Any]:
        return _bounded_clean(
            {
                "kind": self.kind,
                "name": self.name,
                "title": self.title,
                "description": self.description,
                "schema": self.schema,
                "outputSchema": self.output_schema,
                "arguments": self.arguments,
                "annotations": self.annotations,
                "uri": self.uri,
                "mimeType": self.mime_type,
                "size": self.size,
                "icons": self.icons,
                "_meta": self.meta,
                "execution": self.execution,
            }
        )


@dataclass
class MCPInventory:
    server_id: str
    transport: str
    protocol_version: str = MCP_PROTOCOL_VERSION
    server_info: Dict[str, Any] = field(default_factory=dict)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    tools: List[InventoryItem] = field(default_factory=list)
    prompts: List[InventoryItem] = field(default_factory=list)
    resources: List[InventoryItem] = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)
    launch_identity: Dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> Dict[str, Any]:
        def _sort(items: Iterable[InventoryItem]) -> List[Dict[str, Any]]:
            return [
                item.canonical()
                for item in sorted(
                    items, key=lambda value: (value.kind, value.name, value.uri)
                )
            ]

        return _bounded_clean(
            {
                "server_id": self.server_id,
                "transport": self.transport,
                "protocol_version": self.protocol_version,
                "server_info": self.server_info,
                "capabilities": self.capabilities,
                "launch_identity": self.launch_identity,
                "tools": _sort(self.tools),
                "prompts": _sort(self.prompts),
                "resources": _sort(self.resources),
            }
        )

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(
            self.canonical(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass
class LiveProbeResult:
    status: str
    inventory: Optional[MCPInventory] = None
    issues: List[RuntimeIssue] = field(default_factory=list)
    error: str = ""
    stderr: str = ""


_SECRET_KEY_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|"
    r"password|passwd|secret|token|credential|private[_-]?key|client[_-]?secret|"
    r"cookie|session)"
)
_SECRET_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "key",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
}
_DANGEROUS_ENV = {
    "BASH_ENV",
    "DYLD_INSERT_LIBRARIES",
    "ENV",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PERL5OPT",
    "PROMPT_COMMAND",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "RUBYOPT",
}
_SHELL_PROGRAMS = {
    "bash",
    "cmd",
    "cmd.exe",
    "dash",
    "fish",
    "ksh",
    "powershell",
    "powershell.exe",
    "pwsh",
    "sh",
    "zsh",
}
_SHELL_FLAGS = {"-c", "/c", "-command", "--command", "-encodedcommand", "-enc"}
_PACKAGE_RUNNERS = {"npx", "npx.cmd", "uvx", "pipx", "bunx", "pnpx"}
_PROMPT_INJECTION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)ignore\s+(?:all\s+)?(?:previous|above|system)\s+instructions?"
        ),
    ),
    (
        "approval_bypass",
        re.compile(
            r"(?i)(?:do\s+not|don['’]t)\s+(?:ask|request).{0,30}"
            r"(?:approval|permission|confirmation)|assume.{0,30}(?:approved|authorized)"
        ),
    ),
    (
        "secret_request",
        re.compile(
            r"(?i)(?:send|upload|return|include|reveal|dump).{0,50}"
            r"(?:secret|token|password|credential|system\s+prompt|private\s+key)"
        ),
    ),
    (
        "tool_first",
        re.compile(
            r"(?i)(?:before\s+(?:replying|answering)|without\s+explaining).{0,80}"
            r"(?:call|invoke|run)\s+(?:this|the)\s+tool"
        ),
    ),
)


def _issue(
    rule_id: str,
    level: str,
    title: str,
    detail: str,
    location: str,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    remediation: str = "",
) -> RuntimeIssue:
    return RuntimeIssue(
        rule_id=rule_id,
        level=level,
        title=title,
        detail=detail,
        location=location,
        evidence=evidence or {},
        remediation=remediation,
    )


def _redact(value: Any) -> str:
    del value
    return "[REDACTED]"


def _replace_known_secrets(text: str, secret_values: Sequence[str]) -> str:
    result = text
    values = {
        str(value)
        for value in secret_values
        if value is not None and len(str(value)) >= 4
    }
    for value in sorted(values, key=len, reverse=True):
        result = result.replace(value, "[REDACTED]")
    return result


def _sanitize_url(url: str, secret_values: Sequence[str] = ()) -> str:
    """Remove URL credentials and redact secret query values without I/O."""

    text = _replace_known_secrets(str(url), secret_values)
    try:
        parsed = urlsplit(text)
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        try:
            port = f":{parsed.port}" if parsed.port is not None else ""
        except ValueError:
            port = ""
        netloc = (
            f"{hostname}{port}" if parsed.username or parsed.password else parsed.netloc
        )
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.casefold() in _SECRET_QUERY_KEYS:
                value = "[REDACTED]"
            else:
                value = _replace_known_secrets(value, secret_values)
            pairs.append((key, value))
        query = urlencode(pairs, doseq=True)
        fragment = _replace_known_secrets(parsed.fragment, secret_values)
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))
    except (TypeError, ValueError):
        # The fallback is deliberately lossy: malformed URLs are untrusted
        # diagnostic data and must not retain likely credential material.
        text = re.sub(r"(?i)(://)[^/@\s]+@", r"\1[REDACTED]@", text)
        return re.sub(
            r"(?i)([?&](?:access_token|api_key|apikey|authorization|client_secret|"
            r"key|password|secret|sig|signature|token)=)[^&#\s]*",
            r"\1[REDACTED]",
            text,
        )


def _scrub_text(
    value: Any,
    secret_values: Sequence[str] = (),
    *,
    max_chars: int = _MAX_PROTOCOL_STRING,
) -> str:
    text = _replace_known_secrets(str(value), secret_values)
    text = re.sub(
        r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+",
        "[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|"
        r"password|passwd|secret|token|credential|private[_-]?key|client[_-]?secret|"
        r"cookie|session)[\"']?\s*[:=]\s*)[\"']?[^\s,;\"'\]}]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(--(?:api-key|apikey|password|secret|token)(?:=|\s+))\S+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"https?://[^\s\"'<>]+",
        lambda match: _sanitize_url(match.group(0), secret_values),
        text,
        flags=re.IGNORECASE,
    )
    if len(text) > max_chars:
        return f"{text[:max_chars]}…[TRUNCATED]"
    return text


def _bounded_clean(
    value: Any,
    secret_values: Sequence[str] = (),
    *,
    _depth: int = 0,
) -> Any:
    """Return a JSON-safe, secret-scrubbed and bounded protocol value."""

    if _depth >= _MAX_PROTOCOL_DEPTH:
        return "[MAX-DEPTH]"
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        entries = list(value.items())
        for raw_key, child in entries[:_MAX_PROTOCOL_ITEMS]:
            key = _scrub_text(raw_key, secret_values, max_chars=256)
            if _SECRET_KEY_RE.search(str(raw_key)) and not isinstance(
                child,
                (Mapping, list, tuple, bool),
            ):
                result[key] = "[REDACTED]"
            else:
                result[key] = _bounded_clean(
                    child,
                    secret_values,
                    _depth=_depth + 1,
                )
        if len(entries) > _MAX_PROTOCOL_ITEMS:
            result["__truncated_fields__"] = len(entries) - _MAX_PROTOCOL_ITEMS
        return result
    if isinstance(value, (list, tuple)):
        result = [
            _bounded_clean(child, secret_values, _depth=_depth + 1)
            for child in value[:_MAX_PROTOCOL_ITEMS]
        ]
        if len(value) > _MAX_PROTOCOL_ITEMS:
            result.append(f"[TRUNCATED {len(value) - _MAX_PROTOCOL_ITEMS} ITEMS]")
        return result
    if isinstance(value, str):
        return _scrub_text(value, secret_values)
    if isinstance(value, bytes):
        return _scrub_text(value.decode("utf-8", errors="replace"), secret_values)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else str(value)
    return _scrub_text(value, secret_values)


def _safe_error(exc: BaseException, secret_values: Sequence[str] = ()) -> str:
    return _scrub_text(
        f"{type(exc).__name__}: {exc}",
        secret_values,
        max_chars=_MAX_ERROR_CHARS,
    )


def _collect_secret_values(
    *,
    url: str = "",
    headers: Optional[Mapping[str, str]] = None,
    env: Optional[Mapping[str, str]] = None,
    args: Sequence[str] = (),
) -> List[str]:
    values: List[str] = []
    if url:
        try:
            parsed = urlsplit(url)
            if parsed.username:
                values.append(parsed.username)
            if parsed.password:
                values.append(parsed.password)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                if key.casefold() in _SECRET_QUERY_KEYS and value:
                    values.append(value)
        except ValueError:
            pass
    for key, value in (headers or {}).items():
        key_text = str(key)
        if _SECRET_KEY_RE.search(key_text) or key_text.casefold() not in {
            "accept",
            "content-type",
            "user-agent",
        }:
            values.append(str(value))
    values.extend(str(value) for value in (env or {}).values())
    secret_flags = {"--api-key", "--apikey", "--password", "--secret", "--token", "-p"}
    for index, arg in enumerate(str(value) for value in args):
        previous = str(args[index - 1]).casefold() if index else ""
        if previous in secret_flags:
            values.append(arg)
        elif any(arg.casefold().startswith(f"{flag}=") for flag in secret_flags):
            values.append(arg.split("=", 1)[1])
        if arg.casefold().startswith(("http://", "https://")):
            values.extend(_collect_secret_values(url=arg))
    return list(dict.fromkeys(value for value in values if value))


def _literal_secret(value: Any) -> bool:
    text = str(value).strip()
    if not text or len(text) < 8:
        return False
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", text):
        return False
    if text.lower() in {"changeme", "example", "placeholder", "your_token_here"}:
        return False
    return True


def _host_scope(hostname: str) -> str:
    host = hostname.strip("[]").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return "loopback"
    if host.endswith((".local", ".internal", ".lan")):
        return "private-name"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "public-name"
    if address.is_loopback:
        return "loopback"
    if address.is_private or address.is_link_local or address.is_reserved:
        return "private-address"
    return "public-address"


def _audit_url(
    url: str, location: str, *, purpose: str = "endpoint"
) -> List[RuntimeIssue]:
    issues: List[RuntimeIssue] = []
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return [
            _issue(
                "MCP-URL-INVALID",
                "medium",
                "Invalid MCP URL",
                str(exc),
                location,
            )
        ]
    if parsed.scheme not in {"http", "https"}:
        issues.append(
            _issue(
                "MCP-URL-SCHEME",
                "high",
                "Unsafe MCP URL scheme",
                f"{purpose} uses unsupported scheme {parsed.scheme or '(missing)'!r}.",
                location,
                remediation="Use an explicit https:// endpoint, or loopback HTTP for local development.",
            )
        )
        return issues
    scope = _host_scope(parsed.hostname or "")
    if purpose == "OAuth metadata" and scope in {
        "loopback",
        "private-name",
        "private-address",
    }:
        issues.append(
            _issue(
                "MCP-OAUTH-PRIVATE-ENDPOINT",
                "high",
                "OAuth metadata endpoint targets a private address",
                "Server-controlled OAuth discovery must not reach loopback, private, link-local, or internal names.",
                location,
                evidence={"host_scope": scope},
                remediation="Allowlist the expected HTTPS issuer and reject redirects/DNS results into private ranges.",
            )
        )
    if parsed.scheme == "http" and scope != "loopback":
        issues.append(
            _issue(
                "MCP-URL-CLEARTEXT",
                "high",
                "MCP endpoint uses cleartext HTTP",
                f"{purpose} sends MCP traffic to {scope} without TLS.",
                location,
                evidence={"host_scope": scope},
                remediation="Use HTTPS and validate the server certificate.",
            )
        )
    if parsed.username or parsed.password:
        issues.append(
            _issue(
                "MCP-URL-USERINFO",
                "high",
                "Credential embedded in MCP URL",
                "URL user-info exposes a credential to config files, logs, and process telemetry.",
                location,
                remediation="Remove URL user-info and use a scoped secret provider.",
            )
        )
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in _SECRET_QUERY_KEYS and _literal_secret(value):
            issues.append(
                _issue(
                    "MCP-URL-QUERY-SECRET",
                    "high",
                    "Credential embedded in MCP URL query",
                    f"Query field {key!r} contains a literal credential ({_redact(value)}).",
                    location,
                    evidence={"query_key": key},
                    remediation="Move the credential to a scoped authorization mechanism.",
                )
            )
    return issues


def _package_token(command: str, args: Sequence[str]) -> str:
    lowered = Path(command).name.lower()
    tokens = list(args)
    if lowered == "pipx" and tokens and tokens[0].lower() == "run":
        tokens = tokens[1:]
    for token in tokens:
        if token == "--":
            continue
        if token.startswith("-"):
            continue
        return token
    return ""


def _is_pinned_runner_spec(command: str, package: str) -> bool:
    name = Path(command).name.lower()
    if not package:
        return False
    if name == "uvx" or name == "pipx":
        return "==" in package and not package.endswith("==")
    if name in {"npx", "npx.cmd", "bunx", "pnpx"}:
        if package.startswith("@"):
            # @scope/name@1.2.3 is pinned; @scope/name alone is not.
            return package.count("@") >= 2 and not package.lower().endswith("@latest")
        return "@" in package and not package.lower().endswith("@latest")
    return True


def audit_server_config(
    server_name: str,
    server: Mapping[str, Any],
    *,
    location: str = "mcpServers",
) -> List[RuntimeIssue]:
    """Audit a single MCP client config entry without starting it."""

    issues: List[RuntimeIssue] = []
    base = f"{location}.{server_name}"
    if not isinstance(server, Mapping):
        return [
            _issue(
                "MCP-CONFIG-TYPE",
                "medium",
                "Invalid MCP server configuration",
                "The server entry must be an object.",
                base,
            )
        ]

    url = server.get("url") or server.get("endpoint")
    if isinstance(url, str) and url:
        issues.extend(_audit_url(url, f"{base}.url"))

    command = server.get("command", "")
    raw_args = server.get("args", [])
    args = [str(value) for value in raw_args] if isinstance(raw_args, list) else []
    config_secret_values = _collect_secret_values(
        url=url if isinstance(url, str) else "",
        headers=(
            server.get("headers")
            if isinstance(server.get("headers"), Mapping)
            else None
        ),
        env=server.get("env") if isinstance(server.get("env"), Mapping) else None,
        args=args,
    )
    if command and not isinstance(command, str):
        issues.append(
            _issue(
                "MCP-COMMAND-TYPE",
                "high",
                "Invalid MCP launch command",
                "The command must be one executable string and args must be an array.",
                f"{base}.command",
            )
        )
    elif isinstance(command, str) and command:
        executable = Path(command).name.lower()
        if re.search(r"[|;&><`\r\n]", command):
            issues.append(
                _issue(
                    "MCP-LAUNCH-SHELL-META",
                    "critical",
                    "Shell syntax embedded in MCP executable",
                    "MCP commands must be represented as executable + argv, never as a shell program.",
                    f"{base}.command",
                    remediation="Move each argument into the args array and remove shell operators.",
                )
            )
        if executable in _SHELL_PROGRAMS and any(
            arg.lower() in _SHELL_FLAGS for arg in args
        ):
            issues.append(
                _issue(
                    "MCP-LAUNCH-SHELL",
                    "high",
                    "MCP server starts through a shell",
                    "A shell wrapper expands metacharacters, environment variables and profile hooks.",
                    f"{base}.args",
                    evidence={"executable": executable},
                    remediation="Launch a pinned executable directly with a fixed argv array.",
                )
            )
        if executable in _PACKAGE_RUNNERS:
            package = _package_token(command, args)
            if not _is_pinned_runner_spec(command, package):
                issues.append(
                    _issue(
                        "MCP-LAUNCH-UNPINNED",
                        "high",
                        "MCP package runner is not pinned",
                        f"{executable} would resolve {package or 'an implicit package'} at execution time.",
                        f"{base}.args",
                        evidence={"runner": executable, "package": package},
                        remediation="Install and verify a fixed version, then launch the installed executable directly.",
                    )
                )
            if any(arg in {"-y", "--yes"} for arg in args):
                issues.append(
                    _issue(
                        "MCP-LAUNCH-AUTO-INSTALL",
                        "high",
                        "MCP launch auto-accepts package installation",
                        "The package runner may download and execute code without an approval boundary.",
                        f"{base}.args",
                        remediation="Remove auto-approval and use a reviewed, pinned installation.",
                    )
                )
        command_path = Path(command).expanduser()
        if any(separator in command for separator in ("/", "\\")):
            if not command_path.is_absolute():
                issues.append(
                    _issue(
                        "MCP-LAUNCH-RELATIVE",
                        "high",
                        "MCP executable path is relative",
                        "The executable can be replaced by changing the client working directory or search path.",
                        f"{base}.command",
                        remediation="Use a reviewed absolute executable path and verify its digest/owner.",
                    )
                )
            else:
                lowered_path = str(command_path).replace("\\", "/").lower()
                writable_markers = (
                    "/tmp/",
                    "/var/tmp/",
                    "/downloads/",
                    "/appdata/local/temp/",
                    "/cache/",
                )
                under_user_profile = False
                try:
                    command_path.resolve(strict=False).relative_to(
                        Path.home().resolve()
                    )
                    under_user_profile = True
                except (OSError, ValueError):
                    pass
                if under_user_profile or any(
                    marker in lowered_path for marker in writable_markers
                ):
                    issues.append(
                        _issue(
                            "MCP-LAUNCH-WRITABLE-PATH",
                            "medium",
                            "MCP executable is under a user-writable location",
                            "A same-user process can replace the server executable after approval.",
                            f"{base}.command",
                            remediation="Install it in a protected location and verify a trusted digest before launch.",
                        )
                    )
                try:
                    mode = command_path.stat().st_mode
                    # POSIX mode bits returned by Windows are synthetic and
                    # do not describe the file's ACL.  Treating S_IWOTH as an
                    # ACL check creates a critical false positive there.
                    if os.name != "nt" and mode & stat.S_IWOTH:
                        issues.append(
                            _issue(
                                "MCP-LAUNCH-WORLD-WRITABLE",
                                "critical",
                                "MCP executable is world-writable",
                                "Any local user can replace the executable before the client starts it.",
                                f"{base}.command",
                            )
                        )
                except OSError:
                    pass
        joined = " ".join(args)
        if re.search(r"(?:https?://|git\+|github:|git@)[^\s]+", joined, re.I):
            if not re.search(
                r"(?:@[0-9a-f]{12,40}\b|#(?:sha256=)?[0-9a-f]{32,64}\b)", joined, re.I
            ):
                issues.append(
                    _issue(
                        "MCP-LAUNCH-MUTABLE-REMOTE",
                        "high",
                        "MCP launch references mutable remote code",
                        "A remote package/repository is executed without a commit or digest pin.",
                        f"{base}.args",
                        remediation="Pin a reviewed commit and verify the downloaded artifact digest.",
                    )
                )
        if re.search(r"(?:^|\s)(?:\||&&|;|>|<|`|\$\()", joined):
            issues.append(
                _issue(
                    "MCP-LAUNCH-ARGV-META",
                    "medium",
                    "Shell metacharacters appear in MCP arguments",
                    "The configured executable may interpret an argument as a shell program.",
                    f"{base}.args",
                    evidence={
                        "argv_preview": _scrub_text(
                            joined,
                            config_secret_values,
                            max_chars=160,
                        )
                    },
                )
            )
        for index, arg in enumerate(args):
            if re.match(r"https?://", arg, re.I):
                issues.extend(
                    _audit_url(arg, f"{base}.args[{index}]", purpose="launch argument")
                )
            previous = args[index - 1].lower() if index else ""
            if previous in {
                "--api-key",
                "--apikey",
                "--password",
                "--secret",
                "--token",
                "-p",
            } and _literal_secret(arg):
                issues.append(
                    _issue(
                        "MCP-ARGV-SECRET",
                        "high",
                        "Literal credential in MCP process arguments",
                        f"Argument after {previous!r} contains a literal credential ({_redact(arg)}).",
                        f"{base}.args[{index}]",
                        remediation="Resolve credentials inside the process from a scoped secret provider.",
                    )
                )

    if raw_args and not isinstance(raw_args, list):
        issues.append(
            _issue(
                "MCP-ARGS-TYPE",
                "high",
                "MCP args is not an array",
                "String command lines create ambiguous parsing and unsafe quoting.",
                f"{base}.args",
                remediation="Represent arguments as a JSON array.",
            )
        )

    env = server.get("env", {})
    if isinstance(env, Mapping):
        for key, value in env.items():
            key_text = str(key)
            if key_text.upper() in _DANGEROUS_ENV:
                issues.append(
                    _issue(
                        "MCP-ENV-INJECTION",
                        "high",
                        "Dangerous environment variable in MCP launch",
                        f"{key_text} can change code loading or shell behaviour.",
                        f"{base}.env.{key_text}",
                        remediation="Remove loader/profile injection variables from the server environment.",
                    )
                )
            if _SECRET_KEY_RE.search(key_text) and _literal_secret(value):
                issues.append(
                    _issue(
                        "MCP-ENV-SECRET",
                        "high",
                        "Literal credential in MCP environment",
                        f"{key_text} contains a literal credential ({_redact(value)}).",
                        f"{base}.env.{key_text}",
                        remediation="Use an OS keychain or secret manager with a short-lived scoped token.",
                    )
                )
    elif env:
        issues.append(
            _issue(
                "MCP-ENV-TYPE",
                "medium",
                "MCP env is not an object",
                "Environment variables could not be audited.",
                f"{base}.env",
            )
        )

    headers = server.get("headers", {})
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if _SECRET_KEY_RE.search(str(key)) and _literal_secret(value):
                issues.append(
                    _issue(
                        "MCP-HEADER-SECRET",
                        "high",
                        "Literal credential in MCP header",
                        f"Header {key!r} stores a literal credential ({_redact(value)}).",
                        f"{base}.headers.{key}",
                        remediation="Resolve authorization at runtime from a scoped secret provider.",
                    )
                )

    # OAuth/security values appear under different client-specific keys, so
    # recursively inspect names while retaining a precise config path.
    stack: List[Tuple[str, Any]] = [(base, server)]
    while stack:
        current_path, value = stack.pop()
        if isinstance(value, Mapping):
            for key, child in value.items():
                child_path = f"{current_path}.{key}"
                key_lower = str(key).lower()
                if isinstance(child, (Mapping, list)):
                    stack.append((child_path, child))
                if isinstance(child, str):
                    if key_lower in {
                        "authorization_endpoint",
                        "token_endpoint",
                        "registration_endpoint",
                        "jwks_uri",
                        "issuer",
                        "metadata_url",
                    }:
                        issues.extend(
                            _audit_url(child, child_path, purpose="OAuth metadata")
                        )
                    if "scope" in key_lower and (
                        child.strip() == "*" or "admin" in child.lower()
                    ):
                        issues.append(
                            _issue(
                                "MCP-OAUTH-BROAD-SCOPE",
                                "high",
                                "MCP OAuth scope is overly broad",
                                f"Configured scope {child!r} grants broad authority.",
                                child_path,
                                remediation="Request the minimum per-tool scopes and use step-up authorization.",
                            )
                        )
                    if key_lower in {"audience", "resource"} and not child.strip():
                        issues.append(
                            _issue(
                                "MCP-OAUTH-AUDIENCE",
                                "high",
                                "MCP token audience is empty",
                                "Tokens must be bound to the intended MCP resource server.",
                                child_path,
                            )
                        )
                    if key_lower in {
                        "forward_token",
                        "token_passthrough",
                        "passthrough",
                    } and child.lower() in {"1", "true", "yes", "enabled"}:
                        issues.append(
                            _issue(
                                "MCP-OAUTH-PASSTHROUGH",
                                "critical",
                                "MCP token passthrough enabled",
                                "Forwarding the client token to downstream services violates audience boundaries.",
                                child_path,
                                remediation="Exchange for a downstream audience-bound token.",
                            )
                        )
                if key_lower in {
                    "forward_token",
                    "token_passthrough",
                    "passthrough",
                } and (
                    child is True
                    or (
                        isinstance(child, (int, float))
                        and not isinstance(child, bool)
                        and child == 1
                    )
                ):
                    issues.append(
                        _issue(
                            "MCP-OAUTH-PASSTHROUGH",
                            "critical",
                            "MCP token passthrough enabled",
                            "Forwarding the client token to downstream services violates audience boundaries.",
                            child_path,
                            remediation="Exchange for a downstream audience-bound token.",
                        )
                    )
                if (
                    "scope" in key_lower
                    and isinstance(child, list)
                    and any(
                        str(scope).strip() == "*" or "admin" in str(scope).lower()
                        for scope in child
                    )
                ):
                    issues.append(
                        _issue(
                            "MCP-OAUTH-BROAD-SCOPE",
                            "high",
                            "MCP OAuth scope is overly broad",
                            "The configured scope list includes wildcard or administrative authority.",
                            child_path,
                            evidence={"scope_count": len(child)},
                            remediation="Request the minimum per-tool scopes and use step-up authorization.",
                        )
                    )
                if key_lower in {
                    "sessionid",
                    "session_id",
                    "session-id",
                } and _literal_secret(child):
                    issues.append(
                        _issue(
                            "MCP-SESSION-STATIC",
                            "high",
                            "Static MCP session identifier in configuration",
                            "A shared literal session identifier is replayable and is not an authentication boundary.",
                            child_path,
                            remediation="Generate unpredictable per-user sessions and bind them to authenticated identity.",
                        )
                    )
        elif isinstance(value, list):
            for index, child in enumerate(value):
                stack.append((f"{current_path}[{index}]", child))

    for tool in (
        server.get("tools", []) if isinstance(server.get("tools", []), list) else []
    ):
        if isinstance(tool, Mapping):
            issues.extend(
                audit_inventory_item(
                    _normalise_item("tool", tool, config_secret_values),
                    location=f"{base}.tools.{tool.get('name', '?')}",
                )
            )
    return _dedupe_issues(issues)


def _normalise_item(
    kind: str,
    value: Mapping[str, Any],
    secret_values: Sequence[str] = (),
) -> InventoryItem:
    cleaned = _bounded_clean(value, secret_values)
    if not isinstance(cleaned, Mapping):
        cleaned = {}
    name = str(cleaned.get("name") or cleaned.get("title") or cleaned.get("uri") or "?")
    description = str(cleaned.get("description") or "")
    schema = cleaned.get("inputSchema") or cleaned.get("schema") or {}
    output_schema = cleaned.get("outputSchema") or {}
    annotations = cleaned.get("annotations") or {}
    arguments = cleaned.get("arguments") or []
    icons = cleaned.get("icons") or []
    meta = cleaned.get("_meta") or {}
    execution = cleaned.get("execution") or {}
    size = cleaned.get("size")
    return InventoryItem(
        kind=kind,
        name=name,
        description=description,
        schema=dict(schema) if isinstance(schema, Mapping) else {},
        annotations=dict(annotations) if isinstance(annotations, Mapping) else {},
        uri=str(cleaned.get("uri") or ""),
        raw=dict(cleaned),
        title=str(cleaned.get("title") or ""),
        output_schema=(
            dict(output_schema) if isinstance(output_schema, Mapping) else {}
        ),
        arguments=[dict(item) for item in arguments if isinstance(item, Mapping)]
        if isinstance(arguments, list)
        else [],
        mime_type=str(cleaned.get("mimeType") or ""),
        size=size if isinstance(size, int) and not isinstance(size, bool) else None,
        icons=[dict(item) for item in icons if isinstance(item, Mapping)]
        if isinstance(icons, list)
        else [],
        meta=dict(meta) if isinstance(meta, Mapping) else {},
        execution=dict(execution) if isinstance(execution, Mapping) else {},
    )


def _schema_issues(schema: Mapping[str, Any], location: str) -> List[RuntimeIssue]:
    issues: List[RuntimeIssue] = []

    def visit(node: Any, path: str) -> None:
        if not isinstance(node, Mapping):
            return
        node_type = node.get("type")
        if node_type == "object":
            if node.get("additionalProperties", True) is not False:
                issues.append(
                    _issue(
                        "MCP-SCHEMA-OPEN-OBJECT",
                        "medium",
                        "MCP input object accepts unknown properties",
                        "Open object schemas make validation and authorization ambiguous.",
                        path,
                        remediation="Set additionalProperties: false and enumerate accepted fields.",
                    )
                )
            properties = node.get("properties", {})
            if isinstance(properties, Mapping):
                for key, child in properties.items():
                    visit(child, f"{path}.properties.{key}")
        elif node_type == "string":
            bounded = any(
                key in node
                for key in ("enum", "const", "pattern", "format", "maxLength")
            )
            if not bounded:
                issues.append(
                    _issue(
                        "MCP-SCHEMA-UNBOUNDED-STRING",
                        "medium",
                        "MCP string input is unconstrained",
                        "The field has no enum, format, pattern, or maximum length.",
                        path,
                        remediation="Constrain syntax, length and allowed values at the protocol boundary.",
                    )
                )
        elif node_type == "array":
            if "maxItems" not in node:
                issues.append(
                    _issue(
                        "MCP-SCHEMA-UNBOUNDED-ARRAY",
                        "medium",
                        "MCP array input is unbounded",
                        "The field has no maximum item count.",
                        path,
                    )
                )
            visit(node.get("items"), f"{path}.items")
        for keyword in ("anyOf", "oneOf", "allOf"):
            branches = node.get(keyword, [])
            if isinstance(branches, list):
                for index, child in enumerate(branches):
                    visit(child, f"{path}.{keyword}[{index}]")

    visit(schema, location)
    return issues


def audit_inventory_item(
    item: InventoryItem, *, location: str = ""
) -> List[RuntimeIssue]:
    issues: List[RuntimeIssue] = []
    base = location or f"{item.kind}.{item.name}"
    text_values: List[Tuple[str, str]] = [("description", item.description)]
    for key, value in item.raw.items():
        if key.lower() in {
            "description",
            "prompt",
            "template",
            "instructions",
            "errortemplate",
            "outputtemplate",
        } and isinstance(value, str):
            text_values.append((str(key), value))
    for field_name, text in text_values:
        if not text:
            continue
        if re.search(
            r"[\u200b\u200c\u200d\u2060\ufeff]|[\u202a-\u202e\u2066-\u2069]", text
        ):
            issues.append(
                _issue(
                    "MCP-CONTENT-HIDDEN-UNICODE",
                    "high",
                    "Hidden Unicode control in MCP content",
                    "Zero-width or bidi-control characters can conceal tool instructions.",
                    f"{base}.{field_name}",
                )
            )
        for label, pattern in _PROMPT_INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                issues.append(
                    _issue(
                        "MCP-CONTENT-INJECTION",
                        "high",
                        "MCP content contains control-plane instructions",
                        f"Detected {label} wording in {item.kind} {item.name!r}.",
                        f"{base}.{field_name}",
                        evidence={
                            "pattern": label,
                            "excerpt": text[
                                max(0, match.start() - 30) : match.end() + 60
                            ][:180],
                        },
                        remediation="Treat server-provided descriptions and content as untrusted data.",
                    )
                )
    if item.schema:
        issues.extend(_schema_issues(item.schema, f"{base}.inputSchema"))
    readonly = item.annotations.get("readOnlyHint")
    destructive = item.annotations.get("destructiveHint")
    if readonly is True and destructive is True:
        issues.append(
            _issue(
                "MCP-ANNOTATION-CONFLICT",
                "high",
                "MCP tool annotations conflict",
                "A tool cannot credibly be both read-only and destructive.",
                f"{base}.annotations",
                remediation="Derive annotations from reviewed implementation behavior.",
            )
        )
    return _dedupe_issues(issues)


def audit_inventory(inventory: MCPInventory) -> List[RuntimeIssue]:
    issues: List[RuntimeIssue] = []
    for item in [*inventory.tools, *inventory.prompts, *inventory.resources]:
        issues.extend(
            audit_inventory_item(
                item, location=f"{inventory.server_id}.{item.kind}.{item.name}"
            )
        )
    names: Dict[str, List[str]] = {}
    for item in inventory.tools:
        names.setdefault(item.name.casefold(), []).append(item.name)
    for key, values in names.items():
        if len(values) > 1:
            issues.append(
                _issue(
                    "MCP-TOOL-DUPLICATE",
                    "high",
                    "Duplicate MCP tool name",
                    f"Server publishes {len(values)} tools normalising to {key!r}.",
                    inventory.server_id,
                    evidence={"names": values},
                )
            )
    return _dedupe_issues(issues)


def detect_tool_shadowing(inventories: Sequence[MCPInventory]) -> List[RuntimeIssue]:
    owners: Dict[str, List[str]] = {}
    for inventory in inventories:
        for tool in inventory.tools:
            owners.setdefault(tool.name.casefold(), []).append(inventory.server_id)
    issues: List[RuntimeIssue] = []
    for name, servers in owners.items():
        distinct = sorted(set(servers))
        if len(distinct) > 1:
            issues.append(
                _issue(
                    "MCP-TOOL-SHADOWING",
                    "high",
                    "MCP tool name is shadowed across servers",
                    f"Tool {name!r} is published by: {', '.join(distinct)}.",
                    "mcp.inventory",
                    evidence={"tool": name, "servers": distinct},
                    remediation="Use unique qualified names and explicitly bind approvals to server identity.",
                )
            )
    return issues


def audit_annotation_behavior(
    inventory: MCPInventory,
    observed_capabilities: Mapping[str, Iterable[str]],
) -> List[RuntimeIssue]:
    """Compare untrusted MCP annotation hints with observed code/runtime effects.

    Capability names intentionally match the shared/capability analyzers but
    callers may supply equivalent lower-case strings from another backend.
    """

    issues: List[RuntimeIssue] = []
    write_effects = {
        "destructive",
        "external_write",
        "file_write",
        "memory_write",
        "path_write",
        "persistence",
        "prompt_write",
    }
    destructive_effects = {"destructive", "command_exec", "persistence"}
    open_world_effects = {"external_network", "external_write", "network"}
    by_name = {
        str(name).casefold(): {str(value).lower() for value in values}
        for name, values in observed_capabilities.items()
    }
    for tool in inventory.tools:
        observed = by_name.get(tool.name.casefold(), set())
        if not observed:
            continue
        annotations = tool.annotations
        location = f"{inventory.server_id}.tool.{tool.name}.annotations"
        conflicts: List[Tuple[str, set[str], str]] = []
        if annotations.get("readOnlyHint") is True and observed & write_effects:
            conflicts.append(
                (
                    "readOnlyHint",
                    observed & write_effects,
                    "Tool claims read-only behavior but observed effects mutate state.",
                )
            )
        if (
            annotations.get("destructiveHint") is False
            and observed & destructive_effects
        ):
            conflicts.append(
                (
                    "destructiveHint",
                    observed & destructive_effects,
                    "Tool claims non-destructive behavior but observed effects can execute, persist, or destroy.",
                )
            )
        if annotations.get("openWorldHint") is False and observed & open_world_effects:
            conflicts.append(
                (
                    "openWorldHint",
                    observed & open_world_effects,
                    "Tool claims closed-world behavior but observed effects reach external systems.",
                )
            )
        for hint, capabilities, detail in conflicts:
            issues.append(
                _issue(
                    "MCP-ANNOTATION-BEHAVIOR-MISMATCH",
                    "high",
                    "MCP annotation contradicts observed behavior",
                    detail,
                    location,
                    evidence={
                        "tool": tool.name,
                        "hint": hint,
                        "observed_capabilities": sorted(capabilities),
                    },
                    remediation="Derive risk hints from reviewed implementation and enforce policy independently of annotations.",
                )
            )
    return _dedupe_issues(issues)


def _decode_rpc_payload(content_type: str, raw: bytes) -> Dict[str, Any]:
    if len(raw) > _MAX_RPC_BYTES:
        raise ValueError(f"MCP response exceeds {_MAX_RPC_BYTES} bytes")
    text = raw.decode("utf-8", errors="strict")
    if "text/event-stream" in content_type.lower() or text.lstrip().startswith(
        "event:"
    ):
        candidates = []
        for line in text.splitlines():
            if line.startswith("data:"):
                candidates.append(line[5:].strip())
        for candidate in reversed(candidates):
            if candidate and candidate != "[DONE]":
                value = json.loads(candidate)
                if isinstance(value, dict):
                    return value
        raise ValueError("SSE response did not contain a JSON-RPC data event")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("MCP response must be a JSON object")
    return value


_LIST_SURFACES: Tuple[Tuple[str, str], ...] = (
    ("tools/list", "tools"),
    ("prompts/list", "prompts"),
    ("resources/list", "resources"),
)


async def _collect_paginated_surface(method: str, request_page: Any) -> Dict[str, Any]:
    """Collect one MCP list surface under page, item, and cursor budgets."""

    item_key = dict(_LIST_SURFACES).get(method)
    if item_key is None:
        raise ValueError(f"Unsupported MCP list method: {method}")
    items: List[Dict[str, Any]] = []
    seen_cursors: set[str] = set()
    cursor: Optional[str] = None
    for page_number in range(1, _MAX_LIST_PAGES + 1):
        params = {"cursor": cursor} if cursor is not None else {}
        page = await request_page(params)
        if not isinstance(page, Mapping):
            raise ValueError(f"{method} result must be an object")
        page_items = page.get(item_key, [])
        if not isinstance(page_items, list) or any(
            not isinstance(item, Mapping) for item in page_items
        ):
            raise ValueError(f"{method} returned an invalid {item_key} list")
        if len(items) + len(page_items) > _MAX_LIST_ITEMS:
            raise ValueError(f"{method} item budget exceeded")
        items.extend(dict(item) for item in page_items)

        next_cursor = page.get("nextCursor")
        if next_cursor is None or next_cursor == "":
            return {item_key: items}
        if not isinstance(next_cursor, str) or len(next_cursor) > _MAX_CURSOR_CHARS:
            raise ValueError(f"{method} returned an invalid pagination cursor")
        if next_cursor in seen_cursors:
            raise ValueError(f"{method} repeated a pagination cursor")
        if page_number >= _MAX_LIST_PAGES:
            raise ValueError(f"{method} page budget exceeded")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise ValueError(f"{method} page budget exceeded")


def _required_collection_failures(
    initialize: Mapping[str, Any],
    errors: Mapping[str, str],
) -> set[str]:
    required = {"tools/list"} & set(errors)
    capabilities = initialize.get("capabilities", {})
    if isinstance(capabilities, Mapping):
        for capability, method in (
            ("prompts", "prompts/list"),
            ("resources", "resources/list"),
        ):
            if capability in capabilities and method in errors:
                required.add(method)
    return required


def _collection_issues(
    server_id: str,
    initialize: Mapping[str, Any],
    errors: Mapping[str, str],
) -> List[RuntimeIssue]:
    required = _required_collection_failures(initialize, errors)
    issues: List[RuntimeIssue] = []
    for method, error in errors.items():
        if method == "tools/list":
            rule_id = "MCP-LIVE-TOOLS-INCOMPLETE"
            level = "medium"
            title = "Live MCP tool inventory failed"
        elif method in required:
            rule_id = "MCP-LIVE-ADVERTISED-INCOMPLETE"
            level = "medium"
            title = f"Advertised MCP method {method} failed"
        else:
            rule_id = "MCP-LIVE-CAPABILITY-UNAVAILABLE"
            level = "info"
            title = f"MCP method {method} unavailable"
        issues.append(
            _issue(
                rule_id,
                level,
                title,
                _scrub_text(error, max_chars=_MAX_ERROR_CHARS),
                server_id,
            )
        )
    return issues


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("MCP live probe time budget exceeded")
    return remaining


def _sanitized_search_path(path_value: str) -> str:
    cwd = Path.cwd().resolve()
    entries: List[str] = []
    for raw_entry in str(path_value).split(os.pathsep):
        entry = raw_entry.strip().strip('"')
        if not entry:
            continue
        directory = Path(entry).expanduser()
        if not directory.is_absolute():
            continue
        try:
            directory = directory.resolve(strict=False)
        except OSError:
            continue
        if os.path.normcase(str(directory)) == os.path.normcase(str(cwd)):
            continue
        entries.append(str(directory))
    return os.pathsep.join(dict.fromkeys(entries))


def _secure_resolve_executable(command: str) -> Optional[str]:
    """Resolve a command without implicit cwd or relative-PATH lookup."""

    command = str(command).strip()
    if not command:
        return None
    command_path = Path(command).expanduser()
    if command_path.is_absolute():
        candidates = [command_path]
    elif any(separator in command for separator in ("/", "\\")):
        return None
    else:
        directories = [
            Path(entry)
            for entry in _sanitized_search_path(os.environ.get("PATH", "")).split(
                os.pathsep
            )
            if entry
        ]
        names = [command]
        if os.name == "nt":
            extensions = [
                extension.casefold()
                for extension in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(
                    ";"
                )
                if extension
            ]
            if Path(command).suffix.casefold() not in extensions:
                names.extend(f"{command}{extension}" for extension in extensions)
        candidates = [directory / name for directory in directories for name in names]

    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_file():
                continue
            if os.name != "nt" and not os.access(str(resolved), os.X_OK):
                continue
            return str(resolved)
        except OSError:
            continue
    return None


def _hash_executable(path: str) -> Tuple[str, int, str]:
    resolved = Path(path).resolve(strict=True)
    file_stat = resolved.stat()
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("MCP executable is not a regular file")
    if file_stat.st_size > _MAX_EXECUTABLE_BYTES:
        raise ValueError("MCP executable exceeds the digest byte budget")
    digest = hashlib.sha256()
    consumed = 0
    with resolved.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > _MAX_EXECUTABLE_BYTES:
                raise ValueError("MCP executable exceeds the digest byte budget")
            digest.update(chunk)
    after = resolved.stat()
    if (after.st_size, after.st_mtime_ns) != (file_stat.st_size, file_stat.st_mtime_ns):
        raise RuntimeError("MCP executable changed while its digest was computed")
    return digest.hexdigest(), consumed, str(resolved)


def _http_launch_identity(url: str, headers: Mapping[str, str]) -> Dict[str, Any]:
    secret_values = _collect_secret_values(url=url, headers=headers)
    header_names = [
        "[credential-header]"
        if _SECRET_KEY_RE.search(str(key))
        else str(key).casefold()
        for key in headers
        if str(key).casefold() not in {"accept", "content-type"}
    ]
    return _bounded_clean(
        {
            "kind": "http",
            "endpoint": _sanitize_url(url, secret_values),
            "header_names": sorted(set(header_names)),
        },
        secret_values,
    )


def _stdio_launch_identity(
    executable: str,
    args: Sequence[str],
    env: Mapping[str, str],
    *,
    binary_sha256: str,
    binary_size: int,
    secret_values: Sequence[str],
) -> Dict[str, Any]:
    return _bounded_clean(
        {
            "kind": "stdio",
            "executable": executable,
            "argv": [str(value) for value in args],
            "env_keys": sorted(
                "[credential-env]" if _SECRET_KEY_RE.search(str(key)) else str(key)
                for key in env
            ),
            "binary_sha256": binary_sha256,
            "binary_size": binary_size,
        },
        secret_values,
    )


async def _http_rpc(
    client: Any,
    url: str,
    method: str,
    *,
    request_id: Optional[int],
    params: Optional[Dict[str, Any]],
    headers: Dict[str, str],
    secret_values: Optional[List[str]] = None,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, str]]:
    payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        payload["id"] = request_id
    if params is not None:
        payload["params"] = params
    chunks: List[bytes] = []
    consumed = 0
    content_type = ""
    new_headers = dict(headers)
    async with client.stream("POST", url, json=payload, headers=headers) as response:
        response.raise_for_status()
        session_id = response.headers.get("Mcp-Session-Id")
        if session_id:
            new_headers["Mcp-Session-Id"] = session_id
            if secret_values is not None and session_id not in secret_values:
                secret_values.append(session_id)
        content_type = response.headers.get("content-type", "")
        async for chunk in response.aiter_bytes():
            consumed += len(chunk)
            if consumed > _MAX_RPC_BYTES:
                raise ValueError(f"MCP response exceeds {_MAX_RPC_BYTES} bytes")
            chunks.append(chunk)
    raw = b"".join(chunks)
    if request_id is None or not raw:
        return None, new_headers
    decoded = _decode_rpc_payload(content_type, raw)
    if decoded.get("error"):
        error = _bounded_clean(decoded["error"], secret_values or ())
        raise RuntimeError(
            f"{method}: "
            f"{json.dumps(error, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}"
        )
    result = decoded.get("result", {})
    if not isinstance(result, dict):
        raise ValueError(f"{method} result must be an object")
    return result, new_headers


def _inventory_from_results(
    server_id: str,
    transport: str,
    initialize: Mapping[str, Any],
    results: Mapping[str, Mapping[str, Any]],
    *,
    secret_values: Sequence[str] = (),
    launch_identity: Optional[Mapping[str, Any]] = None,
) -> MCPInventory:
    def items(method: str, key: str, kind: str) -> List[InventoryItem]:
        result = results.get(method, {})
        values = result.get(key, []) if isinstance(result, Mapping) else []
        if not isinstance(values, list):
            return []
        return [
            _normalise_item(kind, value, secret_values)
            for value in values
            if isinstance(value, Mapping)
        ]

    safe_initialize = _bounded_clean(initialize, secret_values)
    if not isinstance(safe_initialize, Mapping):
        safe_initialize = {}
    server_info = safe_initialize.get("serverInfo") or {}
    capabilities = safe_initialize.get("capabilities") or {}

    return MCPInventory(
        server_id=_scrub_text(server_id, secret_values, max_chars=256),
        transport=_scrub_text(transport, secret_values, max_chars=32),
        protocol_version=str(
            safe_initialize.get("protocolVersion") or MCP_PROTOCOL_VERSION
        ),
        server_info=dict(server_info) if isinstance(server_info, Mapping) else {},
        capabilities=(dict(capabilities) if isinstance(capabilities, Mapping) else {}),
        tools=items("tools/list", "tools", "tool"),
        prompts=items("prompts/list", "prompts", "prompt"),
        resources=items("resources/list", "resources", "resource"),
        launch_identity=(
            dict(_bounded_clean(launch_identity, secret_values))
            if isinstance(launch_identity, Mapping)
            else {}
        ),
    )


async def probe_http_server(
    server_id: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    timeout: float = 8.0,
    allow_remote: bool = False,
) -> LiveProbeResult:
    """Collect live inventory from a streamable-HTTP MCP endpoint.

    Public endpoints require ``allow_remote=True``. Redirects are disabled to
    prevent an approved URL becoming an OAuth/HTTP SSRF pivot.
    """

    secret_values = _collect_secret_values(url=url, headers=headers)
    try:
        parsed = urlparse(url)
        scope = _host_scope(parsed.hostname or "")
    except ValueError as exc:
        error = _safe_error(exc, secret_values)
        return LiveProbeResult(
            status="blocked",
            error=error,
            issues=_audit_url(url, f"{server_id}.url"),
        )
    if parsed.scheme not in {"http", "https"}:
        return LiveProbeResult(
            status="blocked", error="Only HTTP(S) MCP endpoints are supported"
        )
    if scope not in {"loopback"} and not allow_remote:
        return LiveProbeResult(
            status="blocked",
            error="Remote live MCP probing requires explicit allow_remote consent",
            issues=_audit_url(url, f"{server_id}.url"),
        )
    try:
        import httpx

        request_headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **{str(k): str(v) for k, v in (headers or {}).items()},
        }
        deadline = time.monotonic() + max(float(timeout), 0.001)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            initialize, request_headers = await asyncio.wait_for(
                _http_rpc(
                    client,
                    url,
                    "initialize",
                    request_id=1,
                    params={
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "clawlock", "version": "2.6"},
                    },
                    headers=request_headers,
                    secret_values=secret_values,
                ),
                timeout=_remaining_timeout(deadline),
            )
            await asyncio.wait_for(
                _http_rpc(
                    client,
                    url,
                    "notifications/initialized",
                    request_id=None,
                    params={},
                    headers=request_headers,
                    secret_values=secret_values,
                ),
                timeout=_remaining_timeout(deadline),
            )
            initialize_map = initialize or {}
            results: Dict[str, Mapping[str, Any]] = {}
            optional_errors: Dict[str, str] = {}
            next_request_id = 2
            for method, _item_key in _LIST_SURFACES:

                async def request_page(
                    params: Dict[str, Any],
                    method_name: str = method,
                ) -> Mapping[str, Any]:
                    nonlocal next_request_id, request_headers
                    request_id = next_request_id
                    next_request_id += 1
                    result, request_headers = await asyncio.wait_for(
                        _http_rpc(
                            client,
                            url,
                            method_name,
                            request_id=request_id,
                            params=params,
                            headers=request_headers,
                            secret_values=secret_values,
                        ),
                        timeout=_remaining_timeout(deadline),
                    )
                    return result or {}

                try:
                    results[method] = await _collect_paginated_surface(
                        method,
                        request_page,
                    )
                except Exception as exc:
                    optional_errors[method] = _safe_error(exc, secret_values)
            inventory = _inventory_from_results(
                server_id,
                "http",
                initialize_map,
                results,
                secret_values=secret_values,
                launch_identity=_http_launch_identity(url, headers or {}),
            )
            issues = _audit_url(url, f"{server_id}.url") + audit_inventory(inventory)
            issues.extend(
                _collection_issues(server_id, initialize_map, optional_errors)
            )
            required_failures = _required_collection_failures(
                initialize_map,
                optional_errors,
            )
            status = "incomplete" if required_failures else "complete"
            return LiveProbeResult(
                status=status, inventory=inventory, issues=_dedupe_issues(issues)
            )
    except Exception as exc:
        error = _safe_error(exc, secret_values)
        return LiveProbeResult(
            status="error",
            error=error,
            issues=[
                _issue(
                    "MCP-LIVE-FAILED",
                    "medium",
                    "Live MCP probe failed",
                    error,
                    server_id,
                )
            ],
        )


async def _read_stdio_response(
    reader: asyncio.StreamReader,
    *,
    timeout: float,
    expected_id: int,
    secret_values: Sequence[str] = (),
) -> Dict[str, Any]:
    consumed = 0
    deadline = time.monotonic() + max(float(timeout), 0.001)
    for _ in range(100):
        raw = await asyncio.wait_for(
            reader.readline(),
            timeout=_remaining_timeout(deadline),
        )
        if not raw:
            raise EOFError("MCP server closed stdout")
        consumed += len(raw)
        if consumed > _MAX_RPC_BYTES:
            raise ValueError("MCP stdio response budget exceeded")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError):
            continue  # tolerate bounded diagnostic output on stdout
        if not isinstance(value, dict) or value.get("id") != expected_id:
            continue
        if value.get("error"):
            error = _bounded_clean(value["error"], secret_values)
            raise RuntimeError(
                json.dumps(
                    error,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        result = value.get("result", {})
        if not isinstance(result, dict):
            raise ValueError("MCP result must be an object")
        return result
    raise TimeoutError(f"No JSON-RPC response for id {expected_id}")


async def probe_stdio_server(
    server_id: str,
    command: str,
    args: Sequence[str],
    *,
    env: Optional[Mapping[str, str]] = None,
    timeout: float = 8.0,
    allow_execute: bool = False,
    allow_unpinned: bool = False,
) -> LiveProbeResult:
    """Start a stdio MCP server only after an explicit execution consent."""

    config = {"command": command, "args": list(args), "env": dict(env or {})}
    issues = audit_server_config(server_id, config)
    secret_values = _collect_secret_values(env=env, args=args)
    if not allow_execute:
        return LiveProbeResult(
            status="blocked",
            issues=issues,
            error="Starting a local MCP server requires explicit allow_execute consent",
        )
    pin_override_rules = {
        "MCP-LAUNCH-UNPINNED",
        "MCP-LAUNCH-AUTO-INSTALL",
        "MCP-LAUNCH-MUTABLE-REMOTE",
    }
    launch_structure_rules = {
        "MCP-ARGS-TYPE",
        "MCP-COMMAND-TYPE",
        "MCP-ENV-INJECTION",
    }
    blocking_issues = [
        issue
        for issue in issues
        if issue.level.casefold() in {"high", "critical"}
        and (
            issue.rule_id.startswith("MCP-LAUNCH-")
            or issue.rule_id in launch_structure_rules
        )
        and not (allow_unpinned and issue.rule_id in pin_override_rules)
    ]
    if blocking_issues:
        rule_ids = ", ".join(sorted({issue.rule_id for issue in blocking_issues}))
        return LiveProbeResult(
            status="blocked",
            issues=issues,
            error=f"Refusing unsafe MCP server launch: {rule_ids}",
        )
    executable = _secure_resolve_executable(command)
    if not executable:
        return LiveProbeResult(
            status="error",
            issues=issues,
            error=_scrub_text(
                f"MCP executable not found in an absolute trusted search path: {command}",
                secret_values,
                max_chars=_MAX_ERROR_CHARS,
            ),
        )

    deadline = time.monotonic() + max(float(timeout), 0.001)
    try:
        binary_sha256, binary_size, executable = await asyncio.wait_for(
            asyncio.to_thread(_hash_executable, executable),
            timeout=_remaining_timeout(deadline),
        )
    except Exception as exc:
        error = _safe_error(exc, secret_values)
        issues.append(
            _issue(
                "MCP-LAUNCH-IDENTITY",
                "high",
                "MCP executable identity could not be verified",
                error,
                f"{server_id}.command",
            )
        )
        return LiveProbeResult(
            status="blocked",
            issues=_dedupe_issues(issues),
            error=error,
        )

    # Do not hand every credential-bearing host environment variable to an
    # inspected server.  Keep only variables required to locate/start a
    # process; server-specific values must be explicitly present in config.
    inherited_names = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
    child_env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in inherited_names
    }
    child_env.update({str(key): str(value) for key, value in (env or {}).items()})
    if "PATH" in child_env:
        child_env["PATH"] = _sanitized_search_path(child_env["PATH"])
    process: Optional[asyncio.subprocess.Process] = None
    stderr_text = ""
    probe_result: Optional[LiveProbeResult] = None
    try:
        process = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                str(executable),
                *[str(value) for value in args],
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
            ),
            timeout=_remaining_timeout(deadline),
        )
        assert process.stdin is not None
        assert process.stdout is not None

        async def send(
            method: str, request_id: Optional[int], params: Dict[str, Any]
        ) -> None:
            payload: Dict[str, Any] = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }
            if request_id is not None:
                payload["id"] = request_id
            process.stdin.write(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
            await asyncio.wait_for(
                process.stdin.drain(),
                timeout=_remaining_timeout(deadline),
            )

        await send(
            "initialize",
            1,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "clawlock", "version": "2.6"},
            },
        )
        initialize = await _read_stdio_response(
            process.stdout,
            timeout=_remaining_timeout(deadline),
            expected_id=1,
            secret_values=secret_values,
        )
        await send("notifications/initialized", None, {})
        results: Dict[str, Mapping[str, Any]] = {}
        optional_errors: Dict[str, str] = {}
        next_request_id = 2
        for method, _item_key in _LIST_SURFACES:

            async def request_page(
                params: Dict[str, Any],
                method_name: str = method,
            ) -> Mapping[str, Any]:
                nonlocal next_request_id
                request_id = next_request_id
                next_request_id += 1
                await send(method_name, request_id, params)
                return await _read_stdio_response(
                    process.stdout,
                    timeout=_remaining_timeout(deadline),
                    expected_id=request_id,
                    secret_values=secret_values,
                )

            try:
                results[method] = await _collect_paginated_surface(
                    method,
                    request_page,
                )
            except Exception as exc:
                optional_errors[method] = _safe_error(exc, secret_values)
        inventory = _inventory_from_results(
            server_id,
            "stdio",
            initialize,
            results,
            secret_values=secret_values,
            launch_identity=_stdio_launch_identity(
                executable,
                args,
                env or {},
                binary_sha256=binary_sha256,
                binary_size=binary_size,
                secret_values=secret_values,
            ),
        )
        issues.extend(audit_inventory(inventory))
        issues.extend(_collection_issues(server_id, initialize, optional_errors))
        required_failures = _required_collection_failures(initialize, optional_errors)
        status = "incomplete" if required_failures else "complete"
        probe_result = LiveProbeResult(
            status=status,
            inventory=inventory,
            issues=_dedupe_issues(issues),
        )
        return probe_result
    except Exception as exc:
        error = _safe_error(exc, secret_values)
        probe_result = LiveProbeResult(
            status="error",
            issues=_dedupe_issues(
                issues
                + [
                    _issue(
                        "MCP-LIVE-FAILED",
                        "medium",
                        "Live MCP probe failed",
                        error,
                        server_id,
                    )
                ]
            ),
            error=error,
            stderr=stderr_text,
        )
        return probe_result
    finally:
        if process is not None:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except Exception:
                    pass
            if process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            try:
                _, stderr = await asyncio.wait_for(process.communicate(), timeout=1.5)
                stderr_text = _scrub_text(
                    stderr[:_MAX_STDERR_BYTES].decode("utf-8", errors="replace"),
                    secret_values,
                    max_chars=_MAX_STDERR_BYTES,
                )
            except Exception:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await process.wait()
                except Exception:
                    pass
            if probe_result is not None:
                probe_result.stderr = stderr_text


def inventory_from_dict(value: Mapping[str, Any]) -> MCPInventory:
    def load_items(key: str, kind: str) -> List[InventoryItem]:
        raw = value.get(key, [])
        if not isinstance(raw, list):
            return []
        return [
            _normalise_item(str(item.get("kind") or kind), item)
            for item in raw
            if isinstance(item, Mapping)
        ]

    server_info = _bounded_clean(value.get("server_info") or {})
    capabilities = _bounded_clean(value.get("capabilities") or {})
    launch_identity = _bounded_clean(value.get("launch_identity") or {})
    try:
        captured_at = float(value.get("captured_at") or time.time())
        if captured_at != captured_at or abs(captured_at) == float("inf"):
            raise ValueError
    except (TypeError, ValueError):
        captured_at = time.time()

    inventory = MCPInventory(
        server_id=_scrub_text(value.get("server_id") or "unknown", max_chars=256),
        transport=_scrub_text(value.get("transport") or "unknown", max_chars=32),
        protocol_version=_scrub_text(
            value.get("protocol_version") or MCP_PROTOCOL_VERSION,
            max_chars=128,
        ),
        server_info=dict(server_info) if isinstance(server_info, Mapping) else {},
        capabilities=(dict(capabilities) if isinstance(capabilities, Mapping) else {}),
        tools=load_items("tools", "tool"),
        prompts=load_items("prompts", "prompt"),
        resources=load_items("resources", "resource"),
        captured_at=captured_at,
        launch_identity=(
            dict(launch_identity) if isinstance(launch_identity, Mapping) else {}
        ),
    )
    return inventory


def save_trusted_snapshot(
    inventory: MCPInventory,
    path: Path,
    *,
    trust: bool = False,
    signing_key: Optional[bytes] = None,
) -> None:
    """Atomically write a baseline only after an explicit trust decision."""

    if not trust:
        raise PermissionError(
            "A first observation is not trusted automatically; pass trust=True"
        )
    payload: Dict[str, Any] = {
        "schema_version": 2,
        "trusted_at": time.time(),
        "fingerprint": inventory.fingerprint,
        "inventory": {**inventory.canonical(), "captured_at": inventory.captured_at},
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if signing_key:
        payload["hmac_sha256"] = hmac.new(
            signing_key, canonical, hashlib.sha256
        ).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, path)


def load_trusted_snapshot(
    path: Path,
    *,
    signing_key: Optional[bytes] = None,
) -> MCPInventory:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("inventory"), dict):
        raise ValueError("Invalid MCP snapshot")
    schema_version = value.get("schema_version", 1)
    if schema_version not in {1, 2}:
        raise ValueError("Unsupported MCP snapshot schema")
    supplied = value.get("hmac_sha256")
    unsigned = dict(value)
    unsigned.pop("hmac_sha256", None)
    canonical = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if signing_key:
        expected = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        if not supplied or not hmac.compare_digest(str(supplied), expected):
            raise ValueError("MCP snapshot signature is missing or invalid")
    inventory = inventory_from_dict(value["inventory"])
    if schema_version == 1:
        legacy_inventory = dict(value["inventory"])
        legacy_inventory.pop("captured_at", None)
        legacy_payload = json.dumps(
            legacy_inventory,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        observed_fingerprint = hashlib.sha256(legacy_payload).hexdigest()
    else:
        observed_fingerprint = inventory.fingerprint
    if observed_fingerprint != value.get("fingerprint"):
        raise ValueError("MCP snapshot fingerprint does not match its inventory")
    return inventory


def diff_inventory(
    trusted: MCPInventory,
    current: MCPInventory,
) -> List[RuntimeIssue]:
    issues: List[RuntimeIssue] = []
    if trusted.server_id != current.server_id:
        issues.append(
            _issue(
                "MCP-DRIFT-IDENTITY",
                "critical",
                "MCP server identity changed",
                f"Trusted {trusted.server_id!r}, observed {current.server_id!r}.",
                current.server_id,
            )
        )
    if trusted.transport != current.transport:
        issues.append(
            _issue(
                "MCP-DRIFT-TRANSPORT",
                "critical",
                "MCP transport changed",
                f"Trusted {trusted.transport!r}, observed {current.transport!r}.",
                current.server_id,
                remediation="Re-establish transport trust and explicitly approve a new snapshot.",
            )
        )
    if trusted.protocol_version != current.protocol_version:
        issues.append(
            _issue(
                "MCP-DRIFT-PROTOCOL",
                "medium",
                "MCP protocol version changed",
                f"{trusted.protocol_version} -> {current.protocol_version}",
                current.server_id,
            )
        )
    trusted_server_info = _bounded_clean(trusted.server_info)
    current_server_info = _bounded_clean(current.server_info)
    if trusted_server_info != current_server_info:
        issues.append(
            _issue(
                "MCP-DRIFT-SERVER-INFO",
                "high",
                "MCP server metadata changed",
                "The server name, version, or other published identity metadata differs from trust.",
                current.server_id,
                evidence={
                    "before": trusted_server_info,
                    "after": current_server_info,
                },
            )
        )
    trusted_launch = _bounded_clean(trusted.launch_identity)
    current_launch = _bounded_clean(current.launch_identity)
    if trusted_launch != current_launch:
        trusted_digest = (
            trusted_launch.get("binary_sha256")
            if isinstance(trusted_launch, Mapping)
            else None
        )
        current_digest = (
            current_launch.get("binary_sha256")
            if isinstance(current_launch, Mapping)
            else None
        )
        if trusted_digest and current_digest and trusted_digest != current_digest:
            issues.append(
                _issue(
                    "MCP-DRIFT-BINARY",
                    "critical",
                    "MCP executable digest changed",
                    "The launched server binary differs from the trusted executable digest.",
                    current.server_id,
                    remediation="Quarantine the executable and review its provenance before retrusting it.",
                )
            )
        trusted_nonbinary = (
            {
                key: value
                for key, value in trusted_launch.items()
                if key not in {"binary_sha256", "binary_size"}
            }
            if isinstance(trusted_launch, Mapping)
            else trusted_launch
        )
        current_nonbinary = (
            {
                key: value
                for key, value in current_launch.items()
                if key not in {"binary_sha256", "binary_size"}
            }
            if isinstance(current_launch, Mapping)
            else current_launch
        )
        if trusted_nonbinary != current_nonbinary or not (
            trusted_digest and current_digest
        ):
            issues.append(
                _issue(
                    "MCP-DRIFT-LAUNCH",
                    "high",
                    "MCP launch identity changed",
                    "The sanitized endpoint, executable, arguments, or environment identity differs from trust.",
                    current.server_id,
                    remediation="Review the launch configuration and explicitly approve a new snapshot.",
                )
            )
    if _bounded_clean(trusted.capabilities) != _bounded_clean(current.capabilities):
        issues.append(
            _issue(
                "MCP-DRIFT-CAPABILITY",
                "high",
                "MCP capabilities changed",
                "The server's advertised capability set differs from the trusted snapshot.",
                current.server_id,
                evidence={
                    "before": _bounded_clean(trusted.capabilities),
                    "after": _bounded_clean(current.capabilities),
                },
            )
        )

    def flatten(inventory: MCPInventory) -> Dict[Tuple[str, str], InventoryItem]:
        return {
            (item.kind, item.name.casefold()): item
            for item in [*inventory.tools, *inventory.prompts, *inventory.resources]
        }

    before = flatten(trusted)
    after = flatten(current)
    for key in sorted(after.keys() - before.keys()):
        item = after[key]
        issues.append(
            _issue(
                "MCP-DRIFT-ADDED",
                "high" if item.kind == "tool" else "medium",
                f"MCP {item.kind} added after trust",
                f"New {item.kind} {item.name!r} was not present in the trusted inventory.",
                f"{current.server_id}.{item.kind}.{item.name}",
            )
        )
    for key in sorted(before.keys() - after.keys()):
        item = before[key]
        issues.append(
            _issue(
                "MCP-DRIFT-REMOVED",
                "medium",
                f"MCP {item.kind} removed after trust",
                f"Trusted {item.kind} {item.name!r} is no longer published.",
                f"{current.server_id}.{item.kind}.{item.name}",
            )
        )
    for key in sorted(before.keys() & after.keys()):
        old = before[key]
        new = after[key]
        if old.canonical() != new.canonical():
            old_canonical = old.canonical()
            new_canonical = new.canonical()
            changed = [
                field_name
                for field_name in sorted(old_canonical.keys() | new_canonical.keys())
                if field_name not in {"kind", "name"}
                and old_canonical.get(field_name) != new_canonical.get(field_name)
            ]
            issues.append(
                _issue(
                    "MCP-DRIFT-MODIFIED",
                    "high",
                    f"MCP {new.kind} changed after trust",
                    f"{new.name!r} changed fields: {', '.join(changed)}.",
                    f"{current.server_id}.{new.kind}.{new.name}",
                    evidence={"changed_fields": changed},
                    remediation="Re-review the implementation and explicitly approve a new snapshot.",
                )
            )
    return _dedupe_issues(issues)


def _dedupe_issues(issues: Iterable[RuntimeIssue]) -> List[RuntimeIssue]:
    seen: set[Tuple[str, str, str]] = set()
    result: List[RuntimeIssue] = []
    for issue in issues:
        key = (issue.rule_id, issue.location, issue.detail)
        if key not in seen:
            seen.add(key)
            result.append(issue)
    return result


__all__ = [
    "InventoryItem",
    "LiveProbeResult",
    "MCPInventory",
    "MCP_PROTOCOL_VERSION",
    "RuntimeIssue",
    "audit_inventory",
    "audit_inventory_item",
    "audit_annotation_behavior",
    "audit_server_config",
    "detect_tool_shadowing",
    "diff_inventory",
    "inventory_from_dict",
    "load_trusted_snapshot",
    "probe_http_server",
    "probe_stdio_server",
    "save_trusted_snapshot",
]
