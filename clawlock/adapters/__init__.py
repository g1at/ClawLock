"""
Adapter layer — detects and abstracts ZeroClaw, OpenClaw, Claude Code,
and generic Claw products. added memory_files, credential_dirs.
"""

from __future__ import annotations
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from ..utils import IS_ANDROID, IS_MACOS, IS_WINDOWS, find_binary


@dataclass
class AdapterSpec:
    name: str
    display: str
    bin: Optional[str]
    version_cmd: Optional[List[str]]
    audit_cmd: Optional[List[str]]
    list_skills_cmd: Optional[List[str]]
    config_paths: List[str] = field(default_factory=list)
    skills_dirs: List[str] = field(default_factory=list)
    mcp_configs: List[str] = field(default_factory=list)
    soul_filenames: List[str] = field(default_factory=lambda: ["SOUL.md", "CLAUDE.md"])
    memory_files: List[str] = field(default_factory=list)
    credential_dirs: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class CveLookupTarget:
    product: str
    version: str


ADAPTERS: Dict[str, AdapterSpec] = {
    "openclaw": AdapterSpec(
        "openclaw",
        "OpenClaw",
        "openclaw",
        ["openclaw", "--version"],
        ["openclaw", "security", "audit", "--deep"],
        ["openclaw", "skills", "list"],
        ["~/.openclaw/openclaw.json", "~/.config/openclaw/config.json"],
        ["~/.openclaw/skills", "~/.config/openclaw/skills"],
        ["~/.openclaw/mcp_config.json", "~/.openclaw/mcp.json"],
        ["SOUL.md"],
        ["~/.openclaw/HEARTBEAT.md", "~/.openclaw/MEMORY.md", "~/.openclaw/memory"],
        ["~/.openclaw/credentials", "~/.openclaw/auth", "~/.openclaw"],
        ["openclaw", "node"],
    ),
    "zeroclaw": AdapterSpec(
        "zeroclaw",
        "ZeroClaw",
        "zeroclaw",
        ["zeroclaw", "--version"],
        ["zeroclaw", "audit"],
        ["zeroclaw", "skill", "list"],
        ["~/.zeroclaw/config.json", "~/.config/zeroclaw/config.json"],
        ["~/.zeroclaw/skills"],
        ["~/.zeroclaw/mcp.json"],
        ["SOUL.md"],
        ["~/.zeroclaw/MEMORY.md", "~/.zeroclaw/memory"],
        ["~/.zeroclaw/credentials", "~/.zeroclaw"],
        ["zeroclaw"],
    ),
    "claude-code": AdapterSpec(
        "claude-code",
        "Claude Code",
        "claude",
        ["claude", "--version"],
        None,
        None,
        ["~/.claude/settings.json", "~/.config/claude/settings.json"],
        ["~/.claude/skills"],
        ["~/.claude/claude_desktop_config.json", "~/.claude/mcp.json"],
        ["CLAUDE.md", "SOUL.md"],
        ["~/.claude/MEMORY.md", "~/.claude/memory"],
        ["~/.claude/credentials", "~/.claude"],
        ["claude"],
    ),
    "generic": AdapterSpec(
        "generic",
        "Generic Claw",
        None,
        None,
        None,
        None,
        [],
        [],
        [".mcp.json", "mcp.json"],
        ["SOUL.md", "CLAUDE.md", "AGENT.md"],
        ["MEMORY.md", "HEARTBEAT.md"],
        [],
        [],
    ),
}
_CVE_PRODUCT_NAMES: Dict[str, str] = {
    "openclaw": "OpenClaw",
    "zeroclaw": "ZeroClaw",
    "claude-code": "Claude Code",
}
_UNKNOWN_VERSION_MARKERS = {"", "unknown", "n/a", "none", "not installed"}
_VERSION_COMMANDS: Dict[str, List[List[str]]] = {
    "openclaw": [["openclaw", "--version"], ["openclaw", "-V"], ["openclaw", "-v"]],
    "zeroclaw": [
        ["zeroclaw", "--version"],
        ["zeroclaw", "-v"],
        ["zeroclaw", "version"],
    ],
}


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.returncode, r.stdout.strip(), r.stderr.strip())
    except FileNotFoundError:
        return (-1, "", f"not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except Exception as e:
        return (-1, "", str(e))


def _binary_search_roots(adapter: AdapterSpec) -> List[Path]:
    home = Path.home()
    roots: List[Path] = []
    if IS_WINDOWS:
        for label in {adapter.display, adapter.name, adapter.bin or ""}:
            if label:
                roots.extend(
                    [
                        home / "AppData" / "Local" / "Programs" / label,
                        home / "AppData" / "Local" / "Programs" / label / "bin",
                    ]
                )
        roots.extend(
            [
                home / "AppData" / "Roaming" / "npm",
                home / "scoop" / "shims",
                home / "AppData" / "Local" / "Microsoft" / "WinGet" / "Links",
            ]
        )
        return roots
    roots.extend(
        [
            home / ".local" / "bin",
            home / ".npm-global" / "bin",
            home / ".yarn" / "bin",
            home / ".bun" / "bin",
            home / "bin",
            Path("/usr/local/bin"),
            Path("/usr/bin"),
        ]
    )
    if IS_MACOS:
        roots.extend([Path("/opt/homebrew/bin"), Path("/opt/local/bin")])
    elif IS_ANDROID:
        roots.insert(0, Path("/data/data/com.termux/files/usr/bin"))
    else:
        roots.append(Path("/snap/bin"))
    return roots


def _candidate_binary_names(bin_name: str) -> List[str]:
    if not bin_name:
        return []
    names = [bin_name]
    if IS_WINDOWS and "." not in Path(bin_name).name:
        names.extend([f"{bin_name}.exe", f"{bin_name}.cmd", f"{bin_name}.bat"])
    return names


def _resolve_binary_path(adapter: AdapterSpec) -> Optional[str]:
    if not adapter.bin:
        return None
    path = find_binary(adapter.bin)
    if path:
        return path
    for root in _binary_search_roots(adapter):
        for name in _candidate_binary_names(adapter.bin):
            candidate = root / name
            if candidate.exists():
                return str(candidate)
    return None


def detect_adapter() -> AdapterSpec:
    for spec in ADAPTERS.values():
        if spec.bin and _resolve_binary_path(spec):
            return spec
    return ADAPTERS["generic"]


def get_adapter(name: str) -> AdapterSpec:
    return (
        detect_adapter() if name == "auto" else ADAPTERS.get(name, ADAPTERS["generic"])
    )


def _version_commands(adapter: AdapterSpec, binary_path: str) -> List[List[str]]:
    commands = _VERSION_COMMANDS.get(adapter.name, [])
    if adapter.version_cmd:
        commands = commands + [adapter.version_cmd]
    resolved: List[List[str]] = []
    seen = set()
    for cmd in commands:
        actual = list(cmd)
        if not actual:
            continue
        actual[0] = binary_path
        key = tuple(actual)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(actual)
    return resolved


def _extract_version(output: str) -> Optional[str]:
    for line in output.splitlines():
        normalized = _normalize_version(line)
        if normalized:
            return normalized
    return None


def get_claw_version(adapter: AdapterSpec) -> str:
    if not adapter.version_cmd:
        return "unknown"
    binary_path = _resolve_binary_path(adapter)
    if not binary_path:
        return "unknown"
    for cmd in _version_commands(adapter, binary_path):
        _, out, err = run_cmd(cmd)
        version = _extract_version(out) or _extract_version(err)
        if version:
            return version
    return "unknown"


def _normalize_version(version: str) -> Optional[str]:
    raw = (version or "").strip()
    if not raw or raw.lower() in _UNKNOWN_VERSION_MARKERS:
        return None
    match = re.search("\\d+(?:\\.\\d+){0,3}(?:[-+._A-Za-z0-9]+)?", raw)
    return match.group(0) if match else None


def _adapter_has_installation(adapter: AdapterSpec) -> bool:
    if adapter.bin and _resolve_binary_path(adapter):
        return True
    paths = adapter.config_paths + adapter.credential_dirs
    return any((Path(p).expanduser().exists() for p in paths))


def resolve_cve_lookup(
    adapter: AdapterSpec, version: str
) -> Tuple[Optional[CveLookupTarget], str]:
    product = _CVE_PRODUCT_NAMES.get(adapter.name)
    if not product:
        return (
            None,
            "No supported Claw product detected. Online CVE matching was skipped.",
        )
    if not _adapter_has_installation(adapter):
        return (
            None,
            "No installed Claw product detected. Online CVE matching was skipped.",
        )
    normalized_version = _normalize_version(version)
    if not normalized_version:
        return (
            None,
            f"Could not identify the {product} version. Online CVE matching was skipped.",
        )
    return (CveLookupTarget(product=product, version=normalized_version), "")


def load_config(adapter: AdapterSpec) -> Tuple[Dict[str, Any], Optional[str]]:
    for cp in adapter.config_paths:
        p = Path(cp).expanduser()
        if p.exists():
            try:
                return (json.loads(p.read_text()), str(p))
            except Exception:
                pass
    return ({}, None)
