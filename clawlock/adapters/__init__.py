"""
Adapter layer — detects and abstracts ZeroClaw, OpenClaw, Claude Code,
and generic Claw products. added memory_files, credential_dirs.
"""
from __future__ import annotations
import json, re, shutil, subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AdapterSpec:
    name: str; display: str; bin: Optional[str]
    version_cmd: Optional[List[str]]; audit_cmd: Optional[List[str]]
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
    "openclaw": AdapterSpec("openclaw", "OpenClaw", "openclaw",
        ["openclaw", "--version"], ["openclaw", "security", "audit", "--deep"],
        ["openclaw", "skills", "list"],
        ["~/.openclaw/openclaw.json", "~/.config/openclaw/config.json"],
        ["~/.openclaw/skills", "~/.config/openclaw/skills"],
        ["~/.openclaw/mcp_config.json", "~/.openclaw/mcp.json"],
        ["SOUL.md"],
        ["~/.openclaw/HEARTBEAT.md", "~/.openclaw/MEMORY.md", "~/.openclaw/memory"],
        ["~/.openclaw/credentials", "~/.openclaw/auth", "~/.openclaw"],
        ["openclaw", "node"],
    ),
    "zeroclaw": AdapterSpec("zeroclaw", "ZeroClaw", "zeroclaw",
        ["zeroclaw", "version"], ["zeroclaw", "audit"], ["zeroclaw", "skill", "list"],
        ["~/.zeroclaw/config.json", "~/.config/zeroclaw/config.json"],
        ["~/.zeroclaw/skills"], ["~/.zeroclaw/mcp.json"], ["SOUL.md"],
        ["~/.zeroclaw/MEMORY.md", "~/.zeroclaw/memory"],
        ["~/.zeroclaw/credentials", "~/.zeroclaw"],
        ["zeroclaw"],
    ),
    "claude-code": AdapterSpec("claude-code", "Claude Code", "claude",
        ["claude", "--version"], None, None,
        ["~/.claude/settings.json", "~/.config/claude/settings.json"],
        ["~/.claude/skills"],
        ["~/.claude/claude_desktop_config.json", "~/.claude/mcp.json"],
        ["CLAUDE.md", "SOUL.md"],
        ["~/.claude/MEMORY.md", "~/.claude/memory"],
        ["~/.claude/credentials", "~/.claude"],
        ["claude"],
    ),
    "generic": AdapterSpec("generic", "Generic Claw", None,
        None, None, None, [], [], [".mcp.json", "mcp.json"],
        ["SOUL.md", "CLAUDE.md", "AGENT.md"],
        ["MEMORY.md", "HEARTBEAT.md"], [], [],
    ),
}

_CVE_PRODUCT_NAMES: Dict[str, str] = {
    "openclaw": "OpenClaw",
    "zeroclaw": "ZeroClaw",
    "claude-code": "Claude Code",
}
_UNKNOWN_VERSION_MARKERS = {"", "unknown", "n/a", "none", "not installed"}


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError: return -1, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired: return -1, "", "timeout"
    except Exception as e: return -1, "", str(e)


def detect_adapter() -> AdapterSpec:
    for spec in ADAPTERS.values():
        if spec.bin and shutil.which(spec.bin): return spec
    return ADAPTERS["generic"]


def get_adapter(name: str) -> AdapterSpec:
    return detect_adapter() if name == "auto" else ADAPTERS.get(name, ADAPTERS["generic"])


def get_claw_version(adapter: AdapterSpec) -> str:
    if not adapter.version_cmd: return "unknown"
    _, out, _ = run_cmd(adapter.version_cmd)
    return out.splitlines()[0] if out else "unknown"


def _normalize_version(version: str) -> Optional[str]:
    raw = (version or "").strip()
    if not raw or raw.lower() in _UNKNOWN_VERSION_MARKERS:
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}(?:[-+._A-Za-z0-9]+)?", raw)
    return match.group(0) if match else None


def _adapter_has_installation(adapter: AdapterSpec) -> bool:
    if adapter.bin and shutil.which(adapter.bin):
        return True
    paths = adapter.config_paths + adapter.credential_dirs
    return any(Path(p).expanduser().exists() for p in paths)


def resolve_cve_lookup(adapter: AdapterSpec, version: str) -> Tuple[Optional[CveLookupTarget], str]:
    product = _CVE_PRODUCT_NAMES.get(adapter.name)
    if not product:
        return None, "未识别到受支持的 Claw 产品，已跳过在线 CVE 匹配。"
    if not _adapter_has_installation(adapter):
        return None, "未发现已安装的 Claw 产品，已跳过在线 CVE 匹配。"
    normalized_version = _normalize_version(version)
    if not normalized_version:
        return None, f"未能识别 {product} 的版本号，已跳过在线 CVE 匹配。"
    return CveLookupTarget(product=product, version=normalized_version), ""


def load_config(adapter: AdapterSpec) -> Tuple[Dict[str, Any], Optional[str]]:
    for cp in adapter.config_paths:
        p = Path(cp).expanduser()
        if p.exists():
            try: return json.loads(p.read_text()), str(p)
            except Exception: pass
    return {}, None
