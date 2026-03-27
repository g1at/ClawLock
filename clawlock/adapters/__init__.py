"""
Adapter layer — detects and abstracts ZeroClaw, OpenClaw, Claude Code,
and generic Claw products. added memory_files, credential_dirs.
"""
from __future__ import annotations
import json, shutil, subprocess
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


def load_config(adapter: AdapterSpec) -> Tuple[Dict[str, Any], Optional[str]]:
    for cp in adapter.config_paths:
        p = Path(cp).expanduser()
        if p.exists():
            try: return json.loads(p.read_text()), str(p)
            except Exception: pass
    return {}, None
