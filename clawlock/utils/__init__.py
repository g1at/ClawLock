"""
ClawLock platform utilities — cross-platform abstraction for
Windows, macOS, Linux, and Android (Termux).
"""

from __future__ import annotations
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─── Platform detection ───────────────────────────────────────────────────────

SYSTEM = platform.system().lower()  # "linux", "darwin", "windows", "linux" (android)
IS_WINDOWS = SYSTEM == "windows"
IS_MACOS = SYSTEM == "darwin"
IS_LINUX = SYSTEM == "linux"
IS_ANDROID = IS_LINUX and (
    "ANDROID_ROOT" in os.environ
    or "TERMUX_VERSION" in os.environ
    or Path("/data/data/com.termux").exists()
)


def platform_label() -> str:
    if IS_ANDROID:
        return "Android (Termux)"
    if IS_WINDOWS:
        return f"Windows {platform.release()}"
    if IS_MACOS:
        return f"macOS {platform.mac_ver()[0]}"
    return f"Linux {platform.release()}"


# ─── Temp directory (cross-platform) ─────────────────────────────────────────


def temp_path(filename: str) -> Path:
    """Return a cross-platform temp file path."""
    return Path(tempfile.gettempdir()) / filename


# ─── Process detection (cross-platform) ──────────────────────────────────────


def list_processes() -> List[Dict[str, str]]:
    """Return list of running processes as [{pid, user, cmd}]."""
    procs: List[Dict[str, str]] = []
    try:
        if IS_WINDOWS:
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        procs.append({"cmd": parts[0], "pid": parts[1], "user": ""})
        else:
            r = subprocess.run(
                ["ps", "aux"] if not IS_ANDROID else ["ps", "-e"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines()[1:]:  # skip header
                    parts = line.split(None, 10)
                    if len(parts) >= 2:
                        procs.append(
                            {
                                "user": parts[0],
                                "pid": parts[1],
                                "cmd": parts[-1] if len(parts) > 2 else parts[1],
                            }
                        )
    except Exception:
        pass
    return procs


def list_listening_ports() -> List[str]:
    """Return lines describing ports listening on 0.0.0.0 / all interfaces."""
    lines: List[str] = []
    try:
        if IS_WINDOWS:
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "LISTENING" in line and "0.0.0.0" in line:
                        lines.append(line.strip())
        elif IS_MACOS:
            r = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "*:" in line or "0.0.0.0:" in line:
                        lines.append(line.strip())
        else:
            # Linux / Android
            for cmd in [["ss", "-tlnp"], ["netstat", "-tlnp"]]:
                if shutil.which(cmd[0]):
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if r.returncode == 0:
                        for line in r.stdout.splitlines():
                            if "0.0.0.0" in line:
                                lines.append(line.strip())
                        break
    except Exception:
        pass
    return lines


# ─── File permission check (cross-platform) ──────────────────────────────────


def check_file_permission(path: Path) -> Tuple[bool, bool, str]:
    """
    Check if a file/directory is overly permissive.
    Returns (is_world_readable, is_group_readable, human_description).
    """
    if not path.exists():
        return False, False, "not found"

    if IS_WINDOWS:
        return _check_perm_windows(path)
    else:
        return _check_perm_unix(path)


def _check_perm_unix(path: Path) -> Tuple[bool, bool, str]:
    import stat

    try:
        mode = path.stat().st_mode
        world_r = bool(mode & stat.S_IROTH)
        group_r = bool(mode & stat.S_IRGRP)
        return world_r, group_r, oct(mode)
    except Exception:
        return False, False, "unknown"


def _check_perm_windows(path: Path) -> Tuple[bool, bool, str]:
    """Use icacls on Windows to check ACLs."""
    try:
        r = subprocess.run(
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0:
            output = r.stdout.lower()
            # "everyone" or "users" with read access = world-readable
            world_r = "everyone" in output and (
                "(r)" in output
                or "(f)" in output
                or "(rx)" in output
                or "(oi)" in output
            )
            # "builtin\\users" = group-readable equivalent
            group_r = "users" in output and ("(r)" in output or "(rx)" in output)
            return world_r, group_r, r.stdout.strip()[:100]
    except Exception:
        pass
    return False, False, "unknown"


def fix_file_permission(path: Path, private: bool = True) -> bool:
    """
    Fix file permissions to be private (owner-only).
    On Unix: chmod 700 (dir) or 600 (file).
    On Windows: icacls to remove Everyone/Users access.
    """
    try:
        if IS_WINDOWS:
            # Remove inheritance + remove Everyone/Users
            subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{os.environ.get('USERNAME', 'User')}:(F)",
                    "/remove",
                    "Everyone",
                    "/remove",
                    "Users",
                ],
                capture_output=True,
                timeout=10,
            )
            return True
        else:
            if path.is_dir():
                os.chmod(path, 0o700)
            else:
                os.chmod(path, 0o600)
            return True
    except Exception:
        return False


# ─── Binary discovery (cross-platform) ───────────────────────────────────────


def find_binary(name: str) -> Optional[str]:
    """Find a binary in PATH, cross-platform."""
    return shutil.which(name)


def find_all_binaries(names: List[str]) -> Dict[str, Optional[str]]:
    """Find multiple binaries."""
    return {name: shutil.which(name) for name in names}


# ─── Device fingerprint (privacy-preserving) ────────────────────────────────


def device_fingerprint() -> str:
    """
    Generate a privacy-preserving device fingerprint.
    SHA-256 of (hostname + OS + username), truncated to 12 hex chars.
    Used for enterprise multi-machine scan tracking and report correlation.
    """
    import hashlib
    import getpass

    raw = f"{platform.node()}|{platform.system()}|{platform.release()}|{getpass.getuser()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ─── Scan history persistence ────────────────────────────────────────────────

HISTORY_FILE = Path.home() / ".clawlock" / "scan_history.json"
_HISTORY_CACHE: list | None = None
_HISTORY_CACHE_PATH: Path | None = None


def _history_cache_matches() -> bool:
    return _HISTORY_CACHE_PATH == HISTORY_FILE


def _load_history() -> list:
    global _HISTORY_CACHE, _HISTORY_CACHE_PATH

    if _HISTORY_CACHE is not None and _history_cache_matches():
        return list(_HISTORY_CACHE)

    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if HISTORY_FILE.exists():
            import json

            _HISTORY_CACHE = json.loads(HISTORY_FILE.read_text())
            _HISTORY_CACHE_PATH = HISTORY_FILE
            return list(_HISTORY_CACHE)
    except Exception:
        pass

    _HISTORY_CACHE = []
    _HISTORY_CACHE_PATH = HISTORY_FILE
    return []


def _save_history(records: list):
    global _HISTORY_CACHE, _HISTORY_CACHE_PATH
    import json

    cached = list(records[-100:])
    _HISTORY_CACHE = cached
    _HISTORY_CACHE_PATH = HISTORY_FILE

    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_FILE.write_text(json.dumps(cached, ensure_ascii=False, indent=2))
    except Exception:
        # Persistence is best-effort; scans should still succeed when the
        # runtime cannot write to the user's home directory.
        return False
    return True


def record_scan(
    adapter: str,
    score: int,
    critical: int,
    warning: int,
    findings_total: int,
    findings_summary: list | None = None,
):
    """Append a scan result to persistent history."""
    from datetime import datetime

    records = _load_history()
    entry = {
        "time": datetime.now().isoformat(),
        "adapter": adapter,
        "device": device_fingerprint(),
        "score": score,
        "critical": critical,
        "warning": warning,
        "total": findings_total,
    }
    if findings_summary is not None:
        entry["findings"] = findings_summary
    records.append(entry)
    _save_history(records)


def get_scan_history(limit: int = 20) -> list:
    """Return last N scan records."""
    return _load_history()[-limit:]
