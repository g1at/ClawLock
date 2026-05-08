"""
ClawLock platform utilities — cross-platform abstraction for
Windows, macOS, Linux, and Android (Termux).
"""

from __future__ import annotations
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import contextmanager
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
#
# Storage is SQLite (``~/.clawlock/clawlock.db``). Concurrent ``clawlock``
# processes can append safely thanks to WAL mode and SQLite's own locking,
# something the previous JSON-on-disk implementation could not guarantee.
# ``HISTORY_FILE`` is kept as a module attribute pointing at the legacy JSON
# location so test fixtures and the one-off importer can still address it.

HISTORY_FILE = Path.home() / ".clawlock" / "scan_history.json"
DB_PATH = Path.home() / ".clawlock" / "clawlock.db"
_LEGACY_IMPORTED_FLAG = Path.home() / ".clawlock" / ".history-imported"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    adapter TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT '',
    score INTEGER NOT NULL DEFAULT 0,
    critical INTEGER NOT NULL DEFAULT 0,
    warning INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(time);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'info',
    location TEXT NOT NULL DEFAULT '',
    measure_ids TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_level ON findings(level);
"""


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        for stmt in _SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)
        yield conn
    finally:
        conn.close()


def _import_legacy_history_once() -> None:
    """One-time import of any existing ``scan_history.json`` into SQLite.

    Idempotent: presence of ``.history-imported`` marker (or a missing legacy
    file) skips re-import. The legacy file is renamed to ``.imported`` so it
    survives as a backup but does not get re-ingested.
    """
    import json as _json

    if _LEGACY_IMPORTED_FLAG.exists():
        return
    legacy = HISTORY_FILE
    if not legacy.exists():
        try:
            _LEGACY_IMPORTED_FLAG.parent.mkdir(parents=True, exist_ok=True)
            _LEGACY_IMPORTED_FLAG.touch()
        except Exception:
            pass
        return
    try:
        records = _json.loads(legacy.read_text(encoding="utf-8"))
    except Exception:
        records = []
    if isinstance(records, list):
        try:
            with _connect() as conn:
                for r in records:
                    if not isinstance(r, dict):
                        continue
                    cur = conn.execute(
                        "INSERT INTO scans (time, adapter, device, score, critical, warning, total) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (
                            str(r.get("time", "")),
                            str(r.get("adapter", "")),
                            str(r.get("device", "")),
                            int(r.get("score", 0)),
                            int(r.get("critical", 0)),
                            int(r.get("warning", 0)),
                            int(r.get("total", 0)),
                        ),
                    )
                    scan_id = cur.lastrowid
                    for f in r.get("findings", []) or []:
                        if not isinstance(f, dict):
                            continue
                        conn.execute(
                            "INSERT INTO findings (scan_id, title, level, location, measure_ids) "
                            "VALUES (?,?,?,?,?)",
                            (
                                scan_id,
                                str(f.get("title", "")),
                                str(f.get("level", "info")),
                                str(f.get("location", "")),
                                _json.dumps(f.get("measure_ids", []) or [], ensure_ascii=False),
                            ),
                        )
        except Exception:
            return
    try:
        legacy.rename(legacy.with_suffix(".json.imported"))
    except Exception:
        pass
    try:
        _LEGACY_IMPORTED_FLAG.touch()
    except Exception:
        pass


def record_scan(
    adapter: str,
    score: int,
    critical: int,
    warning: int,
    findings_total: int,
    findings_summary: list | None = None,
):
    """Append a scan result to persistent history (SQLite-backed)."""
    import json as _json
    from datetime import datetime

    _import_legacy_history_once()
    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (time, adapter, device, score, critical, warning, total) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    datetime.now().isoformat(),
                    adapter,
                    device_fingerprint(),
                    int(score),
                    int(critical),
                    int(warning),
                    int(findings_total),
                ),
            )
            scan_id = cur.lastrowid
            for f in findings_summary or []:
                if not isinstance(f, dict):
                    continue
                conn.execute(
                    "INSERT INTO findings (scan_id, title, level, location, measure_ids) "
                    "VALUES (?,?,?,?,?)",
                    (
                        scan_id,
                        str(f.get("title", "")),
                        str(f.get("level", "info")),
                        str(f.get("location", "")),
                        _json.dumps(f.get("measure_ids", []) or [], ensure_ascii=False),
                    ),
                )
    except Exception:
        # Persistence is best-effort; scans should still succeed even if the
        # SQLite write fails (read-only home, locked DB, etc.).
        return False
    return True


def get_scan_history(limit: int = 20) -> list:
    """Return last N scan records, oldest-first (matches legacy JSON order)."""
    import json as _json

    _import_legacy_history_once()
    out: list = []
    try:
        with _connect() as conn:
            rows = list(
                conn.execute(
                    "SELECT id, time, adapter, device, score, critical, warning, total "
                    "FROM scans ORDER BY id DESC LIMIT ?",
                    (int(limit),),
                )
            )
    except Exception:
        return out
    for row in reversed(rows):
        scan_id, t_iso, adapter, device, score, critical, warning, total = row
        findings: list = []
        try:
            with _connect() as conn:
                for f in conn.execute(
                    "SELECT title, level, location, measure_ids FROM findings WHERE scan_id = ?",
                    (scan_id,),
                ):
                    title, level, location, measure_ids_json = f
                    entry = {"title": title, "level": level, "location": location}
                    try:
                        ids = _json.loads(measure_ids_json or "[]")
                        if ids:
                            entry["measure_ids"] = ids
                    except Exception:
                        pass
                    findings.append(entry)
        except Exception:
            findings = []
        out.append(
            {
                "time": t_iso,
                "adapter": adapter,
                "device": device,
                "score": score,
                "critical": critical,
                "warning": warning,
                "total": total,
                "findings": findings,
            }
        )
    return out
