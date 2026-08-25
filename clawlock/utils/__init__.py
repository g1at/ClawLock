"""
ClawLock platform utilities — cross-platform abstraction for
Windows, macOS, Linux, and Android (Termux).
"""

from __future__ import annotations
import os
import platform
import re
import sqlite3
import stat
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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

_DEFAULT_COMMAND_OUTPUT_LIMIT = 1024 * 1024
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)


class CommandOutputTruncated(RuntimeError):
    """An external command exceeded ClawLock's capture budget."""

    def __init__(self, command: Sequence[str], limit: int):
        self.command = tuple(command)
        self.limit = limit
        super().__init__(
            f"external command output exceeded the {limit}-byte safety limit"
        )


@dataclass(frozen=True)
class BoundedCommandResult:
    """Small, compatibility-friendly result returned by ``run_bounded_command``."""

    args: List[str]
    returncode: int
    stdout: str
    stderr: str


def _is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is lexically inside *root*, case-insensitively on NT."""
    try:
        path_text = os.path.normcase(os.path.abspath(os.fspath(path)))
        root_text = os.path.normcase(os.path.abspath(os.fspath(root)))
        return os.path.commonpath((path_text, root_text)) == root_text
    except (OSError, ValueError):
        return False


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _trusted_binary_candidate(
    candidate: Path,
    *,
    untrusted_roots: Sequence[Path],
) -> Optional[str]:
    """Validate without following a final symlink/reparse point."""
    if not candidate.is_absolute():
        return None
    lexical = Path(os.path.abspath(os.fspath(candidate)))
    if _is_link_or_reparse(lexical):
        return None
    try:
        canonical = Path(os.path.realpath(os.fspath(lexical)))
    except OSError:
        return None
    if any(
        _is_within(lexical, root)
        or _is_within(canonical, Path(os.path.realpath(os.fspath(root))))
        for root in untrusted_roots
    ):
        return None
    try:
        info = lexical.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return str(lexical)


def _binary_name_candidates(name: str) -> List[str]:
    if not IS_WINDOWS:
        return [name]
    suffixes = [
        item.strip()
        for item in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
        if re.fullmatch(r"\.[A-Za-z0-9]+", item.strip())
    ]
    if not suffixes:
        suffixes = [".COM", ".EXE", ".BAT", ".CMD"]
    if Path(name).suffix:
        return [name]
    return [f"{name}{suffix.lower()}" for suffix in suffixes] + [
        f"{name}{suffix.upper()}" for suffix in suffixes
    ]


def resolve_trusted_binary(
    name: str,
    *,
    path: Optional[str] = None,
    untrusted_roots: Optional[Sequence[Path]] = None,
) -> Optional[str]:
    """Resolve an executable without current-directory or link hijacking.

    Unlike ``shutil.which`` on Windows, this resolver never searches the
    current directory implicitly. Empty and relative PATH entries are ignored,
    and candidates inside the working (normally scanned) repository are
    rejected. Explicit absolute paths go through the same validation.
    """
    raw = str(name or "").strip().strip('"')
    if not raw:
        return None
    roots = [Path(root) for root in (untrusted_roots or ())]
    try:
        roots.append(Path.cwd())
    except OSError:
        pass

    supplied = Path(raw).expanduser()
    has_separator = any(separator in raw for separator in (os.sep, os.altsep) if separator)
    # Backslashes are separators even when tests emulate Windows on POSIX.
    has_separator = has_separator or "\\" in raw
    if supplied.is_absolute():
        return _trusted_binary_candidate(supplied, untrusted_roots=roots)
    if has_separator:
        return None

    path_value = os.environ.get("PATH", "") if path is None else path
    seen = set()
    for entry in path_value.split(os.pathsep):
        clean = entry.strip().strip('"')
        if not clean:
            continue
        directory = Path(clean).expanduser()
        if not directory.is_absolute():
            continue
        for binary_name in _binary_name_candidates(raw):
            candidate = directory / binary_name
            marker = os.path.normcase(os.path.abspath(os.fspath(candidate)))
            if marker in seen:
                continue
            seen.add(marker)
            resolved = _trusted_binary_candidate(candidate, untrusted_roots=roots)
            if resolved:
                return resolved
    return None


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    trailing = ""
    while raw and raw[-1] in ".,;)]}":
        trailing = raw[-1] + trailing
        raw = raw[:-1]
    try:
        parsed = urlsplit(raw)
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = "[REDACTED]@" + netloc.rsplit("@", 1)[1]
        query = urlencode(
            [(key, "[REDACTED]") for key, _value in parse_qsl(parsed.query, keep_blank_values=True)]
        )
        fragment = "[REDACTED]" if parsed.fragment else ""
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment)) + trailing
    except (TypeError, ValueError):
        return "[REDACTED-URL]" + trailing


def scrub_command_diagnostic(value: object, *, max_chars: int = 500) -> str:
    """Remove common credentials before surfacing child-process diagnostics."""
    text = str(value or "")
    text = _URL.sub(_redact_url, text)
    text = re.sub(
        r"(?i)\bauthorization\s*[:=]\s*(?:bearer\s+)?[^\s,;]+",
        "Authorization: [REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer [REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(\b[A-Za-z_][A-Za-z0-9_.-]*(?:key|token|secret|password|passwd|auth|credential)[A-Za-z0-9_.-]*\s*=\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)([\"']?[A-Za-z_][A-Za-z0-9_.-]*(?:key|token|secret|password|passwd|auth|credential)[A-Za-z0-9_.-]*[\"']?\s*:\s*)"
        r"(?:\"[^\"]*\"|'[^']*')",
        r"\1\"[REDACTED]\"",
        text,
    )
    return text.strip()[:max_chars]


def run_bounded_command(
    command: Sequence[str],
    *,
    timeout: float,
    max_output_bytes: int = _DEFAULT_COMMAND_OUTPUT_LIMIT,
    cwd: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> BoundedCommandResult:
    """Execute with bounded streaming capture and fail closed on truncation."""
    if not command:
        raise ValueError("external command is empty")
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes must be positive")
    untrusted_roots = [Path(cwd)] if cwd is not None else None
    binary = resolve_trusted_binary(
        str(command[0]), untrusted_roots=untrusted_roots
    )
    if binary is None:
        raise FileNotFoundError(f"untrusted or unavailable executable: {command[0]}")
    actual = [binary, *(str(item) for item in command[1:])]
    process = subprocess.Popen(
        actual,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        shell=False,
    )
    buffers = [bytearray(), bytearray()]
    truncated = [False, False]
    reader_errors: List[BaseException] = []

    def drain(index: int, stream) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                remaining = max_output_bytes - len(buffers[index])
                if remaining > 0:
                    buffers[index].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated[index] = True
        except BaseException as exc:  # pragma: no cover - exceptional OS pipe failure
            reader_errors.append(exc)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=drain, args=(0, process.stdout), daemon=True),
        threading.Thread(target=drain, args=(1, process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(timeout=2)
        raise subprocess.TimeoutExpired(actual, timeout) from exc
    for thread in threads:
        thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads) or reader_errors:
        raise RuntimeError("external command output stream could not be drained safely")
    if any(truncated):
        raise CommandOutputTruncated(actual, max_output_bytes)
    return BoundedCommandResult(
        args=actual,
        returncode=returncode,
        stdout=bytes(buffers[0]).decode("utf-8", errors="replace"),
        stderr=bytes(buffers[1]).decode("utf-8", errors="replace"),
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


def _run_system_probe(command: List[str], probe_name: str) -> BoundedCommandResult:
    """Run an OS inventory command without turning failure into an empty result."""
    try:
        result = run_bounded_command(
            command,
            timeout=10,
            max_output_bytes=2 * 1024 * 1024,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"{probe_name} probe unavailable: command not found: {command[0]}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{probe_name} probe timed out while running {command[0]}"
        ) from exc
    except CommandOutputTruncated as exc:
        raise RuntimeError(
            f"{probe_name} probe output exceeded its safety limit"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"{probe_name} probe could not start {command[0]}: "
            f"{scrub_command_diagnostic(exc, max_chars=240)}"
        ) from exc

    if result.returncode != 0:
        detail = scrub_command_diagnostic(
            result.stderr or result.stdout or "no diagnostic output", max_chars=240
        )
        raise RuntimeError(
            f"{probe_name} probe failed (exit {result.returncode}): {detail}"
        )
    return result


def list_processes() -> List[Dict[str, str]]:
    """Return running processes, or raise if OS inventory was incomplete."""
    procs: List[Dict[str, str]] = []
    if IS_WINDOWS:
        result = _run_system_probe(
            ["tasklist", "/FO", "CSV", "/NH"], "process inventory"
        )
        for line in result.stdout.splitlines():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                procs.append({"cmd": parts[0], "pid": parts[1], "user": ""})
    else:
        result = _run_system_probe(
            ["ps", "aux"] if not IS_ANDROID else ["ps", "-e"],
            "process inventory",
        )
        for line in result.stdout.splitlines()[1:]:  # skip header
            parts = line.split(None, 10)
            if len(parts) >= 2:
                procs.append(
                    {
                        "user": parts[0],
                        "pid": parts[1],
                        "cmd": parts[-1] if len(parts) > 2 else parts[1],
                    }
                )
    return procs


def list_listening_ports() -> List[str]:
    """Return exposed listeners, or raise if OS inventory was incomplete."""
    lines: List[str] = []
    if IS_WINDOWS:
        result = _run_system_probe(["netstat", "-ano"], "listening-port inventory")
        for line in result.stdout.splitlines():
            if "LISTENING" in line and "0.0.0.0" in line:
                lines.append(line.strip())
    elif IS_MACOS:
        result = _run_system_probe(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"],
            "listening-port inventory",
        )
        for line in result.stdout.splitlines():
            if "*:" in line or "0.0.0.0:" in line:
                lines.append(line.strip())
    else:
        command = next(
            (
                candidate
                for candidate in (["ss", "-tlnp"], ["netstat", "-tlnp"])
                if find_binary(candidate[0])
            ),
            None,
        )
        if command is None:
            raise RuntimeError(
                "listening-port inventory probe unavailable: neither ss nor "
                "netstat was found"
            )
        result = _run_system_probe(command, "listening-port inventory")
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line:
                lines.append(line.strip())
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
        r = run_bounded_command(
            ["icacls", str(path)],
            timeout=10,
            max_output_bytes=1024 * 1024,
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
        # Permission hardening must never follow a link outside the expected
        # credential tree.  Callers can surface the refusal and ask the user to
        # inspect the link manually.
        if not path.exists() or path.is_symlink():
            return False
        if IS_WINDOWS:
            username = os.environ.get("USERNAME", "").strip()
            if not username:
                return False
            # Use well-known SIDs instead of localized account names for the
            # broad principals.  Most importantly, check icacls' return code:
            # the old implementation reported success even on a partial/failed
            # ACL rewrite.
            result = run_bounded_command(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:(F)",
                    "/remove:g",
                    "*S-1-1-0",       # Everyone
                    "*S-1-5-32-545",  # BUILTIN\\Users
                ],
                timeout=10,
                max_output_bytes=1024 * 1024,
            )
            return result.returncode == 0

        target_mode = 0o700 if path.is_dir() else 0o600
        os.chmod(path, target_mode)
        import stat

        return stat.S_IMODE(path.stat().st_mode) == target_mode
    except Exception:
        return False


# Stable identity used by hardening's dependency-injection compatibility path.
# A caller that replaces ``fix_file_permission`` with a dry-run callback should
# not cause the callback's unit test to execute real ACL snapshot commands.
_SYSTEM_FIX_FILE_PERMISSION = fix_file_permission


def capture_file_permission(
    path: Path, snapshot_path: Optional[Path] = None
) -> Optional[Dict[str, object]]:
    """Capture enough permission state to restore *path* later.

    Unix stores the exact mode bits in the hardening action log.  Windows uses
    ``icacls /save`` and stores the durable ACL snapshot path plus its restore
    root.  Symlinks are rejected so a privileged hardening run cannot be
    redirected outside the intended tree.
    """
    try:
        if not path.exists() or path.is_symlink():
            return None
        if IS_WINDOWS:
            if snapshot_path is None:
                return None
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            result = run_bounded_command(
                [
                    "icacls",
                    path.name,
                    "/save",
                    str(snapshot_path),
                    "/c",
                    "/q",
                ],
                cwd=str(path.parent),
                timeout=10,
                max_output_bytes=1024 * 1024,
            )
            if (
                result.returncode != 0
                or not snapshot_path.exists()
                or snapshot_path.stat().st_size == 0
            ):
                return None
            return {
                "platform": "windows",
                "acl_file": str(snapshot_path),
                "restore_root": str(path.parent),
            }

        import stat

        return {
            "platform": "unix",
            "mode": stat.S_IMODE(path.stat().st_mode),
        }
    except Exception:
        return None


def restore_file_permission(path: Path, snapshot: Dict[str, object]) -> bool:
    """Restore a permission snapshot created by ``capture_file_permission``."""
    try:
        if not path.exists() or path.is_symlink():
            return False
        platform_name = str(snapshot.get("platform", ""))
        if platform_name == "windows":
            acl_file = Path(str(snapshot.get("acl_file", "")))
            restore_root = Path(str(snapshot.get("restore_root", "")))
            if not acl_file.is_file() or not restore_root.is_dir():
                return False
            result = run_bounded_command(
                [
                    "icacls",
                    str(restore_root),
                    "/restore",
                    str(acl_file),
                    "/c",
                    "/q",
                ],
                timeout=10,
                max_output_bytes=1024 * 1024,
            )
            return result.returncode == 0
        if platform_name != "unix":
            return False

        mode = int(snapshot["mode"])
        os.chmod(path, mode)
        import stat

        return stat.S_IMODE(path.stat().st_mode) == mode
    except Exception:
        return False


# ─── Binary discovery (cross-platform) ───────────────────────────────────────


def find_binary(name: str) -> Optional[str]:
    """Find a trusted binary in PATH, returning an absolute regular file."""
    return resolve_trusted_binary(name)


def find_all_binaries(names: List[str]) -> Dict[str, Optional[str]]:
    """Find multiple binaries."""
    return {name: find_binary(name) for name in names}


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
    score INTEGER DEFAULT NULL,
    critical INTEGER NOT NULL DEFAULT 0,
    warning INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'complete',
    partial_score INTEGER DEFAULT NULL
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


def _migrate_scan_history_schema(conn: sqlite3.Connection) -> None:
    """Upgrade pre-status history databases without losing old records."""
    columns = {
        row[1]: row for row in conn.execute("PRAGMA table_info(scans)").fetchall()
    }
    score_column = columns.get("score")

    # SQLite cannot remove a NOT NULL constraint in place. Rebuild only the
    # legacy scans table; explicit ids preserve the findings foreign keys.
    if score_column is not None and bool(score_column[3]):
        complete_expr = "complete" if "complete" in columns else "1"
        status_expr = "status" if "status" in columns else "'complete'"
        partial_score_expr = (
            "partial_score" if "partial_score" in columns else "NULL"
        )
        foreign_keys_enabled = bool(conn.execute("PRAGMA foreign_keys").fetchone()[0])
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DROP TABLE IF EXISTS scans_v2")
            conn.execute(
                """
                CREATE TABLE scans_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT NOT NULL,
                    adapter TEXT NOT NULL DEFAULT '',
                    device TEXT NOT NULL DEFAULT '',
                    score INTEGER DEFAULT NULL,
                    critical INTEGER NOT NULL DEFAULT 0,
                    warning INTEGER NOT NULL DEFAULT 0,
                    total INTEGER NOT NULL DEFAULT 0,
                    complete INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'complete',
                    partial_score INTEGER DEFAULT NULL
                )
                """
            )
            conn.execute(
                f"""
                INSERT INTO scans_v2 (
                    id, time, adapter, device, score, critical, warning, total,
                    complete, status, partial_score
                )
                SELECT
                    id, time, adapter, device, score, critical, warning, total,
                    {complete_expr}, {status_expr}, {partial_score_expr}
                FROM scans
                """
            )
            conn.execute("DROP TABLE scans")
            conn.execute("ALTER TABLE scans_v2 RENAME TO scans")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(time)")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            if foreign_keys_enabled:
                conn.execute("PRAGMA foreign_keys = ON")
        columns = {
            row[1]: row
            for row in conn.execute("PRAGMA table_info(scans)").fetchall()
        }

    additions = {
        "complete": "INTEGER NOT NULL DEFAULT 1",
        "status": "TEXT NOT NULL DEFAULT 'complete'",
        "partial_score": "INTEGER DEFAULT NULL",
    }
    for name, declaration in additions.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {declaration}")


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
        _migrate_scan_history_schema(conn)
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
                        "INSERT INTO scans ("
                        "time, adapter, device, score, critical, warning, total, complete, status"
                        ") VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            str(r.get("time", "")),
                            str(r.get("adapter", "")),
                            str(r.get("device", "")),
                            int(r.get("score", 0)),
                            int(r.get("critical", 0)),
                            int(r.get("warning", 0)),
                            int(r.get("total", 0)),
                            1,
                            "complete",
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
    score: int | None,
    critical: int,
    warning: int,
    findings_total: int,
    findings_summary: list | None = None,
    *,
    complete: bool = True,
    status: str | None = None,
    partial_score: int | None = None,
):
    """Append a scan result to persistent history (SQLite-backed)."""
    import json as _json
    from datetime import datetime

    _import_legacy_history_once()
    normalized_status = status or ("complete" if complete else "incomplete")
    persisted_score = int(score) if complete and score is not None else None
    persisted_partial_score = (
        int(partial_score) if partial_score is not None else None
    )
    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans ("
                "time, adapter, device, score, critical, warning, total, "
                "complete, status, partial_score"
                ") VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    datetime.now().isoformat(),
                    adapter,
                    device_fingerprint(),
                    persisted_score,
                    int(critical),
                    int(warning),
                    int(findings_total),
                    int(complete),
                    normalized_status,
                    persisted_partial_score,
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
                    "SELECT id, time, adapter, device, score, critical, warning, total, "
                    "complete, status, partial_score "
                    "FROM scans ORDER BY id DESC LIMIT ?",
                    (int(limit),),
                )
            )
    except Exception:
        return out
    for row in reversed(rows):
        (
            scan_id,
            t_iso,
            adapter,
            device,
            score,
            critical,
            warning,
            total,
            complete,
            status,
            partial_score,
        ) = row
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
                "complete": bool(complete),
                "status": status or ("complete" if complete else "incomplete"),
                "partial_score": partial_score,
                "findings": findings,
            }
        )
    return out
