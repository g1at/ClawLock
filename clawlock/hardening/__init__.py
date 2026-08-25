from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from ..i18n import t
from ..utils import IS_ANDROID, IS_MACOS, IS_WINDOWS, platform_label

console = Console()

# ─── Backup / rollback infrastructure ────────────────────────────────────────

HARDENING_LOG = Path.home() / ".clawlock" / "hardening_log.json"
_DEFAULT_HARDENING_LOG = HARDENING_LOG
_LOG_VERSION = 2
_ACTION_ID_RE = re.compile(
    r"^[a-z0-9]+-\d{8}T\d{6}_\d{6}-[0-9a-f]{12}$"
)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_CREDENTIAL_SUFFIXES = {".json", ".key", ".pem", ".token", ".env", ".rc"}


class HardeningLogError(RuntimeError):
    """The rollback journal is malformed or points outside trusted storage."""


def _hardening_log_path() -> Path:
    """Resolve the default lazily while honoring an explicitly overridden path."""
    if HARDENING_LOG != _DEFAULT_HARDENING_LOG:
        return HARDENING_LOG
    return Path.home() / ".clawlock" / "hardening_log.json"


def _backup_root() -> Path:
    return Path.home() / ".clawlock" / "backups"


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_elevated() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            # The trust boundary cannot be established, so callers must fail
            # closed instead of consuming a user-writable rollback journal.
            return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _trusted_for_elevated_rollback(log_path: Path) -> bool:
    if not _is_elevated():
        return True
    if IS_WINDOWS:
        # A journal in the interactive user's profile remains writable by the
        # same account before elevation.  Until a high-integrity storage backend
        # exists, elevated rollback must not trust it.
        return False
    try:
        expected_uid = os.geteuid()
        for candidate in (log_path, log_path.parent, _backup_root()):
            if not candidate.exists() or candidate.is_symlink():
                return False
            info = candidate.stat()
            if info.st_uid != expected_uid or info.st_mode & 0o022:
                return False
        return True
    except Exception:
        return False


def _file_digest(path: Path) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def _windows_replace_file(source: Path, destination: Path, flags: int = 0) -> None:
    """Replace an existing Windows file while preserving its DACL/metadata."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    replace_file.restype = wintypes.BOOL
    if not replace_file(
        str(_absolute_path(destination)),
        str(_absolute_path(source)),
        None,
        flags,
        None,
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _replace_path(source: Path, destination: Path) -> None:
    """Atomically replace a path, preserving metadata on existing Windows files."""
    if IS_WINDOWS and destination.exists():
        _windows_replace_file(source, destination, flags=0)
    else:
        os.replace(source, destination)


def _atomic_write_json(
    path: Path,
    value: Any,
    *,
    expected_digest: Optional[str] = None,
) -> bool:
    """Atomically replace *path* with validated JSON.

    The temporary file lives beside the destination, so ``os.replace`` remains
    atomic.  ``expected_digest`` prevents overwriting a config that changed
    after the transaction prepared its backup.
    """
    temp_path: Optional[Path] = None
    try:
        if path.is_symlink():
            return False
        if expected_digest is not None:
            if not path.is_file() or _file_digest(path) != expected_digest:
                return False

        encoded = json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        # Validate the exact bytes before they can replace the destination.
        if json.loads(encoded) != value:
            return False

        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        temp_path = Path(temp_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

        if path.exists():
            shutil.copymode(path, temp_path)
        elif os.name != "nt":
            os.chmod(temp_path, 0o600)

        # Validate the on-disk temporary file and re-check the source immediately
        # before replacement to narrow the concurrent-update window.
        if json.loads(temp_path.read_text(encoding="utf-8")) != value:
            return False
        if expected_digest is not None and _file_digest(path) != expected_digest:
            return False

        _replace_path(temp_path, path)
        temp_path = None
        return json.loads(path.read_text(encoding="utf-8")) == value
    except Exception:
        return False
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _credential_directories() -> List[Path]:
    home = Path.home()
    return [
        home / ".openclaw",
        home / ".zeroclaw",
        home / ".claude",
        home / ".config" / "openclaw",
        home / ".config" / "zeroclaw",
        home / ".config" / "claude",
    ]


def _allowed_hardening_target(path: Path) -> bool:
    """Restrict journal-controlled writes to documented ClawLock targets."""
    try:
        target = _absolute_path(path)
        home = _absolute_path(Path.home())
        resolved_home = home.resolve(strict=True)
        resolved_target = target.resolve(strict=False)
        if not _is_within(resolved_target, resolved_home):
            return False
        if target.exists() and target.is_symlink():
            return False

        exact = {
            _absolute_path(candidate)
            for candidates in _known_config_paths().values()
            for candidate in candidates
        }
        directories = {_absolute_path(item) for item in _credential_directories()}
        exact.update(directories)
        exact.update(
            {
                _absolute_path(home / ".npmrc"),
                _absolute_path(home / ".pypirc"),
                _absolute_path(home / ".netrc"),
            }
        )
        if target in exact:
            return True
        return target.parent in directories and target.suffix in _CREDENTIAL_SUFFIXES
    except Exception:
        return False


def _path_in_action_dir(path: Path, action_id: str) -> bool:
    try:
        candidate = _absolute_path(path)
        root = _absolute_path(_backup_root())
        action_dir = _absolute_path(root / action_id)
        if not _is_within(candidate, action_dir):
            return False
        for storage_component in (root.parent, root, action_dir):
            if storage_component.exists() and storage_component.is_symlink():
                return False
        if candidate.exists() and candidate.is_symlink():
            return False
        resolved_root = root.resolve(strict=False)
        resolved_action = action_dir.resolve(strict=False)
        resolved_candidate = candidate.resolve(strict=False)
        default_root = _absolute_path(
            Path.home() / ".clawlock" / "backups"
        )
        if root == default_root:
            # Preserve the home boundary for the built-in location so a
            # symlink/reparse escape in the storage path remains fail-closed.
            resolved_home = _absolute_path(Path.home()).resolve(strict=True)
            if not _is_within(resolved_root, resolved_home):
                return False
        # An explicitly injected root (for example a POSIX /tmp test root) is
        # its own trust anchor.  Every candidate must still remain inside its
        # action directory after resolution.
        return (
            _is_within(resolved_action, resolved_root)
            and _is_within(resolved_candidate, resolved_action)
        )
    except Exception:
        return False


def _permission_snapshot_digest(snapshot: Dict[str, object]) -> Optional[str]:
    try:
        if snapshot.get("platform") == "windows":
            return _file_digest(Path(str(snapshot["acl_file"])))
        if snapshot.get("platform") == "unix":
            return _canonical_digest(snapshot)
    except Exception:
        pass
    return None


def _validate_action_record(entry: object) -> bool:
    if not isinstance(entry, dict) or set(entry) != {
        "version",
        "id",
        "time",
        "measure",
        "status",
        "files",
        "permissions",
    }:
        return False
    action_id = entry.get("id")
    if entry.get("version") != _LOG_VERSION or not isinstance(action_id, str):
        return False
    if not _ACTION_ID_RE.fullmatch(action_id):
        return False
    if not isinstance(entry.get("time"), str):
        return False
    try:
        datetime.fromisoformat(entry["time"])
    except (TypeError, ValueError):
        return False
    if not isinstance(entry.get("measure"), str) or not re.fullmatch(
        r"H\d{3}", entry["measure"]
    ):
        return False
    if entry.get("status") not in {"pending", "committed"}:
        return False

    files = entry.get("files")
    permissions = entry.get("permissions")
    if not isinstance(files, dict) or not isinstance(permissions, dict):
        return False
    if len(files) > 100 or len(permissions) > 100:
        return False

    for original, metadata in files.items():
        if not isinstance(original, str) or not _allowed_hardening_target(Path(original)):
            return False
        if not isinstance(metadata, dict) or set(metadata) != {"backup", "digest"}:
            return False
        backup = metadata.get("backup")
        digest = metadata.get("digest")
        if not isinstance(backup, str) or not _path_in_action_dir(
            Path(backup), action_id
        ):
            return False
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            return False

    for original, metadata in permissions.items():
        if not isinstance(original, str) or not _allowed_hardening_target(Path(original)):
            return False
        if not isinstance(metadata, dict) or set(metadata) != {"snapshot", "digest"}:
            return False
        snapshot = metadata.get("snapshot")
        digest = metadata.get("digest")
        if not isinstance(snapshot, dict) or not isinstance(digest, str):
            return False
        if not _DIGEST_RE.fullmatch(digest):
            return False
        platform_name = snapshot.get("platform")
        if platform_name == "windows":
            if set(snapshot) != {"platform", "acl_file", "restore_root"}:
                return False
            acl_file = snapshot.get("acl_file")
            restore_root = snapshot.get("restore_root")
            if not isinstance(acl_file, str) or not _path_in_action_dir(
                Path(acl_file), action_id
            ):
                return False
            if not isinstance(restore_root, str):
                return False
            if _absolute_path(Path(restore_root)) != _absolute_path(
                Path(original).parent
            ):
                return False
        elif platform_name == "unix":
            if set(snapshot) != {"platform", "mode"}:
                return False
            if not isinstance(snapshot.get("mode"), int) or not 0 <= snapshot["mode"] <= 0o7777:
                return False
        else:
            return False
    return True


def _validate_log(records: object) -> List[dict]:
    if not isinstance(records, list) or len(records) > 200:
        raise HardeningLogError("invalid rollback journal container")
    if not all(_validate_action_record(entry) for entry in records):
        raise HardeningLogError("invalid rollback journal record")
    return records


def _load_hardening_log() -> list:
    log_path = _hardening_log_path()
    if not log_path.exists():
        return []
    try:
        if log_path.is_symlink() or log_path.stat().st_size > 2 * 1024 * 1024:
            raise HardeningLogError("unsafe rollback journal")
        return _validate_log(json.loads(log_path.read_text(encoding="utf-8")))
    except HardeningLogError:
        raise
    except Exception as exc:
        raise HardeningLogError("unreadable rollback journal") from exc


def _save_hardening_log(records: list) -> bool:
    log_path = _hardening_log_path()
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(log_path.parent, 0o700)
        validated = _validate_log(records[-200:])
        return _atomic_write_json(log_path, validated)
    except Exception:
        return False


def _new_action_id(measure_id: str) -> str:
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S_%f")
    return f"{measure_id.lower()}-{stamp}-{uuid.uuid4().hex[:12]}"


def _action_backup_dir(action_id: str) -> Path:
    if not _ACTION_ID_RE.fullmatch(action_id):
        raise ValueError("invalid hardening action id")
    backup_dir = _backup_root() / action_id
    backup_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(backup_dir, 0o700)
    return backup_dir


def _backup_file(path: Path, action_id: Optional[str] = None) -> Optional[Path]:
    """Create and verify a unique backup before modification."""
    if not path.is_file() or path.is_symlink():
        return None
    try:
        action_id = action_id or _new_action_id("manual")
        backup_dir = _action_backup_dir(action_id)
        path_key = hashlib.sha256(
            str(path.absolute()).encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:16]
        backup_path = backup_dir / f"{path_key}-{path.name}.bak"
        if backup_path.exists():
            backup_path = backup_dir / (
                f"{path_key}-{uuid.uuid4().hex[:12]}-{path.name}.bak"
            )
        shutil.copy2(path, backup_path)
        source_digest = _file_digest(path)
        if source_digest is None or _file_digest(backup_path) != source_digest:
            backup_path.unlink(missing_ok=True)
            return None
        return backup_path
    except Exception:
        return None


def _record_hardening_action(
    measure_id: str,
    files_changed: Dict[str, object],
    permissions_changed: Optional[Dict[str, Dict[str, object]]] = None,
    *,
    action_id: Optional[str] = None,
    status: str = "committed",
) -> bool:
    """Record an auto-fix action with backup paths for rollback."""
    action_id = action_id or _new_action_id(measure_id)
    try:
        normalized_files: Dict[str, Dict[str, str]] = {}
        for original, raw_metadata in files_changed.items():
            if isinstance(raw_metadata, dict):
                backup = str(raw_metadata["backup"])
                digest = str(raw_metadata["digest"])
            else:
                backup = str(raw_metadata)
                digest = _file_digest(Path(backup)) or ""
            normalized_files[str(original)] = {"backup": backup, "digest": digest}

        normalized_permissions: Dict[str, Dict[str, object]] = {}
        for original, snapshot in (permissions_changed or {}).items():
            if set(snapshot) == {"snapshot", "digest"}:
                normalized_permissions[str(original)] = dict(snapshot)
            else:
                digest = _permission_snapshot_digest(snapshot)
                normalized_permissions[str(original)] = {
                    "snapshot": dict(snapshot),
                    "digest": digest or "",
                }

        entry = {
            "version": _LOG_VERSION,
            "id": action_id,
            "time": datetime.now().isoformat(),
            "measure": measure_id,
            "status": status,
            "files": normalized_files,
            "permissions": normalized_permissions,
        }
        if not _validate_action_record(entry):
            return False
        log = _load_hardening_log()
        log.append(entry)
        return _save_hardening_log(log)
    except (HardeningLogError, KeyError, TypeError, ValueError):
        return False


def _set_action_status(action_id: str, status: str) -> bool:
    try:
        log = _load_hardening_log()
        for entry in reversed(log):
            if entry.get("id") == action_id:
                entry["status"] = status
                return _save_hardening_log(log)
    except HardeningLogError:
        return False
    return False


def _get_action_record(action_id: str) -> Optional[dict]:
    try:
        for entry in reversed(_load_hardening_log()):
            if entry.get("id") == action_id:
                return entry
    except HardeningLogError:
        pass
    return None


def _remove_action(action_id: str) -> bool:
    try:
        log = _load_hardening_log()
        filtered = [entry for entry in log if entry.get("id") != action_id]
    except HardeningLogError:
        return False
    if len(filtered) == len(log):
        return False
    return _save_hardening_log(filtered)


def _restore_file_from_backup(original: Path, backup: Path) -> bool:
    temp_path: Optional[Path] = None
    try:
        if not backup.is_file() or backup.is_symlink() or original.is_symlink():
            return False
        expected = _file_digest(backup)
        if expected is None:
            return False
        original.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{original.name}.", suffix=".rollback", dir=str(original.parent)
        )
        os.close(fd)
        temp_path = Path(temp_name)
        shutil.copy2(backup, temp_path)
        if _file_digest(temp_path) != expected:
            return False
        _replace_path(temp_path, original)
        temp_path = None
        return _file_digest(original) == expected
    except Exception:
        return False
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


def _restore_action(entry: dict) -> Tuple[List[str], List[str]]:
    """Restore one grouped action; return (restored paths, failed paths)."""
    from ..utils import restore_file_permission

    restored: List[str] = []
    failed: List[str] = []
    if not _validate_action_record(entry):
        return restored, ["<invalid rollback action>"]
    files = entry.get("files", {})
    for original, metadata in files.items():
        backup = Path(metadata["backup"])
        expected_digest = metadata["digest"]
        if _file_digest(backup) != expected_digest:
            failed.append(str(original))
            continue
        if _restore_file_from_backup(Path(original), backup):
            restored.append(str(original))
        else:
            failed.append(str(original))

    permissions = entry.get("permissions", {})
    for original, metadata in permissions.items():
        snapshot = metadata["snapshot"]
        if _permission_snapshot_digest(snapshot) != metadata["digest"]:
            failed.append(str(original))
            continue
        if restore_file_permission(Path(original), snapshot):
            restored.append(str(original))
        else:
            failed.append(str(original))
    return restored, failed


def rollback_last(count: int = 1) -> int:
    """Rollback the last N hardening actions. Returns number of files restored."""
    log_path = _hardening_log_path()
    if log_path.exists() and not _trusted_for_elevated_rollback(log_path):
        console.print(
            f"  [red]{t('提权回滚拒绝使用不可信用户日志', 'Elevated rollback refused an untrusted user journal')}[/red]"
        )
        return 0
    try:
        log = _load_hardening_log()
    except HardeningLogError:
        console.print(
            f"  [red]{t('回滚日志无效；已拒绝执行', 'Rollback journal is invalid; refusing to continue')}[/red]"
        )
        return 0
    restored = 0
    for _ in range(min(count, len(log))):
        entry = log[-1]
        restored_paths, failed_paths = _restore_action(entry)
        for original in restored_paths:
            console.print(
                f"  [green]{t('已还原', 'Restored')}: {original}[/green]"
            )
        for original in failed_paths:
            console.print(
                f"  [red]{t('还原失败', 'Restore failed')}: {original}[/red]"
            )
        if failed_paths:
            # Keep the entire grouped entry so a later rollback can retry every
            # member.  Successful members are safe to restore idempotently.
            break

        candidate_log = log[:-1]
        if not _save_hardening_log(candidate_log):
            # The on-disk log still contains the action because log writes are
            # atomic.  Do not claim it was consumed; a retry is safe.
            console.print(
                f"  [red]{t('回滚日志更新失败；操作记录已保留', 'Rollback log update failed; action retained')}[/red]"
            )
            break
        log = candidate_log
        restored += len(set(restored_paths))
    return restored


TextValue = Union[str, Callable[[], str]]


@dataclass
class HardenMeasure:
    id: str
    title: TextValue
    desc: TextValue
    ux_impact: TextValue
    apply: Callable[[], bool]
    adapters: List[str]
    platforms: List[str] = field(default_factory=list)
    auto_fixable: bool = False
    guidance_only: bool = True


def _text(value: TextValue) -> str:
    return value() if callable(value) else value


def _tr(zh: str, en: str) -> Callable[[], str]:
    return lambda: t(zh, en)


def _g(msg: str):
    console.print(f"  [dim]{msg}[/dim]")


def _guide(*steps: TextValue) -> bool:
    shown = False
    for step in steps:
        text = _text(step)
        if not text:
            continue
        _g(text)
        shown = True
    return shown


def _current_platform_tags() -> set[str]:
    if IS_WINDOWS:
        return {"windows"}
    if IS_MACOS:
        return {"macos"}
    if IS_ANDROID:
        return {"android", "android-termux", "linux"}
    return {"linux"}


def _platform_matches(measure: HardenMeasure) -> bool:
    if not measure.platforms:
        return True
    return bool(_current_platform_tags().intersection(measure.platforms))


def _persistence_guidance() -> bool:
    if IS_WINDOWS:
        return _guide(
            _tr(
                "检查 schtasks 与 Run/RunOnce 注册表键中的异常持久化项。",
                "Review schtasks and Run/RunOnce registry keys for unexpected persistence.",
            ),
            _tr(
                "删除未使用的计划任务和自启动注册表项，只保留有文档说明的自动化。",
                "Delete unused scheduled tasks and autoruns; keep only documented automation.",
            ),
            _tr(
                "在重新创建后台任务前要求人工审批。",
                "Require manual approval before recreating background tasks.",
            ),
        )
    if IS_MACOS:
        return _guide(
            _tr(
                "检查 ~/Library/LaunchAgents、/Library/LaunchAgents 与 launchctl 列表中的异常条目。",
                "Review ~/Library/LaunchAgents, /Library/LaunchAgents, and launchctl output for unexpected entries.",
            ),
            _tr(
                "移除未使用的 LaunchAgent，只保留明确记录用途的后台任务。",
                "Remove unused LaunchAgents and keep only documented background jobs.",
            ),
            _tr(
                "在从 skill 或 prompt 重新建立持久化任务前要求人工审批。",
                "Require manual approval before rebuilding persistence from skills or prompts.",
            ),
        )
    if IS_ANDROID:
        return _guide(
            _tr(
                "检查 ~/.termux/boot 与 termux-job-scheduler 任务中是否存在异常启动脚本。",
                "Review ~/.termux/boot and termux-job-scheduler jobs for unexpected startup scripts.",
            ),
            _tr(
                "删除未使用的 Termux 启动脚本和后台任务，只保留明确记录用途的自动化。",
                "Delete unused Termux boot scripts and background jobs; keep only documented automation.",
            ),
            _tr(
                "在重新创建 Termux 持久化任务前要求人工审批。",
                "Require manual approval before recreating Termux persistence.",
            ),
        )
    return _guide(
        _tr(
            "检查 ~/.config/systemd/user、systemctl --user 与 crontab 中的异常持久化项。",
            "Review ~/.config/systemd/user, systemctl --user, and crontab for unexpected persistence.",
        ),
        _tr(
            "删除未使用的 systemd 用户级单元和 cron 任务，只保留有文档说明的自动化。",
            "Delete unused user-level systemd units and cron jobs; keep only documented automation.",
        ),
        _tr(
            "在从 skill 或 prompt 重新创建后台任务前要求人工审批。",
            "Require manual approval before re-creating background tasks from skills or prompts.",
        ),
    )


def _fix_cred_perms(
    *,
    permission_capturer: Optional[
        Callable[[Path, Optional[Path]], Optional[Dict[str, object]]]
    ] = None,
    permission_fixer: Optional[Callable[[Path, bool], bool]] = None,
):
    from ..utils import (
        _SYSTEM_FIX_FILE_PERMISSION,
        capture_file_permission,
        check_file_permission,
        fix_file_permission,
    )

    fixer = permission_fixer or fix_file_permission
    capturer = permission_capturer
    if capturer is None and fixer is _SYSTEM_FIX_FILE_PERMISSION:
        capturer = capture_file_permission

    targets: List[Path] = []
    credential_dirs = [
        Path.home() / ".openclaw",
        Path.home() / ".zeroclaw",
        Path.home() / ".claude",
        Path.home() / ".config" / "openclaw",
        Path.home() / ".config" / "zeroclaw",
        Path.home() / ".config" / "claude",
    ]
    for directory in credential_dirs:
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            _g(
                f"{t('拒绝跟随凭证目录符号链接', 'Refusing credential-directory symlink')}: {directory}"
            )
            return False
        targets.append(directory)
        for candidate in directory.iterdir():
            if candidate.suffix not in (
                ".json",
                ".key",
                ".pem",
                ".token",
                ".env",
                ".rc",
            ):
                continue
            if candidate.is_symlink():
                _g(
                    f"{t('拒绝跟随凭证文件符号链接', 'Refusing credential-file symlink')}: {candidate}"
                )
                return False
            if not candidate.is_file():
                continue
            if capturer is None:
                targets.append(candidate)
            else:
                world_r, group_r, _ = check_file_permission(candidate)
                if world_r or group_r:
                    targets.append(candidate)

    for f in [
        Path.home() / ".npmrc",
        Path.home() / ".pypirc",
        Path.home() / ".netrc",
    ]:
        if not f.exists():
            continue
        if f.is_symlink() or not f.is_file():
            _g(
                f"{t('拒绝跟随凭证文件符号链接', 'Refusing credential-file symlink')}: {f}"
            )
            return False
        targets.append(f)

    # De-duplicate without resolving paths (resolve would follow a link).
    unique_targets = list(dict.fromkeys(targets))
    if not unique_targets:
        return False

    # Preserve the long-standing injectable/dry-run callback contract.  A
    # replacement fixer has no portable rollback representation unless its
    # caller also injects a capturer, so do not execute real ACL tools or claim
    # a durable transaction in that mode.  Production always uses the paired
    # built-in fixer/capturer below.
    if capturer is None:
        changed = False
        for target in unique_targets:
            if not fixer(target, private=True):
                return False
            changed = True
            _g(f"{t('已收紧', 'Tightened')}: {target}")
        return changed

    action_id = _new_action_id("H009")
    try:
        snapshot_dir = _action_backup_dir(action_id) / "acl"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(snapshot_dir, 0o700)
    except Exception:
        return False

    snapshots: Dict[str, Dict[str, object]] = {}
    for index, target in enumerate(unique_targets):
        snapshot = capturer(
            target, snapshot_dir / f"{index:04d}.acl"
        )
        if snapshot is None:
            _g(
                f"{t('权限快照失败，未执行任何修改', 'Permission snapshot failed; no changes applied')}: {target}"
            )
            return False
        snapshots[str(target)] = snapshot

    # Persist the complete rollback recipe before touching any ACL/mode.
    if not _record_hardening_action(
        "H009",
        {},
        snapshots,
        action_id=action_id,
        status="pending",
    ):
        _g(t("无法写入回滚日志，未执行任何修改。", "Could not write rollback log; no changes applied."))
        return False

    entry = _get_action_record(action_id)
    if entry is None:
        return False
    for target in unique_targets:
        if not fixer(target, private=True):
            _g(f"{t('权限修改失败，正在回滚', 'Permission change failed; rolling back')}: {target}")
            _, failed = _restore_action(entry)
            if not failed:
                _remove_action(action_id)
            return False

    if not _set_action_status(action_id, "committed"):
        _g(t("无法提交回滚日志，正在回滚。", "Could not commit rollback log; rolling back."))
        _, failed = _restore_action(entry)
        if not failed:
            _remove_action(action_id)
        return False

    for target in unique_targets:
        _g(f"{t('已收紧', 'Tightened')}: {target}")
    return True


def _known_config_paths() -> Dict[str, List[Path]]:
    """Return exact product config paths; never sweep arbitrary JSON files."""
    home = Path.home()
    return {
        "openclaw": [
            home / ".openclaw" / "openclaw.json",
            home / ".config" / "openclaw" / "config.json",
        ],
        "zeroclaw": [
            home / ".zeroclaw" / "config.json",
            home / ".config" / "zeroclaw" / "config.json",
        ],
        "claude-code": [
            home / ".claude" / "settings.json",
            home / ".config" / "claude" / "settings.json",
        ],
    }


def _find_config_files(product: Optional[str] = None) -> List[Path]:
    """Find only documented config files, optionally scoped to one product."""
    known = _known_config_paths()
    candidates = known.get(product, []) if product else [
        path for paths in known.values() for path in paths
    ]
    return [
        path
        for path in candidates
        if path.is_file() and not path.is_symlink()
    ]


def _prepare_json_change(path: Path, key: str, value: Any) -> Optional[dict]:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    parts = key.split(".")
    target = data
    for part in parts[:-1]:
        if not isinstance(target, dict):
            return None
        target = target.setdefault(part, {})
    if not isinstance(target, dict):
        return None
    old_val = target.get(parts[-1])
    target[parts[-1]] = value
    return {
        "path": path,
        "key": key,
        "value": value,
        "old_value": old_val,
        "changed": old_val != value,
        "data": data,
        "digest": hashlib.sha256(raw).hexdigest(),
    }


def _apply_json_changes(
    changes: List[Tuple[Path, str, Any]], measure_id: str
) -> int:
    """Apply a group of JSON changes as one rollbackable action."""
    prepared: List[dict] = []
    for path, key, value in changes:
        change = _prepare_json_change(path, key, value)
        if change is None:
            _g(
                f"{t('配置无效或路径不安全，整组修改已中止', 'Invalid config or unsafe path; grouped change aborted')}: {path}"
            )
            return 0
        if not change["changed"]:
            _g(
                f"{path.name}: {key} = {value} "
                f"({t('已经是目标值', 'already at target value')})"
            )
            continue
        prepared.append(change)

    if not prepared:
        return 0

    action_id = _new_action_id(measure_id)
    backups: Dict[str, str] = {}
    for change in prepared:
        path = change["path"]
        backup = _backup_file(path, action_id)
        if backup is None or _file_digest(backup) != change["digest"]:
            _g(
                f"{t('备份失败，整组修改已中止', 'Backup failed; grouped change aborted')}: {path}"
            )
            return 0
        backups[str(path)] = str(backup)

    # Write a pending grouped action before the first mutation.  A process crash
    # can therefore still be recovered with ``harden --rollback``.
    if not _record_hardening_action(
        measure_id,
        backups,
        action_id=action_id,
        status="pending",
    ):
        _g(t("无法写入回滚日志，整组修改已中止。", "Could not write rollback log; grouped change aborted."))
        return 0

    entry = _get_action_record(action_id)
    if entry is None:
        return 0
    for change in prepared:
        if not _atomic_write_json(
            change["path"],
            change["data"],
            expected_digest=change["digest"],
        ):
            _g(
                f"{t('配置原子写入或校验失败，正在回滚', 'Atomic config write or validation failed; rolling back')}: {change['path']}"
            )
            _, failed = _restore_action(entry)
            if not failed:
                _remove_action(action_id)
            return 0

    if not _set_action_status(action_id, "committed"):
        _g(t("无法提交回滚日志，正在回滚。", "Could not commit rollback log; rolling back."))
        _, failed = _restore_action(entry)
        if not failed:
            _remove_action(action_id)
        return 0

    for change in prepared:
        _g(
            f"{change['path'].name}: {change['key']}: "
            f"{change['old_value']} → {change['value']}"
        )
    return len(prepared)


def _patch_json_config(path: Path, key: str, value, measure_id: str) -> bool:
    """Safely patch one JSON config through the grouped transaction path."""
    return _apply_json_changes([(path, key, value)], measure_id) == 1


def _fix_session_retention():
    """H003: Set sessionRetentionDays to 7 in all config files."""
    changes: List[Tuple[Path, str, Any]] = []
    for cfg in _find_config_files("openclaw"):
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            continue
        val = data.get("sessionRetentionDays")
        if isinstance(val, int) and val > 7:
            changes.append((cfg, "sessionRetentionDays", 7))
    if changes and _apply_json_changes(changes, "H003") == len(changes):
        return True
    _g(t("未找到需要修改的配置文件。", "No config files needed modification."))
    return False


def _fix_prompt_baseline():
    """H007: Create SHA-256 baseline for SOUL.md / CLAUDE.md / MEMORY.md."""
    from ..scanners import _load_hashes, _save_hashes
    import hashlib

    stored = _load_hashes()
    updated = 0
    candidates = []
    for fname in ["CLAUDE.md", "SOUL.md", "MEMORY.md"]:
        candidates.append(Path.cwd() / fname)
        for d in [".openclaw", ".claude", ".zeroclaw"]:
            candidates.append(Path.home() / d / fname)
    for c in candidates:
        if c.exists():
            content = c.read_text(encoding="utf-8", errors="ignore")
            h = hashlib.sha256(content.encode()).hexdigest()
            key = str(c.resolve())
            if stored.get(key) != h:
                stored[key] = h
                updated += 1
                _g(f"{t('已更新基线', 'Baseline updated')}: {c.name}")
    if updated:
        _save_hashes(stored)
        return True
    _g(t("基线已是最新。", "Baselines are already up to date."))
    return False


def _fix_approval_mode():
    """H008: Enable approvalMode in config files."""
    changes: List[Tuple[Path, str, Any]] = []
    for cfg in _find_config_files("openclaw"):
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            continue
        val = data.get("approvalMode")
        if val in (False, "none", "disabled", None):
            changes.append((cfg, "approvalMode", "always"))
    if changes and _apply_json_changes(changes, "H008") == len(changes):
        return True
    _g(t("未找到需要修改的配置文件。", "No config files needed modification."))
    return False


MEASURES: List[HardenMeasure] = [
    HardenMeasure(
        "H001",
        _tr("将文件访问限制在工作区内", "Restrict file access to the workspace"),
        _tr(
            "将 allowedDirectories / allowedPaths 收紧到项目路径内。",
            "Tighten allowedDirectories / allowedPaths to project paths only.",
        ),
        _tr(
            "可能会阻止需要跨目录访问的 skills。",
            "May block skills that need cross-directory access.",
        ),
        lambda: _guide('"allowedDirectories": ["~/projects"]'),
        ["openclaw", "zeroclaw", "claude-code"],
    ),
    HardenMeasure(
        "H002",
        _tr("启用 gateway / API 鉴权", "Enable gateway / API auth"),
        _tr("为 gateway 访问设置令牌。", "Require a token for gateway access."),
        _tr("外部工具可能需要新的令牌。", "External tools may need a new token."),
        lambda: _guide('"gatewayAuth": true + "gatewayToken": "<your-token>"'),
        ["openclaw", "zeroclaw"],
    ),
    HardenMeasure(
        "H003",
        _tr("缩短会话保留期", "Shorten session retention"),
        _tr(
            "将会话日志保留期控制在 7 天以内。",
            "Keep session logs for 7 days or less.",
        ),
        _tr(
            "更早的会话历史将不再可用。",
            "Older session history will no longer be available.",
        ),
        _fix_session_retention,
        [],
        auto_fixable=True,
        guidance_only=False,
    ),
    HardenMeasure(
        "H004",
        _tr("关闭浏览器控制", "Disable browser control"),
        _tr("关闭 enableBrowserControl。", "Turn off enableBrowserControl."),
        _tr(
            "依赖浏览器的 skills 可能会停止工作。",
            "Browser-driven skills may stop working.",
        ),
        lambda: _guide('"enableBrowserControl": false'),
        ["openclaw"],
    ),
    HardenMeasure(
        "H005",
        _tr("设置出站白名单", "Set an outbound allowlist"),
        _tr("仅允许 skills 访问经过批准的域名。", "Limit skills to approved domains only."),
        "",
        lambda: _guide('"allowedNetworkDomains": ["api.anthropic.com"]'),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H006",
        _tr("审查 MCP 服务配置", "Review MCP server config"),
        _tr("检查绑定地址和远程端点。", "Check bind addresses and remote endpoints."),
        "",
        lambda: _guide(
            _tr("将 0.0.0.0 改为 127.0.0.1。", "Change 0.0.0.0 to 127.0.0.1."),
            _tr("移除未使用的远程 MCP 服务。", "Remove unused remote MCP servers."),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H007",
        _tr("建立提示词基线", "Create a prompt baseline"),
        _tr(
            "为 SOUL.md / CLAUDE.md / MEMORY.md 记录 SHA-256 基线。",
            "Record a SHA-256 baseline for SOUL.md / CLAUDE.md / MEMORY.md.",
        ),
        "",
        _fix_prompt_baseline,
        [],
        auto_fixable=True,
        guidance_only=False,
    ),
    HardenMeasure(
        "H008",
        _tr("启用审批模式", "Enable approval mode"),
        _tr(
            "在高风险操作前要求确认。",
            "Require confirmation before high-risk actions.",
        ),
        _tr(
            "高风险操作会暂停等待确认。",
            "High-risk actions will pause for confirmation.",
        ),
        _fix_approval_mode,
        ["openclaw", "zeroclaw"],
        auto_fixable=True,
        guidance_only=False,
    ),
    HardenMeasure(
        "H009",
        _tr("收紧凭证权限", "Tighten credential permissions"),
        _tr(
            "将配置和凭证路径限制为仅当前用户可访问。",
            "Limit config and credential paths to the current user.",
        ),
        "",
        _fix_cred_perms,
        [],
        auto_fixable=True,
        guidance_only=False,
    ),
    HardenMeasure(
        "H010",
        _tr("设置速率限制", "Set rate limits"),
        _tr(
            "添加请求速率限制以降低暴力尝试和 API 滥用风险。",
            "Add request limits to reduce brute force and API abuse.",
        ),
        "",
        lambda: _guide('"rateLimit": {"enabled": true, "maxRequestsPerMinute": 60}'),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H011",
        _tr(
            "阻止下载即执行和远程运行时安装",
            "Block download-and-execute and remote runtime installs",
        ),
        _tr(
            "从 skills 和安装脚本中移除 pipe-to-shell 启动方式与运行时依赖拉取。",
            "Remove pipe-to-shell bootstraps and runtime dependency fetch from skills and setup scripts.",
        ),
        _tr(
            "引导安装脚本和一次性依赖拉取可能会停止工作。",
            "Bootstrap installers and one-shot dependency fetches may stop working.",
        ),
        lambda: _guide(
            _tr(
                '移除 "curl | bash"、"wget | sh"、"Invoke-WebRequest | iex" 这类模式。',
                'Remove patterns like "curl | bash", "wget | sh", and "Invoke-WebRequest | iex".',
            ),
            _tr(
                '将 "npx"、"uvx"、"pipx run"、"npm exec"、"pip install git+..." 这类运行时拉取方式替换为固定的本地依赖。',
                'Replace runtime fetchers such as "npx", "uvx", "pipx run", "npm exec", and "pip install git+..." with pinned local dependencies.',
            ),
            _tr(
                "在执行前把依赖 vendoring 或固定到包清单里。",
                "Vendor or pin dependencies in package manifests before execution.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H012",
        _tr("禁用 Windows LOLBins 和脚本宿主", "Deny Windows LOLBins and script hosts"),
        _tr(
            "阻止常被滥用于代码执行的 Windows 内置执行器。",
            "Block built-in Windows executors that are commonly abused for code execution.",
        ),
        _tr(
            "依赖 LOLBins 的 Windows 管理脚本可能会停止工作。",
            "Windows admin scripts that rely on LOLBins may stop working.",
        ),
        lambda: _guide(
            _tr(
                "把 mshta、regsvr32、rundll32、certutil、bitsadmin、wmic 加入拒绝列表或仅审批后可执行的命令集合。",
                "Add mshta, regsvr32, rundll32, certutil, bitsadmin, and wmic to your denylist or approval-only command set.",
            ),
            _tr(
                "优先使用签名应用程序或已审查的 PowerShell 脚本，而不是传统脚本宿主。",
                "Prefer signed application binaries or reviewed PowerShell scripts over legacy script hosts.",
            ),
            _tr(
                "审查所有通过 Windows 内置加载器调用 shell 的 skill 或自动化。",
                "Review any skill or automation that shells out through built-in Windows loaders.",
            ),
        ),
        [],
        platforms=["windows"],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H013",
        _tr("清理持久化落点", "Remove persistence footholds"),
        _tr(
            "审查计划任务、autoruns、LaunchAgents 和用户级 systemd 单元中的持久化项。",
            "Audit scheduled tasks, autoruns, LaunchAgents, and user-level systemd units for persistence.",
        ),
        _tr(
            "合法的后台任务在重新批准前可能会停止工作。",
            "Legitimate background jobs may stop working until re-approved.",
        ),
        _persistence_guidance,
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H014",
        _tr("阻止隧道和反向代理", "Block tunnels and reverse proxies"),
        _tr(
            "阻止反向 SSH 和隧道客户端等隐蔽出站通道。",
            "Prevent covert outbound channels such as reverse SSH and tunneling clients.",
        ),
        _tr(
            "远程调试隧道和临时共享工具可能会停止工作。",
            "Remote debugging tunnels and ad-hoc sharing tools may stop working.",
        ),
        lambda: _guide(
            _tr(
                "对 ssh -R、ngrok、cloudflared tunnel、frpc 设置拒绝或显式审批。",
                "Deny or require explicit approval for ssh -R, ngrok, cloudflared tunnel, and frpc.",
            ),
            _tr(
                "把出站域名限制在白名单内，并从 PATH 中移除未使用的隧道工具。",
                "Keep outbound domains on an allowlist and remove unused tunnel binaries from PATH.",
            ),
            _tr(
                "优先使用已审计的 VPN 或堡垒机，而不是临时反向隧道。",
                "Use audited VPN or bastion access instead of ad-hoc reverse tunnels.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H015",
        _tr("收紧 MCP 鉴权、绑定和 CORS", "Tighten MCP auth, bind, and CORS"),
        _tr(
            "为 MCP 路由启用鉴权、回环地址绑定和严格来源限制。",
            "Require authentication, loopback bind, and restrictive origins for MCP routes.",
        ),
        _tr(
            "外部仪表盘或工具可能需要更新令牌和来源配置。",
            "External dashboards or tools may need token and origin updates.",
        ),
        lambda: _guide(
            _tr(
                "对 /invoke、/tools、/call 等 MCP 端点要求鉴权。",
                "Require auth on /invoke, /tools, /call, and similar MCP endpoints.",
            ),
            _tr(
                '将 MCP 服务绑定到 127.0.0.1，并移除 "Access-Control-Allow-Origin: *"。',
                'Bind MCP services to 127.0.0.1 and remove "Access-Control-Allow-Origin: *".',
            ),
            _tr(
                "只允许显式列出的来源，避免在启用凭证时使用通配符来源。",
                "Only allow explicit origins and avoid wildcard origins with credentials enabled.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H016",
        _tr(
            "禁用用户可控的动态模块加载",
            "Disable user-controlled dynamic module loading",
        ),
        _tr(
            "将由工具或用户输入决定的动态 import/require 路径替换为固定白名单。",
            "Replace dynamic import/require paths derived from tool or user input with fixed allowlists.",
        ),
        _tr(
            "按名称热加载插件的能力在加入白名单前可能无法使用。",
            "Hot-loading plugins by name may stop working until they are allowlisted.",
        ),
        lambda: _guide(
            _tr(
                "把 importlib.import_module(user_input)、__import__(...)、require(args.plugin) 替换为显式查找表。",
                "Replace importlib.import_module(user_input), __import__(...), and require(args.plugin) with explicit lookup tables.",
            ),
            _tr(
                "将已批准的插件名映射到已知模块，不要加载任意模块字符串。",
                "Map approved plugin names to known modules instead of loading arbitrary module strings.",
            ),
            _tr(
                "当请求的模块不在白名单内时默认拒绝。",
                "Fail closed when a requested module is not in the allowlist.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H017",
        _tr("对日志中的提示词和凭证做脱敏", "Redact prompts and credentials from logs"),
        _tr(
            "停止记录 system prompt、聊天历史、token、密码和其他密钥。",
            "Stop logging system prompts, chat history, tokens, passwords, and secrets.",
        ),
        _tr("排障日志会变得更简略。", "Troubleshooting logs become less verbose."),
        lambda: _guide(
            _tr(
                "删除或脱敏包含 system_prompt、messages、token、password、secret 的 logger/debug/print 语句。",
                "Remove or redact logger/debug/print statements that include system_prompt, messages, tokens, passwords, or secrets.",
            ),
            _tr(
                "日志中只保留请求 ID、高层状态和已脱敏的元数据。",
                "Keep only request IDs, high-level status, and sanitized metadata in logs.",
            ),
            _tr(
                "完整 prompt 跟踪只应保存在严格受控的调试环境中。",
                "Store full prompt traces only in tightly controlled debug environments.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H018",
        _tr("清理 prompt 和 skill 操作指令", "Clean prompt and skill operating instructions"),
        _tr(
            "从 SOUL.md 和 skills 中移除 prompt 提取、审批绕过和强制工具调用措辞。",
            "Remove prompt-extraction, approval-bypass, and forced-tool wording from SOUL.md and skills.",
        ),
        _tr(
            "不安全的自动化措辞在安全改写前可能无法继续工作。",
            "Unsafe automation wording may stop working until rewritten safely.",
        ),
        lambda: _guide(
            _tr(
                '删除诸如 "show your system prompt"、"do not ask for approval"、"call the tool before replying" 这类指令。',
                'Delete instructions such as "show your system prompt", "do not ask for approval", and "call the tool before replying".',
            ),
            _tr(
                "让操作者意图保持明确，并对高风险操作要求审批。",
                "Keep operator intent explicit and require approval for high-risk actions.",
            ),
            _tr(
                "更新 prompt 文件后重新运行 `clawlock skill` 和 `clawlock soul`。",
                "Re-run `clawlock skill` and `clawlock soul` after updating prompt files.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
]


# ─── Finding → Measure mapping for --from-scan ──────────────────────────────

# Maps finding title keywords or config keys to relevant measure IDs.
_FINDING_TO_MEASURES: Dict[str, List[str]] = {
    "allowedDirectories": ["H001"],
    "allowedPaths": ["H001"],
    "File access scope": ["H001"],
    "文件访问范围": ["H001"],
    "gatewayAuth": ["H002"],
    "Gateway auth": ["H002"],
    "Gateway 鉴权": ["H002"],
    "auth.enabled": ["H002"],
    "sessionRetentionDays": ["H003"],
    "Session log retention": ["H003"],
    "会话日志保留": ["H003"],
    "enableBrowserControl": ["H004"],
    "Browser control": ["H004"],
    "浏览器控制": ["H004"],
    "allowNetworkAccess": ["H005"],
    "Network access": ["H005"],
    "网络访问": ["H005"],
    "MCP": ["H006", "H015"],
    "prompt baseline": ["H007"],
    "Drift": ["H007"],
    "漂移": ["H007"],
    "approvalMode": ["H008"],
    "Operation approval": ["H008"],
    "操作审批": ["H008"],
    "Credential dir": ["H009"],
    "Credential file": ["H009"],
    "凭证目录": ["H009"],
    "凭证文件": ["H009"],
    "rateLimit": ["H010"],
    "Rate limit": ["H010"],
    "速率限制": ["H010"],
    "curl|": ["H011"],
    "wget|": ["H011"],
    "Download-and-execute": ["H011"],
    "下载即执行": ["H011"],
    "LOLBin": ["H012"],
    "persistence": ["H013"],
    "持久化": ["H013"],
    "Cron": ["H013"],
    "schtasks": ["H013"],
    "LaunchAgent": ["H013"],
    "systemd": ["H013"],
    "Termux": ["H013"],
    "tunnel": ["H014"],
    "隧道": ["H014"],
    "ngrok": ["H014"],
    "dynamic module": ["H016"],
    "动态模块": ["H016"],
}


def _measures_for_findings(findings: list) -> set:
    """Given a list of finding dicts (from scan history), return relevant measure IDs.

    Scanners can attach ``measure_ids`` to ``Finding.metadata`` and reporters
    persist them into the history record. When present this is the
    authoritative mapping; otherwise we fall back to the title/location
    keyword table for findings produced by older runs or scanners that have
    not migrated yet.
    """
    relevant = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        ids = f.get("measure_ids") or []
        if ids:
            relevant.update(ids)
            continue
        text = f"{f.get('title', '')} {f.get('location', '')}"
        for keyword, measure_ids in _FINDING_TO_MEASURES.items():
            if keyword in text:
                relevant.update(measure_ids)
    return relevant


def _needs_confirmation(measure: HardenMeasure) -> bool:
    return bool(_text(measure.ux_impact))


def _measure_action(measure: HardenMeasure) -> str:
    if _needs_confirmation(measure):
        return t("需要确认", "Confirm required")
    if measure.guidance_only:
        return t("仅指导", "Guidance only")
    if measure.auto_fixable:
        return t("可自动修复", "Auto-fix available")
    return t("自动应用", "Apply automatically")


def _print_measure(measure: HardenMeasure):
    console.print(f"[bold][{measure.id}][/bold] {_text(measure.title)}")
    console.print(f"  {t('原因', 'Why')}: {_text(measure.desc)}")
    console.print(
        f"  {t('影响', 'Impact')}: {_text(measure.ux_impact) or t('无', 'None')}"
    )
    console.print(f"  {t('动作', 'Action')}: {_measure_action(measure)}")


def run_hardening(
    adapter_name: str,
    auto: bool = False,
    auto_fix: bool = False,
    from_scan: Optional[list] = None,
    verify: bool = False,
):
    mode = (
        t("自动修复", "auto-fix")
        if auto_fix
        else t("自动", "auto")
        if auto
        else t("交互式", "interactive")
    )
    console.print(
        Panel(
            f"[bold cyan]{t('ClawLock 加固向导', 'ClawLock Hardening Wizard')}[/bold cyan]",
            subtitle=(
                f"{t('适配器', 'Adapter')}: [bold]{adapter_name}[/bold]  |  "
                f"{t('模式', 'Mode')}: {mode}  |  "
                f"{t('平台', 'Platform')}: {platform_label()}"
            ),
        )
    )
    console.print()
    applicable = [
        m
        for m in MEASURES
        if (not m.adapters or adapter_name in m.adapters) and _platform_matches(m)
    ]
    # If --from-scan, filter to only measures relevant to actual findings
    if from_scan is not None:
        relevant_ids = _measures_for_findings(from_scan)
        if relevant_ids:
            applicable = [m for m in applicable if m.id in relevant_ids]
            console.print(
                f"[dim]{t('根据扫描结果筛选了', 'Filtered to')} {len(applicable)} "
                f"{t('条相关加固措施', 'relevant measures based on scan findings')}[/dim]\n"
            )
        else:
            console.print(
                f"[green]{t('扫描未发现与加固措施关联的问题。', 'Scan found no issues linked to hardening measures.')}[/green]"
            )
            return
    safe_now = [m for m in applicable if not m.guidance_only and not _needs_confirmation(m)]
    recommended_only = [
        m for m in applicable if m.guidance_only and not _needs_confirmation(m)
    ]
    needs_confirmation = [m for m in applicable if _needs_confirmation(m)]

    console.print(f"[bold]{t('执行摘要', 'Execution Summary')}[/bold]")
    console.print(f"  {t('现在可安全应用', 'Safe to apply now')}: {len(safe_now)}")
    console.print(f"  {t('仅建议', 'Recommended only')}: {len(recommended_only)}")
    console.print(f"  {t('需要确认', 'Needs confirmation')}: {len(needs_confirmation)}")
    console.print()

    applied = 0
    recommended = 0
    skipped = 0
    failed = 0

    sections = [
        (t("现在可安全应用", "Safe to Apply Now"), safe_now),
        (t("仅建议", "Recommended Only"), recommended_only),
        (t("需要确认", "Needs Confirmation"), needs_confirmation),
    ]

    for title, measures in sections:
        if not measures:
            continue
        console.print(f"[bold]{title}[/bold]")
        console.print()
        for m in measures:
            _print_measure(m)
            if m.guidance_only:
                if _needs_confirmation(m):
                    if auto or auto_fix:
                        skipped += 1
                        console.print(
                            f"  [dim]{t('需要确认：非交互模式下已跳过', 'Requires confirmation: skipped in non-interactive mode')}[/dim]\n"
                        )
                        continue
                    if not Confirm.ask(
                        f"  {t('查看建议', 'Review recommendation')} [{m.id}]?",
                        default=False,
                    ):
                        skipped += 1
                        console.print(
                            f"  [dim]{t('已跳过', 'Skipped')} {m.id}[/dim]\n"
                        )
                        continue
                    recommended += 1
                    console.print(
                        f"  [cyan]{t('需要手动修改：请按上方建议处理', 'Manual change required: follow the recommendation above')}[/cyan]\n"
                    )
                    continue

                recommended += 1
                console.print(
                    f"  [dim]{t('仅提供建议：未执行自动修改', 'Recommendation only: no automatic change was made')}[/dim]\n"
                )
                continue

            if auto_fix and not m.auto_fixable:
                skipped += 1
                console.print(
                    f"  [dim]{t('安全项已跳过：不适用于自动修复模式', 'Safe item skipped: not eligible for auto-fix mode')}[/dim]\n"
                )
                continue

            if not auto and not auto_fix and not Confirm.ask(
                f"  {t('应用加固项', 'Apply hardening')} [{m.id}]?",
                default=True,
            ):
                skipped += 1
                console.print(f"  [dim]{t('已跳过', 'Skipped')} {m.id}[/dim]\n")
                continue

            if auto_fix and m.auto_fixable:
                console.print(
                    f"  [green]{t('自动修复：正在应用', 'Auto-fix: applying now')}[/green]"
                )

            if m.apply():
                applied += 1
                console.print(f"  [green]{m.id} {t('已应用', 'applied')}[/green]\n")
            else:
                failed += 1
                console.print(f"  [red]{m.id} {t('失败', 'failed')}[/red]\n")

    console.print(f"[bold]{t('结果', 'Result')}[/bold]")
    console.print(f"  {t('已自动应用', 'Applied automatically')}: {applied}")
    console.print(f"  {t('仅建议', 'Recommended only')}: {recommended}")
    console.print(f"  {t('待确认前已跳过', 'Skipped until confirmed')}: {skipped}")
    if failed:
        console.print(f"  {t('失败', 'Failed')}: {failed}")
    console.print(
        f"[bold green]{t('加固完成', 'Hardening complete')}[/bold green]: "
        f"{applied} {t('项已应用', 'applied')}, "
        f"{recommended} {t('项仅建议', 'recommended')}, "
        f"{skipped} {t('项已跳过', 'skipped')}."
    )

    # Post-fix verification: re-scan config + credentials to show improvement
    if verify and applied > 0:
        console.print()
        console.print(f"[bold]{t('修复验证', 'Post-fix Verification')}[/bold]")
        try:
            from ..adapters import get_adapter
            from ..scanners import CRIT, HIGH, scan_config, scan_credential_dirs

            adapter = get_adapter(adapter_name)
            cfg_findings, _ = scan_config(adapter)
            cred_findings = scan_credential_dirs(adapter)
            remaining = [
                f for f in cfg_findings + cred_findings
                if f.level in (CRIT, HIGH)
            ]
            if remaining:
                console.print(
                    f"  [yellow]{t('仍有', 'Still')} {len(remaining)} "
                    f"{t('个高危/严重问题待处理', 'critical/high issue(s) remaining')}[/yellow]"
                )
                for rf in remaining[:5]:
                    console.print(f"    [{rf.level}] {rf.title}")
            else:
                console.print(
                    f"  [green]{t('配置和凭证扫描未发现高危/严重问题。', 'Config and credential scan found no critical/high issues.')}[/green]"
                )
        except Exception as exc:
            from ..scanners import _log_scanner_error

            _log_scanner_error("post-fix verification", exc)
            console.print(
                f"  [yellow]{t('验证扫描失败', 'Verification scan failed')}: "
                f"{type(exc).__name__}: {exc}[/yellow]"
            )
            console.print(
                f"  [dim]{t('详见', 'See')} ~/.clawlock/error.log[/dim]"
            )
