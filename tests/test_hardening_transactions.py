from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

import pytest

import clawlock.hardening as hardening
import clawlock.utils as utils


@pytest.fixture
def isolated_hardening_state(tmp_path, monkeypatch):
    log_path = tmp_path / "state" / "hardening_log.json"
    backup_root = tmp_path / "home" / ".clawlock" / "backups"

    def action_backup_dir(action_id: str) -> Path:
        path = backup_root / action_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    monkeypatch.setattr(hardening, "HARDENING_LOG", log_path)
    monkeypatch.setattr(hardening, "_backup_root", lambda: backup_root)
    monkeypatch.setattr(hardening, "_action_backup_dir", action_backup_dir)
    monkeypatch.setattr(hardening, "_allowed_hardening_target", lambda _path: True)
    monkeypatch.setattr(hardening, "_is_elevated", lambda: False)
    monkeypatch.setattr(
        hardening,
        "_windows_replace_file",
        lambda source, destination, flags=0: hardening.os.replace(
            source, destination
        ),
    )
    return log_path, backup_root


def test_backups_are_unique_for_equal_names_and_repeated_calls(
    tmp_path, isolated_hardening_state
):
    first = tmp_path / "one" / "config.json"
    second = tmp_path / "two" / "config.json"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text('{"source": "one"}', encoding="utf-8")
    second.write_text('{"source": "two"}', encoding="utf-8")

    first_backup = hardening._backup_file(first, "one-action")
    second_backup = hardening._backup_file(second, "one-action")
    repeated_backup = hardening._backup_file(first, "one-action")

    assert first_backup is not None
    assert second_backup is not None
    assert repeated_backup is not None
    assert len({first_backup, second_backup, repeated_backup}) == 3
    assert first_backup.read_bytes() == first.read_bytes()
    assert second_backup.read_bytes() == second.read_bytes()
    assert repeated_backup.read_bytes() == first.read_bytes()


def test_backup_failure_aborts_before_config_mutation(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    config = tmp_path / "config.json"
    original = b'{"approvalMode": "none"}\n'
    config.write_bytes(original)
    monkeypatch.setattr(hardening, "_backup_file", lambda *_args, **_kwargs: None)

    assert (
        hardening._patch_json_config(config, "approvalMode", "always", "H008")
        is False
    )
    assert config.read_bytes() == original
    assert not log_path.exists()


def test_grouped_config_action_rolls_back_every_member(
    tmp_path, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_original = b'{"sessionRetentionDays": 30}\n'
    second_original = b'{"sessionRetentionDays": 90}\n'
    first.write_bytes(first_original)
    second.write_bytes(second_original)

    assert (
        hardening._apply_json_changes(
            [
                (first, "sessionRetentionDays", 7),
                (second, "sessionRetentionDays", 7),
            ],
            "H003",
        )
        == 2
    )
    assert json.loads(first.read_text(encoding="utf-8"))["sessionRetentionDays"] == 7
    assert json.loads(second.read_text(encoding="utf-8"))["sessionRetentionDays"] == 7

    records = json.loads(log_path.read_text(encoding="utf-8"))
    assert len(records) == 1
    assert records[0]["status"] == "committed"
    assert set(records[0]["files"]) == {str(first), str(second)}
    assert all(
        Path(metadata["backup"]).is_file()
        for metadata in records[0]["files"].values()
    )

    assert hardening.rollback_last() == 2
    assert first.read_bytes() == first_original
    assert second.read_bytes() == second_original
    assert json.loads(log_path.read_text(encoding="utf-8")) == []


def test_post_write_validation_failure_restores_original(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    config = tmp_path / "config.json"
    original = b'{"approvalMode": "none"}\n'
    config.write_bytes(original)
    real_replace = hardening.os.replace
    corrupted = False

    def corrupt_first_config_replace(source, destination):
        nonlocal corrupted
        real_replace(source, destination)
        if Path(destination) == config and not corrupted:
            corrupted = True
            config.write_text("{not-json", encoding="utf-8")

    monkeypatch.setattr(hardening, "_replace_path", corrupt_first_config_replace)

    assert (
        hardening._patch_json_config(config, "approvalMode", "always", "H008")
        is False
    )
    assert corrupted is True
    assert config.read_bytes() == original
    assert json.loads(log_path.read_text(encoding="utf-8")) == []


def test_rollback_failure_keeps_complete_action_log(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    config = tmp_path / "config.json"
    config.write_text('{"approvalMode": "none"}', encoding="utf-8")
    assert hardening._patch_json_config(
        config, "approvalMode", "always", "H008"
    )
    action_before = json.loads(log_path.read_text(encoding="utf-8"))[0]
    monkeypatch.setattr(
        hardening, "_restore_file_from_backup", lambda _original, _backup: False
    )

    assert hardening.rollback_last() == 0
    assert json.loads(log_path.read_text(encoding="utf-8")) == [action_before]


def test_rollback_log_write_failure_retains_retry_record(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    config = tmp_path / "config.json"
    original = b'{"approvalMode": "none"}\n'
    config.write_bytes(original)
    assert hardening._patch_json_config(
        config, "approvalMode", "always", "H008"
    )
    action_before = json.loads(log_path.read_text(encoding="utf-8"))[0]
    monkeypatch.setattr(hardening, "_save_hardening_log", lambda _records: False)

    assert hardening.rollback_last() == 0
    assert config.read_bytes() == original
    assert json.loads(log_path.read_text(encoding="utf-8")) == [action_before]


def test_h009_injected_backend_is_one_rollbackable_permission_group(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    home = tmp_path / "home"
    home.mkdir()
    first = home / ".npmrc"
    second = home / ".pypirc"
    first.write_text("token=abc", encoding="utf-8")
    second.write_text("[distutils]", encoding="utf-8")
    monkeypatch.setattr(hardening.Path, "home", lambda: home)
    fixed = []

    def capture(path: Path, snapshot_path: Optional[Path]):
        assert snapshot_path is not None
        return {"platform": "unix", "mode": 0o600}

    def fix(path: Path, private: bool = True):
        fixed.append((path, private))
        return True

    assert hardening._fix_cred_perms(
        permission_capturer=capture,
        permission_fixer=fix,
    )
    assert {path for path, _private in fixed} == {first, second}

    records = json.loads(log_path.read_text(encoding="utf-8"))
    assert len(records) == 1
    assert records[0]["measure"] == "H009"
    assert records[0]["status"] == "committed"
    assert set(records[0]["permissions"]) == {str(first), str(second)}

    restored = []

    def restore(path: Path, snapshot):
        restored.append((path, snapshot["mode"]))
        return True

    monkeypatch.setattr(utils, "restore_file_permission", restore)
    assert hardening.rollback_last() == 2
    assert {path for path, _token in restored} == {first, second}
    assert json.loads(log_path.read_text(encoding="utf-8")) == []


def test_windows_permission_fix_rejects_failed_icacls(
    tmp_path, monkeypatch
):
    target = tmp_path / "secret.key"
    target.write_text("secret", encoding="utf-8")
    calls = []

    def failed_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 5, "", "access denied")

    monkeypatch.setattr(utils, "IS_WINDOWS", True)
    monkeypatch.setenv("USERNAME", "tester")
    monkeypatch.setattr(utils, "run_bounded_command", failed_run)

    assert utils.fix_file_permission(target) is False
    assert calls[0][0][0] == "icacls"
    assert "/inheritance:r" in calls[0][0]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (FileNotFoundError(), "command not found"),
        (subprocess.TimeoutExpired("tasklist", 10), "timed out"),
    ],
)
def test_process_probe_raises_for_missing_command_or_timeout(
    monkeypatch, failure, message
):
    def failed_run(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(utils, "IS_WINDOWS", True)
    monkeypatch.setattr(utils, "run_bounded_command", failed_run)

    with pytest.raises(RuntimeError, match=message):
        utils.list_processes()


def test_process_probe_raises_for_nonzero_exit(monkeypatch):
    def failed_run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 7, "", "probe denied")

    monkeypatch.setattr(utils, "IS_WINDOWS", True)
    monkeypatch.setattr(utils, "run_bounded_command", failed_run)

    with pytest.raises(RuntimeError, match="exit 7"):
        utils.list_processes()


def test_port_probe_raises_when_linux_tools_are_missing(monkeypatch):
    monkeypatch.setattr(utils, "IS_WINDOWS", False)
    monkeypatch.setattr(utils, "IS_MACOS", False)
    monkeypatch.setattr(utils, "find_binary", lambda _name: None)

    with pytest.raises(RuntimeError, match="neither ss nor netstat"):
        utils.list_listening_ports()


def test_successful_empty_system_probes_return_empty(monkeypatch):
    def succeeded(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(utils, "IS_WINDOWS", True)
    monkeypatch.setattr(utils, "run_bounded_command", succeeded)

    assert utils.list_processes() == []
    assert utils.list_listening_ports() == []


def test_poisoned_journal_cannot_select_arbitrary_original_path(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, backup_root = isolated_hardening_state
    action_id = "h008-20260824T120000_000000-0123456789ab"
    backup = backup_root / action_id / "payload.bak"
    backup.parent.mkdir(parents=True)
    backup.write_text("attacker content", encoding="utf-8")
    victim = tmp_path / "outside-allowlist.json"
    victim.write_text("original", encoding="utf-8")
    record = {
        "version": 2,
        "id": action_id,
        "time": "2026-08-24T12:00:00",
        "measure": "H008",
        "status": "committed",
        "files": {
            str(victim): {
                "backup": str(backup),
                "digest": hardening._file_digest(backup),
            }
        },
        "permissions": {},
    }
    log_path.parent.mkdir(parents=True)
    log_path.write_text(json.dumps([record]), encoding="utf-8")
    monkeypatch.setattr(hardening, "_allowed_hardening_target", lambda _path: False)

    with pytest.raises(hardening.HardeningLogError):
        hardening._load_hardening_log()
    assert hardening.rollback_last() == 0
    assert victim.read_text(encoding="utf-8") == "original"


def test_journal_rejects_backup_outside_its_action_directory(
    tmp_path, isolated_hardening_state
):
    log_path, backup_root = isolated_hardening_state
    action_id = "h008-20260824T120000_000000-0123456789ab"
    outside_backup = backup_root / "outside-action.bak"
    outside_backup.parent.mkdir(parents=True)
    outside_backup.write_text("original", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text("changed", encoding="utf-8")
    record = {
        "version": 2,
        "id": action_id,
        "time": "2026-08-24T12:00:00",
        "measure": "H008",
        "status": "committed",
        "files": {
            str(config): {
                "backup": str(outside_backup),
                "digest": hardening._file_digest(outside_backup),
            }
        },
        "permissions": {},
    }
    log_path.parent.mkdir(parents=True)
    log_path.write_text(json.dumps([record]), encoding="utf-8")

    with pytest.raises(hardening.HardeningLogError):
        hardening._load_hardening_log()
    assert hardening.rollback_last() == 0
    assert config.read_text(encoding="utf-8") == "changed"


def test_malformed_existing_journal_is_not_overwritten(
    tmp_path, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    log_path.parent.mkdir(parents=True)
    malformed = b"{not-json"
    log_path.write_bytes(malformed)
    config = tmp_path / "config.json"
    config.write_text('{"approvalMode": "none"}', encoding="utf-8")

    assert hardening._patch_json_config(
        config, "approvalMode", "always", "H008"
    ) is False
    assert log_path.read_bytes() == malformed
    assert json.loads(config.read_text(encoding="utf-8"))["approvalMode"] == "none"


def test_tampered_backup_digest_blocks_rollback(
    tmp_path, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    config = tmp_path / "config.json"
    config.write_text('{"approvalMode": "none"}', encoding="utf-8")
    assert hardening._patch_json_config(
        config, "approvalMode", "always", "H008"
    )
    record = json.loads(log_path.read_text(encoding="utf-8"))[0]
    backup = Path(record["files"][str(config)]["backup"])
    backup.write_text("tampered", encoding="utf-8")

    assert hardening.rollback_last() == 0
    assert json.loads(config.read_text(encoding="utf-8"))["approvalMode"] == "always"
    assert json.loads(log_path.read_text(encoding="utf-8")) == [record]


def test_tampered_windows_acl_snapshot_blocks_restore(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    credential = home / ".npmrc"
    credential.write_text("token=abc", encoding="utf-8")
    monkeypatch.setattr(hardening.Path, "home", lambda: home)

    def capture(path: Path, snapshot_path: Optional[Path]):
        assert snapshot_path is not None
        snapshot_path.write_text("original acl", encoding="utf-8")
        return {
            "platform": "windows",
            "acl_file": str(snapshot_path),
            "restore_root": str(path.parent),
        }

    assert hardening._fix_cred_perms(
        permission_capturer=capture,
        permission_fixer=lambda _path, private=True: True,
    )
    record = json.loads(log_path.read_text(encoding="utf-8"))[0]
    acl_file = Path(
        record["permissions"][str(credential)]["snapshot"]["acl_file"]
    )
    acl_file.write_text("tampered acl", encoding="utf-8")
    monkeypatch.setattr(
        utils,
        "restore_file_permission",
        lambda *_args, **_kwargs: pytest.fail("tampered ACL must not be restored"),
    )

    assert hardening.rollback_last() == 0
    assert json.loads(log_path.read_text(encoding="utf-8")) == [record]


def test_existing_windows_replace_uses_replacefilew_flags_zero(
    tmp_path, monkeypatch
):
    source = tmp_path / "replacement.tmp"
    destination = tmp_path / "config.json"
    source.write_text("new", encoding="utf-8")
    destination.write_text("old", encoding="utf-8")
    calls = []

    def replace_file(source_path, destination_path, flags=99):
        calls.append((source_path, destination_path, flags))
        hardening.os.replace(source_path, destination_path)

    monkeypatch.setattr(hardening, "IS_WINDOWS", True)
    monkeypatch.setattr(hardening, "_windows_replace_file", replace_file)
    hardening._replace_path(source, destination)

    assert calls == [(source, destination, 0)]
    assert destination.read_text(encoding="utf-8") == "new"


def test_replacefilew_failure_is_fail_closed(tmp_path, monkeypatch):
    destination = tmp_path / "config.json"
    original = b'{"approvalMode": "none"}'
    destination.write_bytes(original)
    digest = hardening._file_digest(destination)

    def deny_replace(*_args, **_kwargs):
        raise PermissionError("ReplaceFileW denied")

    monkeypatch.setattr(hardening, "IS_WINDOWS", True)
    monkeypatch.setattr(hardening, "_windows_replace_file", deny_replace)

    assert hardening._atomic_write_json(
        destination,
        {"approvalMode": "always"},
        expected_digest=digest,
    ) is False
    assert destination.read_bytes() == original


def test_elevated_windows_rollback_rejects_user_journal(
    tmp_path, monkeypatch, isolated_hardening_state
):
    log_path, _ = isolated_hardening_state
    config = tmp_path / "config.json"
    config.write_text('{"approvalMode": "none"}', encoding="utf-8")
    assert hardening._patch_json_config(
        config, "approvalMode", "always", "H008"
    )
    record = json.loads(log_path.read_text(encoding="utf-8"))[0]
    monkeypatch.setattr(hardening, "IS_WINDOWS", True)
    monkeypatch.setattr(hardening, "_is_elevated", lambda: True)

    assert hardening.rollback_last() == 0
    assert json.loads(config.read_text(encoding="utf-8"))["approvalMode"] == "always"
    assert json.loads(log_path.read_text(encoding="utf-8")) == [record]


def test_config_discovery_never_sweeps_unrelated_json(tmp_path, monkeypatch):
    home = tmp_path / "home"
    openclaw_dir = home / ".openclaw"
    zeroclaw_dir = home / ".zeroclaw"
    claude_dir = home / ".claude"
    for directory in (openclaw_dir, zeroclaw_dir, claude_dir):
        directory.mkdir(parents=True)

    openclaw = openclaw_dir / "openclaw.json"
    zeroclaw = zeroclaw_dir / "config.json"
    claude = claude_dir / "settings.json"
    unrelated = openclaw_dir / "mcp.json"
    for path in (openclaw, zeroclaw, claude, unrelated):
        path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(hardening.Path, "home", lambda: home)

    assert set(hardening._find_config_files()) == {openclaw, zeroclaw, claude}
    assert hardening._find_config_files("openclaw") == [openclaw]
    assert unrelated not in hardening._find_config_files()


def test_approval_fix_only_mutates_openclaw_schema(
    tmp_path, monkeypatch, isolated_hardening_state
):
    home = tmp_path / "home"
    openclaw = home / ".openclaw" / "openclaw.json"
    zeroclaw = home / ".zeroclaw" / "config.json"
    unrelated = home / ".openclaw" / "mcp.json"
    for path in (openclaw, zeroclaw, unrelated):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(hardening.Path, "home", lambda: home)

    assert hardening._fix_approval_mode() is True
    assert json.loads(openclaw.read_text(encoding="utf-8"))["approvalMode"] == "always"
    assert "approvalMode" not in json.loads(zeroclaw.read_text(encoding="utf-8"))
    assert "approvalMode" not in json.loads(unrelated.read_text(encoding="utf-8"))
