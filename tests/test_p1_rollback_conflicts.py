"""Benign temporary-file checks for conflict-aware hardening recovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import clawlock.hardening as hardening
import clawlock.utils as utils


@pytest.fixture
def config_state(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(hardening.Path, "home", lambda: home)
    monkeypatch.setattr(
        hardening, "HARDENING_LOG", home / ".clawlock" / "hardening_log.json"
    )
    monkeypatch.setattr(hardening, "_is_elevated", lambda: False)
    monkeypatch.setattr(
        hardening,
        "_windows_replace_file",
        lambda source, destination, flags=0: hardening.os.replace(source, destination),
    )
    first, second = hardening._known_config_paths()["openclaw"]
    for index, path in enumerate((first, second)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"sessionRetentionDays": 30 + index, "theme": "light"}),
            encoding="utf-8",
        )
    return first, second


def _apply(first, second):
    return hardening._apply_json_changes(
        [(first, "sessionRetentionDays", 7), (second, "sessionRetentionDays", 7)],
        "H003",
    )


def _records():
    return hardening._load_hardening_log()


def test_success_records_each_written_digest_and_rolls_back(config_state):
    first, second = config_state
    originals = {path: path.read_bytes() for path in config_state}

    assert _apply(first, second) == 2
    record = _records()[0]
    assert record["version"] == 3
    assert record["status"] == "committed"
    for path in config_state:
        metadata = record["files"][str(path)]
        assert metadata["write_state"] == "written"
        assert metadata["written_digest"] == hardening._file_digest(path)

    assert hardening.rollback_last() == 2
    assert all(path.read_bytes() == original for path, original in originals.items())
    assert _records() == []


def test_group_failure_preserves_save_to_member_not_yet_written(config_state, monkeypatch):
    first, second = config_state
    original_first = first.read_bytes()
    saved_second = b'{"sessionRetentionDays": 14, "theme": "dark"}'
    real_replace = hardening._replace_path
    saved = False

    def replace_and_save_other(source, destination):
        nonlocal saved
        real_replace(source, destination)
        if destination == first and not saved:
            saved = True
            second.write_bytes(saved_second)

    monkeypatch.setattr(hardening, "_replace_path", replace_and_save_other)

    assert _apply(first, second) == 0
    assert first.read_bytes() == original_first
    assert second.read_bytes() == saved_second
    record = _records()[0]
    assert record["status"] == "pending"
    assert record["files"][str(first)]["write_state"] == "written"
    assert record["files"][str(second)]["write_state"] == "prepared"
    assert all(Path(meta["backup"]).exists() for meta in record["files"].values())
    assert hardening.rollback_last() == 0
    assert second.read_bytes() == saved_second


def test_group_failure_preserves_later_save_to_written_member(config_state, monkeypatch):
    first, second = config_state
    original_second = second.read_bytes()
    saved_first = b'{"sessionRetentionDays": 7, "theme": "dark"}'
    real_write = hardening._atomic_write_json

    def stop_second(path, value, **kwargs):
        if path == second:
            first.write_bytes(saved_first)
            return False
        return real_write(path, value, **kwargs)

    monkeypatch.setattr(hardening, "_atomic_write_json", stop_second)

    assert _apply(first, second) == 0
    assert first.read_bytes() == saved_first
    assert second.read_bytes() == original_second
    assert len(_records()) == 1


def test_manual_rollback_preserves_later_product_save(config_state):
    first, _ = config_state
    assert hardening._patch_json_config(first, "sessionRetentionDays", 7, "H003")
    saved = b'{"sessionRetentionDays": 7, "theme": "dark"}'
    first.write_bytes(saved)
    before = _records()

    assert hardening.rollback_last() == 0
    assert first.read_bytes() == saved
    assert _records() == before


def test_restore_rechecks_current_file_after_preparing_backup(config_state, monkeypatch):
    first, _ = config_state
    assert hardening._patch_json_config(first, "sessionRetentionDays", 7, "H003")
    saved = b'{"sessionRetentionDays": 7, "theme": "dark"}'
    real_copy = hardening.shutil.copy2

    def copy_and_save(source, destination, *args, **kwargs):
        result = real_copy(source, destination, *args, **kwargs)
        if Path(destination).suffix == ".rollback":
            first.write_bytes(saved)
        return result

    monkeypatch.setattr(hardening.shutil, "copy2", copy_and_save)

    assert hardening.rollback_last() == 0
    assert first.read_bytes() == saved
    assert len(_records()) == 1


def test_failed_written_receipt_restores_exact_transaction_output(config_state, monkeypatch):
    first, _ = config_state
    original = first.read_bytes()
    real_save = hardening._save_action_record

    def fail_written_receipt(entry):
        if any(meta["write_state"] == "written" for meta in entry["files"].values()):
            return False
        return real_save(entry)

    monkeypatch.setattr(hardening, "_save_action_record", fail_written_receipt)

    assert not hardening._patch_json_config(first, "sessionRetentionDays", 7, "H003")
    assert first.read_bytes() == original
    assert _records() == []


def test_interrupt_after_replacement_leaves_recoverable_writing_record(config_state, monkeypatch):
    first, _ = config_state
    original = first.read_bytes()
    real_replace = hardening._replace_path

    def interrupt_after_write(source, destination):
        real_replace(source, destination)
        if destination == first:
            raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(hardening, "_replace_path", interrupt_after_write)
        with pytest.raises(KeyboardInterrupt):
            hardening._patch_json_config(first, "sessionRetentionDays", 7, "H003")

    assert _records()[0]["files"][str(first)]["write_state"] == "writing"
    assert hardening.rollback_last() == 1
    assert first.read_bytes() == original


def test_save_after_replacement_is_not_mistaken_for_transaction_output(config_state, monkeypatch):
    first, _ = config_state
    saved = b'{"sessionRetentionDays": 14, "theme": "dark"}'
    real_replace = hardening._replace_path

    def replace_and_save(source, destination):
        real_replace(source, destination)
        if destination == first:
            first.write_bytes(saved)

    monkeypatch.setattr(hardening, "_replace_path", replace_and_save)

    assert not hardening._patch_json_config(first, "sessionRetentionDays", 7, "H003")
    assert first.read_bytes() == saved
    assert _records()[0]["files"][str(first)]["written_digest"] != hardening._file_digest(first)


def test_legacy_records_remain_readable_without_overwriting_uncertain_content(config_state):
    first, _ = config_state
    assert hardening._patch_json_config(first, "sessionRetentionDays", 7, "H003")
    record = _records()[0]
    record["version"] = 2
    for metadata in record["files"].values():
        del metadata["write_state"]
        del metadata["written_digest"]
    assert hardening._save_hardening_log([record])
    saved = first.read_bytes()

    assert _records() == [record]
    assert hardening.rollback_last() == 0
    assert first.read_bytes() == saved
    assert _records() == [record]
    assert Path(record["files"][str(first)]["backup"]).is_file()


def test_legacy_permission_record_still_restores(config_state, monkeypatch):
    first, _ = config_state
    assert hardening._record_hardening_action(
        "H009", {}, {str(first): {"platform": "unix", "mode": 0o600}}
    )
    record = _records()[0]
    record["version"] = 2
    assert hardening._save_hardening_log([record])
    restored = []
    monkeypatch.setattr(
        utils,
        "restore_file_permission",
        lambda path, snapshot: restored.append((path, snapshot)) or True,
    )

    assert hardening.rollback_last() == 1
    assert restored == [(first, {"platform": "unix", "mode": 0o600})]
    assert _records() == []


def test_credential_inspection_error_aborts_before_permission_changes(config_state, monkeypatch):
    calls = []

    def unknown(_path):
        raise utils.PermissionCheckError("inspection unavailable")

    monkeypatch.setattr(utils, "check_file_permission", unknown)

    assert hardening._fix_cred_perms(
        permission_capturer=lambda *_args: {"platform": "unix", "mode": 0o600},
        permission_fixer=lambda *args, **kwargs: calls.append(args) or True,
    ) is False
    assert calls == []
    assert _records() == []
