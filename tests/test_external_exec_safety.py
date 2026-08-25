"""Regression tests for trusted external-command execution."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_trusted_binary_resolution_rejects_current_directory_dropper(
    tmp_path, monkeypatch
):
    import clawlock.utils as utils

    dropper = tmp_path / "promptfoo.exe"
    dropper.write_bytes(b"not a real executable")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(utils, "IS_WINDOWS", True)
    monkeypatch.setenv("PATHEXT", ".EXE")
    monkeypatch.setenv("PATH", f"{os.curdir}{os.pathsep}{tmp_path}")

    assert utils.resolve_trusted_binary("promptfoo") is None
    assert utils.resolve_trusted_binary(str(dropper)) is None


def test_trusted_binary_resolution_ignores_empty_and_relative_path_entries(
    tmp_path, monkeypatch
):
    import clawlock.utils as utils

    dropper_dir = tmp_path / "relative-bin"
    dropper_dir.mkdir()
    (dropper_dir / "promptfoo.exe").write_bytes(b"dropper")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(utils, "IS_WINDOWS", True)
    monkeypatch.setenv("PATHEXT", ".EXE")

    unsafe_path = os.pathsep.join(("", ".", "relative-bin", ""))
    assert utils.resolve_trusted_binary("promptfoo", path=unsafe_path) is None


def test_bounded_command_fails_closed_when_stdout_is_oversized():
    from clawlock.utils import CommandOutputTruncated, run_bounded_command

    with pytest.raises(CommandOutputTruncated, match="safety limit"):
        run_bounded_command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 65536)"],
            timeout=10,
            max_output_bytes=1024,
        )


def test_bounded_command_terminates_on_timeout():
    from clawlock.utils import run_bounded_command

    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=0.2,
            max_output_bytes=1024,
        )


def test_promptfoo_scrubs_secrets_from_child_stderr(monkeypatch):
    import clawlock.integrations.promptfoo as promptfoo
    from clawlock.utils import BoundedCommandResult

    promptfoo_path = str(Path(sys.executable).resolve())
    monkeypatch.setattr(promptfoo, "_promptfoo_binary", lambda: promptfoo_path)

    secret_stderr = (
        "Authorization: Bearer auth-secret "
        "OPENAI_API_KEY=key-secret "
        "https://alice:pass-secret@example.test/run?token=query-secret&debug=1"
    )

    def failed(command, **_kwargs):
        return BoundedCommandResult(list(command), 2, "", secret_stderr)

    monkeypatch.setattr(promptfoo, "run_bounded_command", failed)
    finding = promptfoo.run_redteam("http://127.0.0.1:8000")[0]

    assert finding.metadata["scan_status"] == "error"
    assert "auth-secret" not in finding.detail
    assert "key-secret" not in finding.detail
    assert "pass-secret" not in finding.detail
    assert "query-secret" not in finding.detail
    assert "[REDACTED]" in finding.detail


def test_promptfoo_reports_output_truncation_as_execution_error(monkeypatch):
    import clawlock.integrations.promptfoo as promptfoo
    from clawlock.utils import CommandOutputTruncated

    promptfoo_path = str(Path(sys.executable).resolve())
    monkeypatch.setattr(promptfoo, "_promptfoo_binary", lambda: promptfoo_path)

    def oversized(command, **_kwargs):
        raise CommandOutputTruncated(command, promptfoo._PROMPTFOO_OUTPUT_LIMIT)

    monkeypatch.setattr(promptfoo, "run_bounded_command", oversized)
    finding = promptfoo.run_redteam("http://127.0.0.1:8000")[0]

    assert finding.metadata["scan_status"] == "error"
    assert "safety limit" in finding.detail
