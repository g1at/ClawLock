from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from clawlock.scanners.dynamic import (
    EVENT_PREFIX,
    BehaviorEvent,
    SandboxPolicy,
    analyze_behavior,
    build_container_command,
    parse_behavior_events,
    resolve_container_engine,
    run_dynamic_analysis,
)


PINNED_IMAGE = "example/clawlock-analyzer@sha256:" + "a" * 64


def test_container_command_enforces_read_only_least_privilege(tmp_path):
    command = build_container_command(
        "docker",
        tmp_path,
        PINNED_IMAGE,
        ["analyze", "/workspace"],
    )

    joined = " ".join(command)
    assert "--pull=never" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--cap-add=SYS_PTRACE" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--ipc=none" in command
    assert "--network=none" in command
    assert "readonly" in joined
    assert command[-3:] == [PINNED_IMAGE, "analyze", "/workspace"]


def test_container_command_rejects_mutable_image_and_host_network(tmp_path):
    with pytest.raises(ValueError, match="pinned"):
        build_container_command("docker", tmp_path, "example/latest", ["analyze"])
    with pytest.raises(ValueError, match="Host networking"):
        build_container_command(
            "docker",
            tmp_path,
            PINNED_IMAGE,
            ["analyze"],
            policy=SandboxPolicy(network="host"),
        )


def test_engine_resolution_never_executes_current_directory_dropper(
    tmp_path, monkeypatch
):
    dropper = tmp_path / ("docker.exe" if os.name == "nt" else "docker")
    dropper.write_text("not a trusted engine", encoding="utf-8")
    dropper.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".EXE;.CMD;.BAT")

    assert resolve_container_engine("docker") is None


def test_single_file_mount_does_not_expose_sibling_files(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("print('ok')", encoding="utf-8")
    (tmp_path / "host-secret.txt").write_text("secret", encoding="utf-8")

    command = build_container_command("docker", target, PINNED_IMAGE, ["analyze"])
    mount = command[command.index("--mount") + 1]

    assert f"src={target.resolve()}" in mount
    assert f"dst=/workspace/{target.name}" in mount
    assert f"src={tmp_path.resolve()}," not in mount


def test_container_command_rejects_link_target(tmp_path):
    real = tmp_path / "real.py"
    real.write_text("print('ok')", encoding="utf-8")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(ValueError, match="symlink|reparse"):
        build_container_command("docker", link, PINNED_IMAGE, ["analyze"])


def test_event_parser_fails_closed_on_malformed_and_empty_stream():
    events, issues = parse_behavior_events(EVENT_PREFIX + "{broken}\n")

    assert events == []
    assert {issue.rule_id for issue in issues} == {
        "DYN-EVENT-MALFORMED",
        "DYN-EVENT-NONE",
    }
    assert all(issue.evidence.get("scan_status") == "incomplete" for issue in issues)


def test_behavior_correlation_builds_attack_chains():
    events = [
        BehaviorEvent(kind="file_read", target="/home/user/.ssh/id_rsa", pid=10),
        BehaviorEvent(kind="network", target="https://evil.invalid/u", pid=10),
        BehaviorEvent(
            kind="download",
            target="https://evil.invalid/payload.py",
            pid=10,
            labels=("DOWNLOAD",),
            metadata={"path": "/tmp/payload.py"},
        ),
        BehaviorEvent(kind="exec", target="/tmp/payload.py", pid=10),
        BehaviorEvent(kind="file_write", target="/etc/systemd/system/backdoor.service", pid=10),
        BehaviorEvent(kind="file_read", target="/var/run/docker.sock", pid=10),
    ]

    rule_ids = {issue.rule_id for issue in analyze_behavior(events)}
    assert {
        "DYN-SENSITIVE-EXFIL",
        "DYN-DOWNLOAD-EXEC",
        "DYN-PERSISTENCE",
        "DYN-HOST-ESCAPE",
    } <= rule_ids


def test_dynamic_runner_does_nothing_without_consent(tmp_path, monkeypatch):
    called = False

    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not execute")

    monkeypatch.setattr("clawlock.scanners.dynamic._run_bounded_process", forbidden)
    result = run_dynamic_analysis(tmp_path, PINNED_IMAGE, ["analyze"])

    assert result.status == "blocked"
    assert called is False


def test_dynamic_runner_reports_missing_sandbox_instead_of_host_fallback(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "clawlock.scanners.dynamic.resolve_container_engine", lambda preferred="": None
    )

    result = run_dynamic_analysis(
        tmp_path,
        PINNED_IMAGE,
        ["analyze"],
        allow_execute=True,
    )

    assert result.status == "unavailable"
    assert result.issues[0].evidence["scan_status"] == "incomplete"


def test_dynamic_runner_redacts_canary_and_reports_exfil(tmp_path, monkeypatch):
    captured = {}

    monkeypatch.setattr(
        "clawlock.scanners.dynamic.resolve_container_engine",
        lambda preferred="": "docker",
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        assert "--env=CLAWLOCK_CANARY_SECRET" in command
        assert not any(
            value.startswith("--env=CLAWLOCK_CANARY_SECRET=") for value in command
        )
        secret = kwargs["env"]["CLAWLOCK_CANARY_SECRET"]
        captured["secret"] = secret
        event = {
            "kind": "network",
            "target": f"https://evil.invalid/?value={secret}",
            "pid": 42,
            "metadata": {"payload": secret},
        }
        return SimpleNamespace(
            returncode=0,
            stdout=EVENT_PREFIX + json.dumps(event) + "\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr("clawlock.scanners.dynamic._run_bounded_process", fake_run)
    result = run_dynamic_analysis(
        tmp_path,
        PINNED_IMAGE,
        ["analyze", "/workspace"],
        allow_execute=True,
    )

    assert result.status == "complete"
    assert any(issue.rule_id == "DYN-CANARY-EXFIL" for issue in result.issues)
    assert captured["secret"] not in result.stdout
    assert captured["secret"] not in result.events[0].target
    assert result.events[0].metadata["canary_ids"] == ["CLAWLOCK_CANARY_SECRET"]


def test_dynamic_runner_marks_bounded_capture_overflow_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "clawlock.scanners.dynamic.resolve_container_engine", lambda preferred="": "docker"
    )
    event = EVENT_PREFIX + json.dumps({"kind": "process", "pid": 1}) + "\n"

    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=event,
            stderr="x" * 32,
            stdout_truncated=True,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr("clawlock.scanners.dynamic._run_bounded_process", fake_run)
    result = run_dynamic_analysis(
        tmp_path, PINNED_IMAGE, ["analyze"], allow_execute=True
    )

    assert result.status == "incomplete"
    assert any(issue.rule_id == "DYN-OUTPUT-TRUNCATED" for issue in result.issues)


def test_dynamic_runner_honors_structured_analyzer_diagnostic(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "clawlock.scanners.dynamic.resolve_container_engine", lambda preferred="": "docker"
    )
    diagnostic = {
        "kind": "analyzer_diagnostic",
        "metadata": {"scan_status": "incomplete", "reason": "trace budget"},
    }

    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=EVENT_PREFIX + json.dumps(diagnostic) + "\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr("clawlock.scanners.dynamic._run_bounded_process", fake_run)
    result = run_dynamic_analysis(
        tmp_path, PINNED_IMAGE, ["analyze"], allow_execute=True
    )

    assert result.status == "incomplete"
    assert any(
        issue.rule_id == "DYN-ANALYZER-DIAGNOSTIC" for issue in result.issues
    )


def test_timeout_removes_only_the_generated_container(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "clawlock.scanners.dynamic.resolve_container_engine", lambda preferred="": "docker"
    )
    generated_name = ""

    def fake_run(command, **kwargs):
        nonlocal generated_name
        if command[1] == "run":
            name_arg = next(value for value in command if value.startswith("--name="))
            generated_name = name_arg.split("=", 1)[1]
            return SimpleNamespace(
                returncode=-1,
                stdout="",
                stderr="",
                stdout_truncated=False,
                stderr_truncated=False,
                timed_out=True,
            )
        assert command == ["docker", "rm", "-f", "--", generated_name]
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr("clawlock.scanners.dynamic._run_bounded_process", fake_run)
    result = run_dynamic_analysis(
        tmp_path, PINNED_IMAGE, ["analyze"], allow_execute=True
    )

    assert generated_name.startswith("clawlock-")
    assert result.status == "incomplete"
    assert any(issue.rule_id == "DYN-CONTAINER-CLEANUP" for issue in result.issues)
