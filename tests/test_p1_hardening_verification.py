"""Offline checks for hardening verification status and CLI exit codes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

import clawlock.__main__ as cli
import clawlock.adapters as adapters
import clawlock.hardening as hardening
import clawlock.scanners as scanners
import clawlock.utils as utils
from clawlock.scanners import CRIT, HIGH, INFO, WARN, Finding


runner = CliRunner()
SUCCESS = {
    "en": "Config and credential scan found no critical/high issues.",
    "zh": "配置和凭证扫描未发现高危/严重问题。",
}
INCOMPLETE = {"en": "Verification incomplete", "zh": "验证不完整"}


@pytest.fixture
def verification_state(tmp_path, monkeypatch):
    state = {"config": [], "credentials": [], "calls": [], "logged": []}
    monkeypatch.setattr(hardening.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(hardening, "MEASURES", [])
    console = Console(width=180, color_system=None)
    monkeypatch.setattr(hardening, "console", console)
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(adapters, "get_adapter", lambda _name: SimpleNamespace(name="generic"))
    monkeypatch.setattr(cli, "get_adapter", adapters.get_adapter)
    monkeypatch.setattr(utils, "get_scan_history", lambda _limit: [])
    monkeypatch.setattr(
        scanners, "_log_scanner_error",
        lambda label, exc: state["logged"].append((label, type(exc).__name__)),
    )

    def inspect(domain):
        state["calls"].append(domain)
        result = state[domain]
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(scanners, "scan_config", lambda _adapter: (inspect("config"), None))
    monkeypatch.setattr(scanners, "scan_credential_dirs", lambda _adapter: inspect("credentials"))
    monkeypatch.setattr(
        hardening.Confirm, "ask", lambda *_args, **_kwargs: pytest.fail("Unexpected prompt"),
    )
    return state


def _invoke(lang, *extra):
    return runner.invoke(
        cli.app,
        ["harden", "--adapter", "generic", "--auto", "--verify", *extra],
        env={"CLAWLOCK_LANG": lang},
    )


@pytest.mark.parametrize("lang", ["en", "zh"])
@pytest.mark.parametrize(("scanner", "metadata"), [
    ("internal", {}),
    ("credential", {"scan_status": "error"}),
    ("credential", {"scan_status": "skipped", "requested": True}),
    ("credential", {"scan_status": "incomplete"}),
    ("credential", {"complete": False}),
])
def test_incomplete_takes_priority_over_remaining_risk(verification_state, lang, scanner, metadata):
    verification_state["config"] = [
        Finding(scanner, INFO, "Unavailable inspection", "Synthetic diagnostic", metadata=metadata),
    ]
    verification_state["credentials"] = [
        Finding("credential", CRIT, "Remaining credential issue", "Synthetic risk"),
    ]

    result = _invoke(lang)

    assert result.exit_code == 2, result.output
    assert INCOMPLETE[lang] in result.output
    assert SUCCESS[lang] not in result.output
    assert "Unavailable inspection" in result.output
    assert "Remaining credential issue" in result.output
    assert verification_state["calls"] == ["config", "credentials"]


@pytest.mark.parametrize("lang", ["en", "zh"])
@pytest.mark.parametrize("extra", [[], ["--from-scan"]])
def test_verification_runs_without_applying_any_changes(verification_state, lang, extra):
    result = _invoke(lang, *extra)

    assert result.exit_code == 0, result.output
    assert SUCCESS[lang] in result.output
    assert INCOMPLETE[lang] not in result.output
    assert verification_state["calls"] == ["config", "credentials"]


@pytest.mark.parametrize("lang", ["en", "zh"])
@pytest.mark.parametrize("level", [HIGH, CRIT])
def test_complete_verification_with_remaining_risk_exits_one(verification_state, lang, level):
    verification_state["config"] = [
        Finding("config", level, "Remaining configuration issue", "Synthetic risk"),
    ]

    result = _invoke(lang)

    assert result.exit_code == 1, result.output
    assert "Remaining configuration issue" in result.output
    assert SUCCESS[lang] not in result.output
    assert INCOMPLETE[lang] not in result.output


@pytest.mark.parametrize("lang", ["en", "zh"])
@pytest.mark.parametrize("failed_domain", ["config", "credentials"])
def test_scanner_exception_preserves_other_domain_results(verification_state, lang, failed_domain):
    other_domain = "credentials" if failed_domain == "config" else "config"
    verification_state[failed_domain] = OSError("Temporary inspection failure")
    verification_state[other_domain] = [
        Finding(other_domain, HIGH, "Other domain issue", "Synthetic risk"),
    ]

    result = _invoke(lang)

    assert result.exit_code == 2, result.output
    assert INCOMPLETE[lang] in result.output
    assert "Other domain issue" in result.output
    assert "OSError" in result.output
    assert SUCCESS[lang] not in result.output
    assert verification_state["calls"] == ["config", "credentials"]
    assert len(verification_state["logged"]) == 1


def test_nonrequested_skip_and_warning_do_not_make_verification_incomplete(verification_state):
    verification_state["config"] = [
        Finding("config", INFO, "Optional layer skipped", "", metadata={"scan_status": "skipped"}),
        Finding("config", WARN, "Review suggestion", ""),
    ]

    result = _invoke("en")

    assert result.exit_code == 0, result.output
    assert SUCCESS["en"] in result.output


def test_verification_runs_after_a_benign_temporary_file_action(verification_state, tmp_path, monkeypatch):
    marker = tmp_path / "action-completed.txt"

    def apply():
        marker.write_text("completed", encoding="utf-8")
        return True

    monkeypatch.setattr(hardening, "MEASURES", [
        hardening.HardenMeasure(
            "H900", "Temporary action", "Offline test", "", apply, [],
            auto_fixable=True, guidance_only=False,
        ),
    ])

    result = _invoke("en")

    assert result.exit_code == 0, result.output
    assert marker.read_text(encoding="utf-8") == "completed"
    assert verification_state["calls"] == ["config", "credentials"]
    assert SUCCESS["en"] in result.output


@pytest.mark.parametrize("lang", ["en", "zh"])
def test_rollback_verifies_without_applying_hardening_again(verification_state, monkeypatch, lang):
    rollback_calls = []
    monkeypatch.setattr(cli, "rollback_last", lambda count: rollback_calls.append(count) or 0)
    monkeypatch.setattr(
        cli, "run_hardening", lambda *_args, **_kwargs: pytest.fail("Rollback must not apply hardening"),
    )
    verification_state["credentials"] = [
        Finding("credential", INFO, "Unavailable inspection", "", metadata={"scan_status": "error"}),
    ]

    result = _invoke(lang, "--rollback")

    assert result.exit_code == 2, result.output
    assert INCOMPLETE[lang] in result.output
    assert rollback_calls == [1]
    assert verification_state["calls"] == ["config", "credentials"]


@pytest.mark.parametrize("extra", [[], ["--from-scan"]])
def test_without_verify_keeps_existing_no_scan_behavior(verification_state, extra):
    result = runner.invoke(
        cli.app, ["harden", "--adapter", "generic", "--auto", *extra],
        env={"CLAWLOCK_LANG": "en"},
    )

    assert result.exit_code == 0, result.output
    assert verification_state["calls"] == []
    assert SUCCESS["en"] not in result.output
    assert INCOMPLETE["en"] not in result.output
