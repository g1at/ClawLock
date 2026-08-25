"""CLI trust-boundary and incomplete-scan contract tests."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from clawlock.scanners import HIGH, INFO, WARN, Finding


runner = CliRunner()


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--adapter", "typo"],
        ["scan", "--format", "yaml"],
        ["scan", "--mode", "enfore"],
        ["skill", "README.md", "--no-cloud", "--format", "html"],
    ],
)
def test_cli_rejects_unsupported_choice_values(args):
    from clawlock.__main__ import app

    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert "Unsupported value" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["skill", "missing-skill", "--no-cloud"],
        ["precheck", "missing-SKILL.md"],
        ["mcp-scan", "missing-mcp-source"],
        ["agent-scan", "--code", "missing-agent-source"],
        ["agent-scan", "--config", "missing-agent-config.json"],
        ["scan", "--skills-dir", "missing-skills-directory"],
        ["scan", "--soul", "missing-SOUL.md"],
        ["scan", "--mcp-config", "missing-mcp-config.json"],
    ],
)
def test_explicit_missing_input_paths_exit_two(args):
    from clawlock.__main__ import app

    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert "Path does not exist" in result.output


def test_agent_scan_rejects_invalid_json_config(tmp_path):
    from clawlock.__main__ import app

    config = tmp_path / "agent.json"
    config.write_text("{not-json", encoding="utf-8")

    result = runner.invoke(app, ["agent-scan", "--config", str(config)])

    assert result.exit_code == 2
    assert "Could not read valid JSON config" in result.output


def test_redteam_requires_positive_test_count():
    from clawlock.__main__ import app

    result = runner.invoke(
        app,
        ["redteam", "https://agent.example.test", "--num-tests", "0"],
    )

    assert result.exit_code == 2
    assert "Number of tests must be greater than 0" in result.output


def test_requested_redteam_skip_is_incomplete(monkeypatch):
    import clawlock.__main__ as cli
    import clawlock.integrations.promptfoo as promptfoo

    monkeypatch.setattr(
        promptfoo,
        "run_redteam",
        lambda *_args, **_kwargs: [
            Finding(
                "redteam",
                INFO,
                "promptfoo not installed",
                "Install promptfoo and retry.",
                metadata={"scan_status": "skipped", "requested": True},
            )
        ],
    )

    result = runner.invoke(cli.app, ["redteam", "https://agent.example.test"])

    assert result.exit_code == 2
    assert "red-team run did not complete" in result.stdout
    assert "No high-risk issue was triggered" not in result.stdout


def test_requested_skip_marks_json_report_incomplete(tmp_path):
    import clawlock.reporters as reporters

    output = tmp_path / "report.json"
    reporters.render_scan_report(
        "Generic Claw",
        "unknown",
        {
            "Agent Security": [
                Finding(
                    "agent_scan_llm",
                    INFO,
                    "LLM assessment skipped",
                    "No API key was available.",
                    metadata={
                        "scan_status": "skipped",
                        "requested": True,
                        "rule_id": "ASI-TEST",
                    },
                )
            ]
        },
        output_format="json",
        output_path=str(output),
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["complete"] is False
    assert payload["diagnostics"][0]["title"] == "LLM assessment skipped"
    assert payload["diagnostics"][0]["metadata"]["rule_id"] == "ASI-TEST"
    assert payload["findings"][0]["metadata"]["rule_id"] == "ASI-TEST"


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_skill_risk_exit_code_is_format_independent(
    output_format, tmp_path, monkeypatch
):
    import clawlock.__main__ as cli

    target = tmp_path / "SKILL.md"
    target.write_text("# test", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "scan_skill",
        lambda _path: [
            Finding(
                "skill",
                HIGH,
                "High-risk behavior",
                "detail",
                metadata={"rule_id": "SKILL-TEST", "confidence": "high"},
            )
        ],
    )

    result = runner.invoke(
        cli.app,
        ["skill", str(target), "--no-cloud", "--format", output_format],
    )

    assert result.exit_code == 1
    assert "High-risk behavior" in result.stdout
    if output_format == "json":
        payload = json.loads(result.stdout)
        assert set(payload[0]) == {
            "scanner",
            "level",
            "title",
            "detail",
            "location",
            "snippet",
            "remediation",
            "metadata",
        }
        assert payload[0]["metadata"] == {
            "rule_id": "SKILL-TEST",
            "confidence": "high",
        }


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_skill_incomplete_scan_exits_two(output_format, tmp_path, monkeypatch):
    import clawlock.__main__ as cli

    target = tmp_path / "SKILL.md"
    target.write_text("# test", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "scan_skill",
        lambda _path: [
            Finding(
                "internal",
                WARN,
                "Skill file could not be read",
                "partial scan",
                metadata={
                    "scan_status": "error",
                    "requested": True,
                    "component": "skill_walk",
                },
            )
        ],
    )

    result = runner.invoke(
        cli.app,
        ["skill", str(target), "--no-cloud", "--format", output_format],
    )

    assert result.exit_code == 2
    assert "Skill file could not be read" in result.stdout


def _stub_scan_pipeline_with_failure(monkeypatch):
    import clawlock.__main__ as cli
    import clawlock.adapters as adapters
    import clawlock.integrations as integrations

    monkeypatch.setattr(cli, "get_claw_version", lambda _spec: "unknown")
    monkeypatch.setattr(adapters, "load_config", lambda _spec: ({}, None))
    monkeypatch.setattr(
        cli,
        "scan_config",
        lambda _spec: (_ for _ in ()).throw(RuntimeError("config boom")),
    )
    monkeypatch.setattr(cli, "scan_processes", lambda _spec: [])
    monkeypatch.setattr(cli, "scan_credential_dirs", lambda _spec: [])
    monkeypatch.setattr(
        cli,
        "scan_all_skills",
        lambda _spec, extra_dir=None: ([], 0),
    )
    monkeypatch.setattr(
        cli,
        "scan_soul",
        lambda _spec, soul_path=None: ([], None),
    )
    monkeypatch.setattr(cli, "scan_memory_files", lambda _spec: [])
    monkeypatch.setattr(cli, "scan_mcp", lambda _spec, extra_mcp=None: [])
    monkeypatch.setattr(integrations, "run_agent_scan", lambda **_kwargs: [])
    monkeypatch.setattr(
        cli,
        "_scanner_error_finding",
        lambda label, _exc: Finding(
            "internal",
            WARN,
            f"Scanner failed: {label}",
            "RuntimeError: config boom",
        ),
    )
    return cli


def test_enforce_incomplete_scan_exits_two_and_json_is_explicit(monkeypatch):
    cli = _stub_scan_pipeline_with_failure(monkeypatch)

    result = runner.invoke(
        cli.app,
        [
            "scan",
            "--adapter",
            "generic",
            "--no-cve",
            "--no-redteam",
            "--format",
            "json",
            "--mode",
            "enforce",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["score"] is None
    assert payload["grade"] == "INCOMPLETE"
    assert payload["diagnostics"][0]["check"] == "Config"
    assert "INCOMPLETE" in payload["domain_grades"].values()
    assert payload["partial_score"] == 100


def test_monitor_incomplete_scan_stays_zero_but_never_shows_s_grade(monkeypatch):
    cli = _stub_scan_pipeline_with_failure(monkeypatch)

    result = runner.invoke(
        cli.app,
        [
            "scan",
            "--adapter",
            "generic",
            "--no-cve",
            "--no-redteam",
            "--format",
            "text",
            "--mode",
            "monitor",
        ],
    )

    assert result.exit_code == 0
    assert "Score: N/A (scan incomplete)" in result.stdout
    assert "Grade: INCOMPLETE" in result.stdout
    assert "Grade: S" not in result.stdout


def test_incomplete_html_report_has_no_overall_s_or_numeric_score(
    tmp_path, monkeypatch
):
    import webbrowser

    import clawlock.reporters as reporters

    monkeypatch.delenv("CLAWLOCK_LANG", raising=False)
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)
    output = tmp_path / "report.html"

    reporters._render_html(
        "Generic Claw",
        "unknown",
        "2026-08-24 12:00:00",
        {
            "Config": [
                Finding(
                    "internal",
                    WARN,
                    "Scanner failed: Config",
                    "RuntimeError: config boom",
                )
            ]
        },
        str(output),
    )

    html = output.read_text(encoding="utf-8")
    assert "Scan incomplete" in html
    assert '<span class="score-num">—</span>' in html
    assert '<span class="score-grade">Incomplete</span>' in html
    assert '<span class="score-grade">S</span>' not in html


def test_watch_diff_classifies_new_persistent_and_resolved():
    from clawlock.__main__ import _diff_findings

    resolved_finding = Finding("config", WARN, "Resolved issue", "old")
    persistent_finding = Finding("config", HIGH, "Persistent issue", "same")
    new_finding = Finding("config", WARN, "New issue", "new")

    new, persistent, resolved = _diff_findings(
        [resolved_finding, persistent_finding],
        [persistent_finding, new_finding],
    )

    assert [finding.title for finding in new] == ["New issue"]
    assert [finding.title for finding in persistent] == ["Persistent issue"]
    assert [finding.title for finding in resolved] == ["Resolved issue"]


@pytest.mark.parametrize(
    "args,error_text",
    [
        (["watch", "--interval", "0", "--count", "1"], "greater than 0"),
        (["watch", "--interval", "-1", "--count", "1"], "greater than 0"),
        (["watch", "--count", "-1"], "cannot be negative"),
    ],
)
def test_watch_rejects_invalid_ranges(args, error_text):
    from clawlock.__main__ import app

    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert error_text in result.output


def test_watch_reports_finding_transitions(monkeypatch):
    import time

    import clawlock.__main__ as cli

    issue_a = Finding("config", HIGH, "Issue A", "A")
    issue_b = Finding("config", WARN, "Issue B", "B")
    config_runs = iter(
        [
            ([issue_a], None),
            ([issue_a, issue_b], None),
            ([issue_b], None),
        ]
    )
    monkeypatch.setattr(cli, "scan_config", lambda _spec: next(config_runs))
    monkeypatch.setattr(cli, "scan_soul", lambda _spec: ([], None))
    monkeypatch.setattr(cli, "scan_memory_files", lambda _spec: [])
    monkeypatch.setattr(cli, "scan_processes", lambda _spec: [])
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    result = runner.invoke(
        cli.app,
        ["watch", "--adapter", "generic", "--interval", "1", "--count", "3"],
    )

    assert result.exit_code == 0
    assert result.stdout.count("New: 1") == 2
    assert "Persistent: 1" in result.stdout
    assert "Resolved: 1" in result.stdout


def test_watch_scanner_failure_is_incomplete_not_clean(monkeypatch):
    import clawlock.__main__ as cli

    monkeypatch.setattr(
        cli,
        "scan_config",
        lambda _spec: (_ for _ in ()).throw(RuntimeError("watch boom")),
    )
    monkeypatch.setattr(cli, "scan_soul", lambda _spec: ([], None))
    monkeypatch.setattr(cli, "scan_memory_files", lambda _spec: [])
    monkeypatch.setattr(cli, "scan_processes", lambda _spec: [])
    monkeypatch.setattr(
        cli,
        "_scanner_error_finding",
        lambda label, _exc: Finding(
            "internal",
            WARN,
            f"Scanner failed: {label}",
            "RuntimeError: watch boom",
        ),
    )

    result = runner.invoke(
        cli.app,
        ["watch", "--adapter", "generic", "--interval", "1", "--count", "1"],
    )

    assert result.exit_code == 0
    assert "Watch iteration incomplete" in result.stdout
    assert "No change detected" not in result.stdout
