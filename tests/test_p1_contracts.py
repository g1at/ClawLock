"""Regression tests for scan completion, history, and domain attribution."""

from __future__ import annotations

import asyncio
import sqlite3
from copy import deepcopy

import pytest
from typer.testing import CliRunner

from clawlock.scanners import HIGH, INFO, WARN, Finding


runner = CliRunner()


def test_strict_config_load_does_not_mask_broken_primary(tmp_path):
    from clawlock.adapters import ConfigLoadError, get_adapter, load_config

    primary = tmp_path / "primary.json"
    fallback = tmp_path / "fallback.json"
    primary.write_text("{broken", encoding="utf-8")
    fallback.write_text('{"approvalMode": "always"}', encoding="utf-8")
    adapter = deepcopy(get_adapter("generic"))
    adapter.config_paths = [str(primary), str(fallback)]

    with pytest.raises(ConfigLoadError) as exc_info:
        load_config(adapter, strict=True)

    assert exc_info.value.path == primary
    assert load_config(adapter, strict=False) == (
        {"approvalMode": "always"},
        str(fallback),
    )


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ('{"api_key": "custom-secret-value-123456"}', "custom-secret-value-123456"),
        ('password = "correct horse battery staple"', "correct horse battery staple"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ],
    ids=("quoted-json-key", "quoted-password-with-spaces", "basic-authorization"),
)
def test_llm_transport_redacts_architecture_leak_examples(
    source, secret, monkeypatch
):
    import clawlock.scanners.agent_scan as agent_scan

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"asi":"ASI-01","severity":"info",'
                                '"title":"ok","detail":"ok","remediation":""}'
                            )
                        }
                    }
                ]
            }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, _url, **kwargs):
            captured["request"] = kwargs["json"]
            return FakeResponse()

    monkeypatch.setattr(
        agent_scan.httpx,
        "AsyncClient",
        lambda **_kwargs: FakeClient(),
    )

    findings = asyncio.run(
        agent_scan.scan_agent_llm(
            source,
            api_key="transport-test-key",
            base_url="https://llm.example.test",
        )
    )

    outbound = captured["request"]["messages"][-1]["content"]
    assert secret not in outbound
    assert "[REDACTED]" in outbound
    assert findings[0].metadata["source"] == "llm"


def test_quote_aware_yaml_fallback_redacts_sensitive_values_and_bearer():
    from clawlock.scanners.agent_scan import _redact_text_for_llm

    source = """
'password': 'yaml password with spaces'
"secret": "yaml secret with spaces"
'token': 'yaml token with spaces'
"api key": "yaml api key with spaces"
Authorization: Bearer bearer-value-123456
""".strip()

    redacted = _redact_text_for_llm(source)

    for secret in (
        "yaml password with spaces",
        "yaml secret with spaces",
        "yaml token with spaces",
        "yaml api key with spaces",
        "bearer-value-123456",
    ):
        assert secret not in redacted
    assert redacted.count("[REDACTED]") == 5


def _isolate_history(monkeypatch, tmp_path):
    import clawlock.utils as utils

    monkeypatch.setattr(utils, "DB_PATH", tmp_path / "history.db")
    monkeypatch.setattr(utils, "HISTORY_FILE", tmp_path / "history.json")
    monkeypatch.setattr(utils, "_LEGACY_IMPORTED_FLAG", tmp_path / ".imported")
    return utils


def test_incomplete_report_persists_nullable_score_and_status(tmp_path, monkeypatch):
    import clawlock.reporters as reporters

    utils = _isolate_history(monkeypatch, tmp_path)
    monkeypatch.setattr(utils, "device_fingerprint", lambda: "test-device")

    reporters.render_scan_report(
        "Generic Claw",
        "unknown",
        {
            "Processes": [
                Finding(
                    "internal",
                    WARN,
                    "Scanner failed: Processes",
                    "access denied",
                )
            ]
        },
        output_format="json",
        output_path=str(tmp_path / "report.json"),
    )

    record = utils.get_scan_history(1)[0]
    assert record["complete"] is False
    assert record["status"] == "incomplete"
    assert record["score"] is None
    assert record["partial_score"] == 100
    with sqlite3.connect(utils.DB_PATH) as conn:
        assert conn.execute(
            "SELECT score, complete, status, partial_score FROM scans"
        ).fetchone() == (None, 0, "incomplete", 100)


def test_legacy_history_schema_migrates_as_complete_without_losing_findings(
    tmp_path, monkeypatch
):
    utils = _isolate_history(monkeypatch, tmp_path)
    with sqlite3.connect(utils.DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                adapter TEXT NOT NULL DEFAULT '',
                device TEXT NOT NULL DEFAULT '',
                score INTEGER NOT NULL DEFAULT 0,
                critical INTEGER NOT NULL DEFAULT 0,
                warning INTEGER NOT NULL DEFAULT 0,
                total INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                level TEXT NOT NULL DEFAULT 'info',
                location TEXT NOT NULL DEFAULT '',
                measure_ids TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            INSERT INTO scans
                (time, adapter, device, score, critical, warning, total)
            VALUES ('2026-01-01T00:00:00', 'legacy', 'device', 85, 1, 2, 3);
            INSERT INTO findings
                (scan_id, title, level, location, measure_ids)
            VALUES (1, 'legacy finding', 'high', 'config.json', '[]');
            """
        )

    record = utils.get_scan_history(1)[0]
    assert record["score"] == 85
    assert record["complete"] is True
    assert record["status"] == "complete"
    assert record["findings"][0]["title"] == "legacy finding"
    with sqlite3.connect(utils.DB_PATH) as conn:
        score_column = next(
            row for row in conn.execute("PRAGMA table_info(scans)") if row[1] == "score"
        )
        assert score_column[3] == 0


def test_history_marks_incomplete_and_excludes_it_from_trend(monkeypatch):
    import clawlock.__main__ as cli
    import clawlock.utils as utils

    monkeypatch.setattr(
        utils,
        "get_scan_history",
        lambda _limit: [
            {
                "time": "2026-01-01T00:00:00",
                "adapter": "legacy",
                "score": 80,
                "critical": 0,
                "warning": 0,
                "device": "one",
            },
            {
                "time": "2026-01-02T00:00:00",
                "adapter": "broken",
                "score": None,
                "partial_score": 99,
                "complete": False,
                "status": "incomplete",
                "critical": 0,
                "warning": 1,
                "device": "two",
            },
            {
                "time": "2026-01-03T00:00:00",
                "adapter": "current",
                "score": 90,
                "complete": True,
                "status": "complete",
                "critical": 0,
                "warning": 0,
                "device": "three",
            },
        ],
    )

    result = runner.invoke(cli.app, ["history", "--limit", "3"])

    assert result.exit_code == 0
    assert "INCOMPLETE" in result.stdout
    assert "Score up 80 -> 90" in result.stdout
    assert "80 -> 99" not in result.stdout
    assert "99 -> 90" not in result.stdout


def test_agent_summary_is_incomplete_when_llm_attempt_fails(tmp_path, monkeypatch):
    import clawlock.scanners.agent_scan as agent_scan

    source = tmp_path / "agent.py"
    source.write_text("def safe():\n    return True\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def failed_llm(*_args, **_kwargs):
        return [
            Finding(
                "agent_scan_llm",
                INFO,
                "LLM analysis request failed",
                "network unavailable",
                metadata={
                    "scan_status": "error",
                    "component": "agent_scan_llm",
                    "requested": True,
                },
            )
        ]

    monkeypatch.setattr(agent_scan, "scan_agent_llm", failed_llm)
    findings = agent_scan.scan_agent(code_path=source, enable_llm=True)
    summary = findings[0]

    assert "Agent-Scan INCOMPLETE" in summary.title
    assert "Agent-Scan complete:" not in summary.title
    assert summary.metadata["llm_attempted"] is True
    assert summary.metadata["llm_completed"] is False
    assert summary.metadata["complete"] is False
    assert summary.metadata["security_finding_count"] == 0
    assert summary.metadata["diagnostic_count"] == 1


def test_agent_scan_auto_discovered_malformed_config_exits_incomplete(
    tmp_path, monkeypatch
):
    import clawlock.__main__ as cli
    import clawlock.adapters as adapters

    config_path = tmp_path / "broken.json"
    config_path.write_text("{broken", encoding="utf-8")
    spec = deepcopy(adapters.get_adapter("generic"))
    spec.config_paths = [str(config_path)]
    monkeypatch.setattr(adapters, "get_adapter", lambda _name: spec)

    result = runner.invoke(cli.app, ["agent-scan", "--adapter", "generic"])

    assert result.exit_code == 2
    assert "Scanner failed: Agent Config" in result.stdout
    assert "Agent-Scan INCOMPLETE" in result.stdout
    assert "Agent-Scan complete:" not in result.stdout


def test_agent_llm_and_redteam_findings_map_to_agent_domain():
    from clawlock.reporters import _SCANNER_TO_DOMAIN, _build_domain_report

    agent_domain = _SCANNER_TO_DOMAIN["agent_scan"]
    config_domain = _SCANNER_TO_DOMAIN["config"]
    for scanner, level in (("agent_scan_llm", HIGH), ("redteam", WARN)):
        _, _, scores, _, _ = _build_domain_report(
            [Finding(scanner, level, "finding", "detail")]
        )
        assert scores[agent_domain] < 100
        assert scores[config_domain] == 100


def test_unknown_scanner_does_not_pollute_config_domain():
    from clawlock.reporters import _SCANNER_TO_DOMAIN, _build_domain_report

    _, _, scores, _, overall_score = _build_domain_report(
        [Finding("future_scanner", HIGH, "finding", "detail")]
    )

    assert scores[_SCANNER_TO_DOMAIN["config"]] == 100
    assert overall_score < 100
