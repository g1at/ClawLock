from __future__ import annotations

import json

from typer.testing import CliRunner


runner = CliRunner()


def test_mcp_live_requires_existing_config():
    from clawlock.__main__ import app

    result = runner.invoke(app, ["mcp-live", "missing-mcp.json"])

    assert result.exit_code == 2
    assert "Path does not exist" in result.stderr


def test_mcp_live_does_not_start_stdio_without_execute(tmp_path):
    from clawlock.__main__ import app

    marker = tmp_path / "started"
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "python",
                        "args": ["-c", f"open({str(marker)!r}, 'w').write('yes')"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["mcp-live", str(config), "--format", "json"])

    assert result.exit_code == 2
    assert not marker.exists()
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"


def test_static_mcp_scan_includes_runtime_launch_audit(tmp_path):
    from clawlock.adapters import get_adapter
    from clawlock.scanners import scan_mcp

    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "command": "npx",
                        "args": ["-y", "some-server@latest"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    findings = scan_mcp(get_adapter("generic"), extra_mcp=str(config))

    assert any(
        finding.metadata.get("rule_id") == "MCP-LAUNCH-UNPINNED"
        for finding in findings
    )
    assert any(
        finding.metadata.get("rule_id") == "MCP-LAUNCH-AUTO-INSTALL"
        for finding in findings
    )


def test_dynamic_scan_requires_existing_target():
    from clawlock.__main__ import app

    result = runner.invoke(
        app,
        [
            "dynamic-scan",
            "missing-skill",
            "--image",
            "example/analyzer@sha256:" + "a" * 64,
            "--entrypoint-json",
            '["--", "python", "/workspace/main.py"]',
        ],
    )

    assert result.exit_code == 2
    assert "Path does not exist" in result.stderr


def test_dynamic_scan_is_blocked_without_consent(tmp_path):
    from clawlock.__main__ import app

    result = runner.invoke(
        app,
        [
            "dynamic-scan",
            str(tmp_path),
            "--image",
            "example/analyzer@sha256:" + "a" * 64,
            "--entrypoint-json",
            '["--", "python", "/workspace/main.py"]',
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert any(
        finding["metadata"].get("scan_status") == "error"
        for finding in payload["findings"]
    )


def test_supply_chain_requested_missing_tool_is_incomplete(tmp_path, monkeypatch):
    from clawlock.__main__ import app
    from clawlock.scanners import supply_chain as supply_module

    monkeypatch.setattr(supply_module.shutil, "which", lambda _name: None)
    result = runner.invoke(
        app,
        ["supply-chain", str(tmp_path), "--osv", "--format", "json"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert any(
        finding["metadata"].get("component") == "osv-scanner"
        and finding["metadata"].get("requested") is True
        for finding in payload["findings"]
    )


def test_supply_chain_cli_blocks_provenance_digest_mismatch(tmp_path):
    from clawlock.__main__ import app

    provenance = tmp_path / "provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {"name": "dist/demo.whl", "digest": {"sha256": "a" * 64}}
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "resolvedDependencies": [
                            {"uri": "git+https://example.invalid/demo@" + "c" * 40}
                        ]
                    },
                    "runDetails": {"builder": {"id": "https://builder.invalid/v1"}},
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "supply-chain",
            str(tmp_path),
            "--provenance",
            str(provenance),
            "--expected-digest",
            "b" * 64,
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert any(
        finding["metadata"].get("rule_id") == "SLSA-DIGEST-MISMATCH-001"
        for finding in payload["findings"]
    )


def test_runtime_scan_blocks_privileged_runtime(tmp_path):
    from clawlock.__main__ import app

    compose = tmp_path / "compose.yaml"
    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: alpine:latest\n"
        "    privileged: true\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["runtime-scan", str(compose), "--format", "json"]
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "COMPLETE"
    assert any(
        finding["metadata"].get("rule_id") == "RUN-PRIVILEGED-001"
        for finding in payload["findings"]
    )


def test_runtime_scan_parse_failure_exits_incomplete(tmp_path):
    from clawlock.__main__ import app

    compose = tmp_path / "compose.yaml"
    compose.write_text("services: [unterminated\n", encoding="utf-8")

    result = runner.invoke(
        app, ["runtime-scan", str(compose), "--format", "json"]
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "INCOMPLETE"
    assert any(
        finding["metadata"].get("scan_status") == "error"
        for finding in payload["findings"]
    )


def test_runtime_scan_empty_directory_exits_incomplete(tmp_path):
    from clawlock.__main__ import app

    result = runner.invoke(
        app, ["runtime-scan", str(tmp_path), "--format", "json"]
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "INCOMPLETE"
    assert any(
        finding["metadata"].get("rule_id") == "RUN-INCOMPLETE-001"
        for finding in payload["findings"]
    )


def test_skill_scan_includes_runtime_manifest_findings(tmp_path):
    from clawlock.scanners import scan_skill

    (tmp_path / "SKILL.md").write_text("# Safe skill\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:latest\nUSER root\n", encoding="utf-8"
    )

    findings = scan_skill(tmp_path)

    assert any(
        finding.metadata.get("rule_id") == "RUN-ROOT-001" for finding in findings
    )
