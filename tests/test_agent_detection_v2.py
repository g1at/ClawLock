from __future__ import annotations

import os

import pytest

from clawlock.scanners import agent_scan


def test_agent_code_reports_unsupported_explicit_file(tmp_path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"not source")

    findings = agent_scan.scan_agent_code(target)

    assert any(f.metadata.get("scan_status") == "error" for f in findings)


def test_agent_code_reports_oversized_source(tmp_path, monkeypatch) -> None:
    target = tmp_path / "large.py"
    target.write_text("x = '123456789'\n", encoding="utf-8")
    monkeypatch.setattr(agent_scan, "_AGENT_CODE_MAX_FILE_BYTES", 8)

    findings = agent_scan.scan_agent_code(target)

    assert any("limit" in f.detail for f in findings)
    assert any(f.metadata.get("scan_status") == "error" for f in findings)


def test_agent_code_safe_regular_file_has_no_coverage_error(tmp_path) -> None:
    target = tmp_path / "safe.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    findings = agent_scan.scan_agent_code(target)

    assert not any(f.metadata.get("scan_status") == "error" for f in findings)


def test_agent_scan_includes_runtime_manifest_audit(tmp_path) -> None:
    (tmp_path / "agent.py").write_text("print('agent')\n", encoding="utf-8")
    (tmp_path / "compose.yaml").write_text(
        "services:\n  agent:\n    image: demo:latest\n    privileged: true\n",
        encoding="utf-8",
    )

    findings = agent_scan.scan_agent(code_path=tmp_path)

    assert any(
        finding.metadata.get("rule_id") == "RUN-PRIVILEGED-001"
        for finding in findings
    )


@pytest.mark.skipif(os.name == "nt", reason="symlink privileges vary on Windows")
def test_agent_code_refuses_explicit_symlink(tmp_path) -> None:
    source = tmp_path / "source.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    target = tmp_path / "linked.py"
    target.symlink_to(source)

    findings = agent_scan.scan_agent_code(target)

    assert any(f.metadata.get("scan_status") == "error" for f in findings)
