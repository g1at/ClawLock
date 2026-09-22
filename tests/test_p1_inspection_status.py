"""Offline regression checks for unavailable inspection results."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from typer.testing import CliRunner

import clawlock.integrations as integrations
import clawlock.scanners as scanners
import clawlock.utils as utils


def _http_results(monkeypatch, outcomes):
    pending = iter(outcomes)
    calls = []

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, *, params):
            calls.append(dict(params))
            outcome = next(pending)
            if isinstance(outcome, Exception):
                raise outcome
            status, payload = outcome
            return httpx.Response(
                status, json=payload, request=httpx.Request("GET", url)
            )

    monkeypatch.setattr(integrations.httpx, "AsyncClient", Client)
    return calls


@pytest.mark.parametrize("outcomes", [
    [httpx.ReadTimeout("service timeout")],
    [httpx.ConnectError("service unavailable")],
    [ValueError("invalid JSON")],
    [(403, {})],
    [(503, {}), (503, {}), httpx.ReadTimeout("fallback timeout")],
])
def test_unavailable_cve_lookup_is_incomplete(monkeypatch, outcomes):
    import clawlock.__main__ as cli
    import clawlock.reporters as reporters

    _http_results(monkeypatch, outcomes)
    findings = asyncio.run(integrations.lookup_cve("Example", "1.0"))

    assert len(findings) == 1
    assert findings[0].metadata["requested"] is True
    assert cli._is_scan_error(findings[0])
    assert reporters._is_scan_diagnostic(findings[0])


@pytest.mark.parametrize("payload", [
    {}, None, {"data": None}, {"advisories": {}},
    ["invalid record"], {"data": [{"info": None}]},
])
def test_invalid_cve_response_is_incomplete(monkeypatch, payload):
    _http_results(monkeypatch, [(200, payload)])
    findings = asyncio.run(integrations.lookup_cve("Example"))
    assert findings[0].metadata["scan_status"] == "error"


@pytest.mark.parametrize("payload", [[], {"data": []}, {"advisories": []}])
def test_successful_empty_cve_response_remains_complete(monkeypatch, payload):
    _http_results(monkeypatch, [(200, payload)])
    assert asyncio.run(integrations.lookup_cve("Example")) == []


def test_successful_cve_fallback_has_no_error_diagnostic(monkeypatch):
    calls = _http_results(monkeypatch, [(503, {}), (503, {}), (200, [])])
    assert asyncio.run(integrations.lookup_cve("Example", "1.0")) == []
    assert calls == [
        {"name": "Example", "version": "1.0"},
        {"name": "example", "version": "1.0"},
        {"name": "Example"},
    ]


def test_successful_cve_advisory_is_preserved(monkeypatch):
    _http_results(monkeypatch, [(200, {"data": [{"info": {
        "cve": "example-advisory", "summary": "Example advisory",
        "severity": "medium", "details": "Synthetic advisory metadata.",
    }}]})])
    findings = asyncio.run(integrations.lookup_cve("Example"))
    assert findings[0].metadata["cve_id"] == "example-advisory"
    assert "scan_status" not in findings[0].metadata


def test_unix_permission_failure_is_not_private():
    def denied():
        raise PermissionError("unavailable")

    with pytest.raises(utils.PermissionCheckError):
        utils._check_perm_unix(SimpleNamespace(stat=denied))


@pytest.mark.parametrize("outcome", [
    SimpleNamespace(returncode=5, stdout="", stderr="denied"),
    SimpleNamespace(returncode=0, stdout="", stderr=""),
    subprocess.TimeoutExpired(["icacls"], 10),
])
def test_windows_permission_failure_is_not_private(monkeypatch, outcome):
    def inspect(*_args, **_kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(utils, "run_bounded_command", inspect)
    with pytest.raises(utils.PermissionCheckError):
        utils._check_perm_windows(Path("example.json"))


def test_missing_requested_permission_target_is_not_private(monkeypatch, tmp_path):
    monkeypatch.setattr(utils, "IS_WINDOWS", False)
    with pytest.raises(utils.PermissionCheckError):
        utils.check_file_permission(tmp_path / "missing.json")


def test_unavailable_credential_root_is_incomplete(monkeypatch, tmp_path):
    def denied(_path):
        raise utils.PermissionCheckError("unavailable")

    monkeypatch.setattr(utils, "check_file_permission", denied)
    findings = scanners.scan_credential_dirs(
        SimpleNamespace(credential_dirs=[str(tmp_path)])
    )
    assert len(findings) == 1
    assert findings[0].metadata["scan_status"] == "error"
    assert findings[0].location == str(tmp_path)


def test_unavailable_child_keeps_other_credential_results(monkeypatch, tmp_path):
    unavailable = tmp_path / "unavailable.json"
    readable = tmp_path / "readable.json"
    unavailable.write_text("{}", encoding="utf-8")
    readable.write_text("{}", encoding="utf-8")

    def inspect(path):
        if path == unavailable:
            raise utils.PermissionCheckError("unavailable")
        return path == readable, False, "synthetic permissions"

    monkeypatch.setattr(utils, "check_file_permission", inspect)
    findings = scanners.scan_credential_dirs(
        SimpleNamespace(credential_dirs=[str(tmp_path)])
    )
    assert any(f.location == str(unavailable) and f.metadata.get("scan_status") == "error" for f in findings)
    assert any(f.location == str(readable) and f.level == scanners.HIGH for f in findings)


def test_unreadable_credential_directory_is_incomplete(monkeypatch, tmp_path):
    real_iterdir = Path.iterdir

    def denied(path):
        if path == tmp_path:
            raise PermissionError("unavailable")
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied)
    monkeypatch.setattr(utils, "check_file_permission", lambda _path: (False, False, "private"))
    findings = scanners.scan_credential_dirs(SimpleNamespace(credential_dirs=[str(tmp_path)]))
    assert findings[0].metadata["scan_status"] == "error"


def test_absent_optional_credential_root_remains_skipped(tmp_path):
    assert scanners.scan_credential_dirs(
        SimpleNamespace(credential_dirs=[str(tmp_path / "not-installed")])
    ) == []


@pytest.mark.parametrize("source", ["cve", "credential"])
@pytest.mark.parametrize("mode,exit_code", [("enforce", 2), ("monitor", 0)])
def test_inspection_failure_reaches_scan_report_and_exit(monkeypatch, tmp_path, source, mode, exit_code):
    import clawlock.__main__ as cli
    import clawlock.adapters as adapters

    monkeypatch.setattr(cli, "get_claw_version", lambda _spec: "1.0")
    monkeypatch.setattr(cli, "scan_config", lambda _spec: ([], None))
    monkeypatch.setattr(cli, "scan_processes", lambda _spec: [])
    monkeypatch.setattr(cli, "scan_all_skills", lambda _spec, **_kwargs: ([], 0))
    monkeypatch.setattr(cli, "scan_soul", lambda _spec, **_kwargs: ([], None))
    monkeypatch.setattr(cli, "scan_memory_files", lambda _spec: [])
    monkeypatch.setattr(cli, "scan_mcp", lambda _spec, **_kwargs: [])
    monkeypatch.setattr(adapters, "load_config", lambda _spec: ({}, None))
    monkeypatch.setattr(integrations, "run_agent_scan", lambda **_kwargs: [])
    monkeypatch.setattr(cli, "resolve_cve_lookup", lambda *_args: (adapters.CveLookupTarget("Example", "1.0"), ""))
    _http_results(monkeypatch, [httpx.ReadTimeout("unavailable")] if source == "cve" else [(200, [])])

    def denied(_path):
        raise utils.PermissionCheckError("unavailable")

    monkeypatch.setattr(utils, "check_file_permission", denied)
    monkeypatch.setattr(cli, "scan_credential_dirs", lambda _spec: (
        scanners.scan_credential_dirs(SimpleNamespace(credential_dirs=[str(tmp_path)]))
        if source == "credential" else []
    ))
    result = CliRunner().invoke(cli.app, [
        "scan", "--adapter", "generic", "--no-redteam", "--format", "json", "--mode", mode,
    ])
    assert result.exit_code == exit_code, result.output
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["score"] is None
    assert payload["grade"] == "INCOMPLETE"
    component = "cve_intelligence" if source == "cve" else "credential_permissions"
    assert payload["diagnostics"][0]["metadata"]["component"] == component
    assert any(finding["scanner"] == source for finding in payload["findings"])
