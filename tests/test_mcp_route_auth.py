from __future__ import annotations

from clawlock.scanners.mcp_deep import scan_mcp_source


def _authz(findings):
    return [finding for finding in findings if "AUTHZ" in finding.title]


def test_auth_middleware_only_suppresses_routes_it_dominates(tmp_path):
    source = tmp_path / "server.js"
    source.write_text(
        "app.post('/public', (req, res) => res.json({ok: true}));\n"
        "app.use(authMiddleware);\n"
        "app.post('/invoke', (req, res) => res.json({ok: true}));\n",
        encoding="utf-8",
    )

    findings = _authz(scan_mcp_source(tmp_path))

    assert findings
    assert {finding.location for finding in findings} == {"server.js:1"}


def test_unrelated_auth_helper_does_not_hide_public_route(tmp_path):
    source = tmp_path / "server.js"
    source.write_text(
        "function helper(req) { return passport.authenticate('jwt'); }\n"
        "app.post('/invoke', (req, res) => res.json({ok: true}));\n",
        encoding="utf-8",
    )

    findings = _authz(scan_mcp_source(tmp_path))

    assert findings
    assert all(finding.location == "server.js:2" for finding in findings)
