"""Test-suite-wide configuration.

* Disables ClawLock's network-backed package-existence probe so that
  ``scan_package_manifest_risks`` does not reach npm / PyPI during tests.
* Redirects the SQLite scan-history database and legacy JSON path to a
  per-session tmp directory so tests never write to ``~/.clawlock``.

Individual tests that need to exercise the probe can ``monkeypatch.delenv``.
"""

import os

import pytest


def pytest_configure(config):
    os.environ.setdefault("CLAWLOCK_NO_PKG_CHECK", "1")


@pytest.fixture(autouse=True)
def _isolate_scan_history(tmp_path_factory, monkeypatch):
    """Auto-applied: keep every test's ``record_scan`` writes in a tmp dir."""
    import clawlock.utils as u

    data_dir = tmp_path_factory.mktemp("clawlock-data", numbered=True)
    monkeypatch.setattr(u, "DB_PATH", data_dir / "clawlock.db")
    monkeypatch.setattr(u, "HISTORY_FILE", data_dir / "scan_history.json")
    monkeypatch.setattr(u, "_LEGACY_IMPORTED_FLAG", data_dir / ".history-imported")
    yield
