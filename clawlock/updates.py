from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import yaml

from . import __version__

PYPI_URL = "https://pypi.org/pypi/{package}/json"
GITHUB_RAW_SKILL_URL = "https://raw.githubusercontent.com/{repo}/main/skill/{filename}"


def _version_key(version: str) -> tuple:
    parts = re.findall(r"\d+|[A-Za-z]+", version.strip().lstrip("vV"))
    key = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part.lower()))
    return tuple(key)


def _is_newer(remote: str, local: str) -> bool:
    return _version_key(remote) > _version_key(local)


def _http_get_json(url: str, timeout: float = 5.0) -> Any:
    response = httpx.get(
        url,
        timeout=timeout,
        headers={"User-Agent": f"clawlock/{__version__}"},
    )
    response.raise_for_status()
    return response.json()


def _http_get_text(url: str, timeout: float = 5.0) -> str:
    response = httpx.get(
        url,
        timeout=timeout,
        headers={"User-Agent": f"clawlock/{__version__}"},
    )
    response.raise_for_status()
    return response.text


def _github_repo_from_url(url: str) -> Optional[str]:
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?$", url.strip(), re.IGNORECASE)
    if not match:
        return None
    return f"{match.group(1)}/{match.group(2)}"


def _read_skill_frontmatter_text(text: str) -> Dict[str, Any]:
    if not text.startswith("---\n"):
        return {}
    _, _, rest = text.partition("---\n")
    frontmatter, _, _ = rest.partition("\n---")
    data = yaml.safe_load(frontmatter) or {}
    return data if isinstance(data, dict) else {}


def _read_skill_frontmatter(skill_path: Path) -> Dict[str, Any]:
    return _read_skill_frontmatter_text(skill_path.read_text(encoding="utf-8"))


def check_pypi_latest(package: str = "clawlock") -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "source": "pypi",
        "package": package,
        "local_version": __version__,
        "latest_version": None,
        "update_available": False,
        "error": None,
    }
    try:
        payload = _http_get_json(PYPI_URL.format(package=package))
        latest = str(((payload or {}).get("info") or {}).get("version") or "").strip()
        if latest:
            result["latest_version"] = latest
            result["update_available"] = _is_newer(latest, __version__)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_skill_latest(skill_path: Path) -> Dict[str, Any]:
    frontmatter = _read_skill_frontmatter(skill_path)
    metadata = ((frontmatter.get("metadata") or {}).get("clawlock") or {})
    local_version = str(metadata.get("version") or "").strip()
    homepage = str(metadata.get("homepage") or "").strip()
    name = str(frontmatter.get("name") or skill_path.parent.name or "skill").strip()
    github_repo = _github_repo_from_url(homepage)
    remote_url = GITHUB_RAW_SKILL_URL.format(
        repo=github_repo,
        filename=skill_path.name,
    ) if github_repo else None

    result: Dict[str, Any] = {
        "skill_name": name,
        "local_version": local_version or None,
        "source": "github",
        "github_repo": github_repo,
        "remote_url": remote_url,
        "latest_version": None,
        "installed_package_version": __version__,
        "matches_installed_package": False,
        "update_available": False,
        "error": None,
    }
    if not local_version:
        result["error"] = "Local skill version is missing"
        return result

    result["matches_installed_package"] = local_version == __version__
    if not github_repo or not remote_url:
        result["error"] = "GitHub homepage is missing or unsupported"
        return result

    try:
        remote_frontmatter = _read_skill_frontmatter_text(_http_get_text(remote_url))
        remote_metadata = ((remote_frontmatter.get("metadata") or {}).get("clawlock") or {})
        latest_version = str(remote_metadata.get("version") or "").strip()
        if not latest_version:
            result["error"] = "Remote skill version is missing"
            return result
        result["latest_version"] = latest_version
        result["update_available"] = _is_newer(latest_version, local_version)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def build_update_report(skill_path: Optional[Path] = None) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "package": check_pypi_latest(),
        "skill": None,
        "suggested_updates": [],
    }

    if skill_path is not None:
        report["skill"] = check_skill_latest(skill_path)

    if report["package"].get("update_available"):
        report["suggested_updates"].append("pip install -U clawlock")

    skill = report.get("skill")
    if isinstance(skill, dict) and (
        skill.get("update_available") or not skill.get("matches_installed_package", True)
    ):
        remote_url = skill.get("remote_url")
        if remote_url:
            report["suggested_updates"].append(f"download the latest skill file from {remote_url}")
        else:
            report["suggested_updates"].append(
                "re-sync the local ClawLock skill files from the GitHub repository"
            )

    return report


def render_update_report_text(report: Dict[str, Any]) -> str:
    lines = []
    package = report.get("package") or {}
    lines.append(f"ClawLock local: {package.get('local_version') or __version__}")
    if package.get("error"):
        lines.append(f"PyPI latest: unavailable ({package['error']})")
    else:
        latest = package.get("latest_version") or "unknown"
        status = "update available" if package.get("update_available") else "up to date"
        lines.append(f"PyPI latest: {latest} ({status})")

    skill = report.get("skill")
    if isinstance(skill, dict):
        lines.append(f"Skill local: {skill.get('local_version') or 'unknown'}")
        if skill.get("error"):
            lines.append(f"GitHub skill latest: unavailable ({skill['error']})")
        else:
            latest = skill.get("latest_version") or "unknown"
            latest_status = "update available" if skill.get("update_available") else "up to date"
            lines.append(f"GitHub skill latest: {latest} ({latest_status})")
            installed = skill.get("installed_package_version") or __version__
            status = (
                "matches installed ClawLock"
                if skill.get("matches_installed_package")
                else "does not match installed ClawLock"
            )
            lines.append(f"Skill sync: {status} (installed package: {installed})")

    suggested = report.get("suggested_updates") or []
    if suggested:
        lines.append("Suggested updates:")
        for cmd in suggested:
            lines.append(f"- {cmd}")
    return "\n".join(lines)


def render_update_report_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
