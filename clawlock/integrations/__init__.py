"""
ClawLock v2.5.0 integrations — cloud intelligence and Agent-Scan.
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Optional, Tuple
import httpx
from ..scanners import Finding, CRIT, WARN, INFO
from ..i18n import t

CLOUD_BASE = os.environ.get("CLAWLOCK_CLOUD_URL", "https://matrix.tencent.com/clawscan")
_TIMEOUT = 30.0


def _parse_version_tuple(ver: str) -> Tuple[int, ...]:
    """Parse a version string like '2026.4.1' into a comparable tuple of ints."""
    m = re.findall(r"\d+", ver)
    return tuple(int(x) for x in m) if m else ()


def _extract_fixed_version(info: dict, remediation: str) -> str:
    """Try to extract the fixed/patched version from advisory fields or remediation text."""
    # Try common API field names first.
    for key in ("fixed_version", "patched_version", "fix_version",
                "patched_in", "fixed_in", "affected_before"):
        val = info.get(key, "")
        if val and re.search(r"\d+\.\d+", str(val)):
            return str(val).strip()
    # Fallback: extract version from remediation text.
    # Matches "升级 OpenClaw 至 2026.2.24", "升级到 v2026.3.7", "upgrade to v2026.3.7", etc.
    m = re.search(r"升级.{0,30}?[到至]\s*v?(\d+(?:\.\d+){1,3})", remediation)
    if m:
        return m.group(1)
    m = re.search(r"upgrade\s+to\s*v?(\d+(?:\.\d+){1,3})", remediation, re.I)
    if m:
        return m.group(1)
    return ""


def _is_version_fixed(current: str, fixed: str) -> bool:
    """Return True if current version >= fixed version (i.e. CVE is patched)."""
    cur = _parse_version_tuple(current)
    fix = _parse_version_tuple(fixed)
    if not cur or not fix:
        return False
    return cur >= fix


async def lookup_cve(product: str = "OpenClaw", version: str = "") -> list[Finding]:
    # Upstream /advisories 500s when called with {name=<MixedCase>, version=...}
    # but works with lowercased name, and also works when version is omitted.
    # Try the normal call first; on 5xx fall back to lowercase name, then to
    # a version-less query and rely on client-side _is_version_fixed filtering.
    base_params: dict = {"name": product}
    if version:
        base_params["version"] = version

    async def _fetch(params: dict) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"{CLOUD_BASE}/advisories", params=params)
            r.raise_for_status()
            return r.json()

    try:
        data = await _fetch(base_params)
    except httpx.TimeoutException:
        return [Finding("cve", INFO, t("CVE 情报查询超时", "CVE intelligence query timed out"), t("建议稍后重试。", "Please retry later."))]
    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        if status >= 500 and version:
            try:
                data = await _fetch({"name": product.lower(), "version": version})
            except Exception:
                try:
                    data = await _fetch({"name": product})
                except Exception as e2:
                    return [Finding("cve", INFO, t("CVE 情报暂不可用", "CVE intelligence temporarily unavailable"), f"HTTP {status}; fallback: {str(e2)[:80]}")]
        else:
            return [Finding("cve", INFO, t("CVE 情报暂不可用", "CVE intelligence temporarily unavailable"), f"HTTP {status}")]
    except Exception as e:
        return [Finding("cve", INFO, t("CVE 情报暂不可用", "CVE intelligence temporarily unavailable"), f"{str(e)[:100]}")]
    advisories = (
        data if isinstance(data, list) else data.get("data", data.get("advisories", []))
    )
    findings = []
    for adv in advisories:
        info = adv.get("info", adv)
        cve_id = info.get("cve", info.get("id", ""))
        sev = str(info.get("severity", "medium")).lower()
        title = info.get("summary", info.get("title", cve_id))
        desc = info.get("details", info.get("description", ""))[:200]
        remediation = info.get("security_advise", t("升级到最新版本。", "Upgrade to the latest version."))

        # Skip CVEs already fixed in the current version.
        if version:
            fixed_ver = _extract_fixed_version(info, remediation)
            if fixed_ver and _is_version_fixed(version, fixed_ver):
                findings.append(
                    Finding(
                        "cve",
                        INFO,
                        f"[{cve_id}] {t('(已修复)', '(Fixed)')} {title}",
                        t(f"当前版本 {version} >= 修复版本 {fixed_ver}，该漏洞已不受影响。", f"Current version {version} >= fix version {fixed_ver}, this vulnerability no longer applies."),
                        remediation=t("无需操作。", "No action needed."),
                        metadata={"cve_id": cve_id, "severity": sev, "fixed_version": fixed_ver},
                    )
                )
                continue

        findings.append(
            Finding(
                "cve",
                CRIT if sev in ("critical", "high") else WARN,
                f"[{cve_id}] {title}",
                desc,
                remediation=remediation,
                metadata={"cve_id": cve_id, "severity": sev},
            )
        )
    return findings


async def lookup_skill_intel(skill_name: str, source: str = "local") -> dict:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(
                f"{CLOUD_BASE}/skill_security",
                params={"skill_name": skill_name, "source": source},
            )
            r.raise_for_status()
            return r.json()
    except Exception:
        return {"verdict": "unknown", "reason": "cloud lookup failed"}


def verdict_to_finding(skill_name: str, intel: dict) -> Optional[Finding]:
    verdict = intel.get("verdict", "unknown")
    if verdict not in ("malicious", "risky"):
        return None
    return Finding(
        "skill_intel",
        CRIT if verdict == "malicious" else WARN,
        f"[{skill_name}] {t('云端情报:', 'Cloud intelligence:')} {(t('已知恶意', 'Known malicious') if verdict == 'malicious' else t('存在风险', 'Risky'))}",
        intel.get("reason", f"verdict: {verdict}"),
        remediation=t("立即卸载。", "Uninstall immediately.") if verdict == "malicious" else t("确认来源可信后使用。", "Verify source trustworthiness before use."),
    )


def run_mcp_deep_scan(code_path: Path) -> list[Finding]:
    """MCP Server source code deep analysis via the built-in engine."""
    from ..scanners.mcp_deep import scan_mcp_source

    return scan_mcp_source(code_path)


def run_agent_scan(
    model: str = "",
    token: str = "",
    base_url: str = "",
    config: dict = None,
    code_path: Path = None,
    enable_llm: bool = False,
) -> list[Finding]:
    """
    OWASP ASI 14-category Agent security scan.

    Strategy:
    - Built-in engine always runs applicable layers
    """
    from ..scanners.agent_scan import scan_agent

    findings = scan_agent(
        config=config,
        code_path=code_path,
        llm_model=model,
        llm_token=token,
        llm_base_url=base_url or "",
        enable_llm=enable_llm,
    )
    return findings
