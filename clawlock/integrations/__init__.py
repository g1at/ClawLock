"""
ClawLock v2.2.0 integrations — cloud intelligence,
external scanner, and Agent-Scan.
"""

from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import tempfile
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
    params: dict = {"name": product}
    if version:
        params["version"] = version
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"{CLOUD_BASE}/advisories", params=params)
            r.raise_for_status()
            data = r.json()
    except httpx.TimeoutException:
        return [Finding("cve", INFO, t("CVE 情报查询超时", "CVE intelligence query timed out"), t("建议稍后重试。", "Please retry later."))]
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


def _ext_installed() -> bool:
    return shutil.which("ai-infra-guard") is not None


def _ext_version() -> str:
    if not _ext_installed():
        return "not installed (using built-in engine)"
    try:
        r = subprocess.run(
            ["ai-infra-guard", "--version"], capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
    except Exception:
        return "unknown"


def run_mcp_deep_scan(
    code_path: Path, model: str = "", token: str = "", base_url: str = ""
) -> list[Finding]:
    """
    MCP Server source code deep analysis.

    Strategy: built-in engine always runs; ai-infra-guard binary enhances if installed.
    """
    from ..scanners.mcp_deep import scan_mcp_source

    findings = scan_mcp_source(code_path)
    if _ext_installed() and model and token:
        ext_findings = _run_ext_mcp(code_path, model, token, base_url)
        if ext_findings:
            findings.append(
                Finding(
                    "mcp_deep",
                    INFO,
                    t("ai-infra-guard 增强扫描结果 (ReAct agent 语义分析)", "ai-infra-guard enhanced scan results (ReAct agent semantic analysis)"),
                    t(f"以下 {len(ext_findings)} 项由外部扫描器补充。", f"The following {len(ext_findings)} items were supplemented by external scanner."),
                )
            )
            findings.extend(ext_findings)
    return findings


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


def _ext_token_env(model: str, token: str, base_url: str) -> dict:
    """Pass enhancer credentials via env instead of argv where possible."""
    env = {}
    if not token:
        return env
    provider = (
        "anthropic"
        if "anthropic" in (base_url or "").lower()
        or token.startswith("sk-ant-")
        or model.lower().startswith(("claude", "anthropic"))
        else "openai"
    )
    env["AI_INFRA_GUARD_TOKEN"] = token
    if provider == "anthropic":
        env["ANTHROPIC_API_KEY"] = token
    else:
        env["OPENAI_API_KEY"] = token
    return env


def _run_ext_mcp(
    code_path: Path, model: str, token: str, base_url: str
) -> list[Finding]:
    """Run ai-infra-guard mcp binary as optional enhancer."""
    with tempfile.TemporaryDirectory(prefix="clawlock-mcp-") as tmpdir:
        out_path = Path(tmpdir) / "mcp_ext.json"
        cmd = [
            "ai-infra-guard",
            "mcp",
            "--code",
            str(code_path),
            "--model",
            model,
            "--json",
            str(out_path),
        ]
        if base_url:
            cmd += ["--base-url", base_url]
        try:
            env = os.environ.copy()
            env.update(_ext_token_env(model, token, base_url))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                env=env,
            )
            if result.returncode != 0 or not out_path.exists():
                return []
            results = json.loads(out_path.read_text(encoding="utf-8")).get(
                "results", []
            )
            return [
                Finding(
                    "mcp_deep_ext",
                    CRIT
                    if str(it.get("severity", "")).lower() in ("critical", "high")
                    else WARN,
                    f"[AIG] {it.get('title', '')}",
                    it.get("description", "")[:200],
                    remediation=it.get("remediation", ""),
                )
                for it in results
            ]
        except Exception:
            return []
