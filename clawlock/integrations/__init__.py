"""
ClawLock v1.0.1 integrations — cloud intelligence, cost analysis,
external scanner, React2Shell, Agent-Scan.
"""
from __future__ import annotations
import json, os, re, shutil, subprocess
from pathlib import Path
from typing import Optional
import httpx
from ..scanners import Finding, CRIT, HIGH, WARN, INFO

CLOUD_BASE = os.environ.get("CLAWLOCK_CLOUD_URL", "https://matrix.tencent.com/clawscan")
_TIMEOUT = 10.0

# ═══════════════════════════════════════════════════════════════════════════════
# Cloud CVE + Skill intelligence
# ═══════════════════════════════════════════════════════════════════════════════
async def lookup_cve(product: str = "OpenClaw", version: str = "") -> list[Finding]:
    params: dict = {"name": product}
    if version: params["version"] = version
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"{CLOUD_BASE}/advisories", params=params)
            r.raise_for_status(); data = r.json()
    except httpx.TimeoutException:
        return [Finding("cve", INFO, "CVE 情报查询超时", "建议稍后重试。")]
    except Exception as e:
        return [Finding("cve", INFO, "CVE 情报暂不可用", f"{str(e)[:100]}")]
    advisories = data if isinstance(data, list) else data.get("data", data.get("advisories", []))
    findings = []
    for adv in advisories:
        # Real API nests details in "info" sub-object: {"info": {"cve", "summary", "severity", ...}, "rule", ...}
        info = adv.get("info", adv)  # fallback to flat if no "info" wrapper
        cve_id = info.get("cve", info.get("id", ""))
        sev = str(info.get("severity", "medium")).lower()
        title = info.get("summary", info.get("title", cve_id))
        desc = info.get("details", info.get("description", ""))[:200]
        remediation = info.get("security_advise", "升级到最新版本。")
        findings.append(Finding("cve", CRIT if sev in ("critical", "high") else WARN,
            f"[{cve_id}] {title}", desc, remediation=remediation,
            metadata={"cve_id": cve_id, "severity": sev}))
    return findings

async def lookup_skill_intel(skill_name: str, source: str = "local") -> dict:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"{CLOUD_BASE}/skill_security",
                params={"skill_name": skill_name, "source": source})
            r.raise_for_status(); return r.json()
    except Exception: return {"verdict": "unknown", "reason": "cloud lookup failed"}

def verdict_to_finding(skill_name: str, intel: dict) -> Optional[Finding]:
    verdict = intel.get("verdict", "unknown")
    if verdict not in ("malicious", "risky"): return None
    return Finding("skill_intel", CRIT if verdict == "malicious" else WARN,
        f"[{skill_name}] 云端情报: {'已知恶意' if verdict == 'malicious' else '存在风险'}",
        intel.get("reason", f"verdict: {verdict}"),
        remediation="立即卸载。" if verdict == "malicious" else "确认来源可信后使用。")


# ═══════════════════════════════════════════════════════════════════════════════
# Cost Analysis — v1.0.1 
# ═══════════════════════════════════════════════════════════════════════════════
MODEL_COST_PER_1K = {
    "gpt-4o": 0.005, "gpt-4o-mini": 0.00015, "gpt-4": 0.03, "gpt-3.5-turbo": 0.0005,
    "claude-opus-4": 0.015, "claude-sonnet-4": 0.003, "claude-haiku": 0.00025,
    "claude-3.5-sonnet": 0.003, "claude-3-opus": 0.015,
}

def analyze_cost(config: dict, cfg_path: str = "") -> list[Finding]:
    """Analyze config for cost optimization opportunities."""
    findings = []
    # Check model choice
    model = (config.get("model", "") or config.get("defaultModel", "") or
             config.get("llm", {}).get("model", "")).lower()
    if model:
        for expensive in ["gpt-4o", "claude-opus", "gpt-4"]:
            if expensive in model:
                findings.append(Finding("cost", WARN,
                    f"使用高价模型: {model}",
                    f"当前默认模型 {model} 费用较高。对于简单任务，考虑使用 mini/haiku 变体。",
                    f"config:model", remediation="根据任务复杂度选择合适的模型级别。"))
                break
    # Check heartbeat/cron frequency
    heartbeat = config.get("heartbeat", {}) or config.get("cron", {})
    if isinstance(heartbeat, dict):
        interval = heartbeat.get("interval", heartbeat.get("frequency", 0))
        if isinstance(interval, (int, float)) and 0 < interval < 60:
            findings.append(Finding("cost", WARN,
                "心跳/定时任务频率过高",
                f"心跳间隔 {interval}秒，高频调用会持续消耗 API 额度。",
                remediation="将心跳间隔设为 300 秒（5分钟）以上。"))
    # Check max tokens
    max_tokens = config.get("maxTokens", config.get("max_tokens", 0))
    if isinstance(max_tokens, int) and max_tokens > 8000:
        findings.append(Finding("cost", INFO,
            f"最大 Token 数较高: {max_tokens}",
            "较高的 max_tokens 值在每次请求中消耗更多额度。",
            remediation="根据实际需要调整 maxTokens 值。"))
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# React2Shell CVE-2025-55182 (CVSS 10.0) local detection
# ═══════════════════════════════════════════════════════════════════════════════
REACT2SHELL_AFFECTED = {"react": ("19.0.0", "19.2.99"), "next": ("15.0.0", "15.0.4")}

def scan_react2shell(project_path: Path) -> list[Finding]:
    findings = []
    for pkg_file in project_path.rglob("package.json"):
        if "node_modules" in str(pkg_file): continue
        try: data = json.loads(pkg_file.read_text())
        except Exception: continue
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for pkg_name, version_spec in all_deps.items():
            norm = pkg_name.lower().replace("@", "").replace("/", "-")
            for component, (min_v, max_v) in REACT2SHELL_AFFECTED.items():
                if component not in norm: continue
                ver = re.sub(r'[^0-9.]', '', str(version_spec))
                if not ver: continue
                try:
                    parts = tuple(int(x) for x in ver.split(".")[:3])
                    if tuple(int(x) for x in min_v.split(".")[:3]) <= parts <= \
                       tuple(int(x) for x in max_v.split(".")[:3]):
                        findings.append(Finding("react2shell", CRIT,
                            f"CVE-2025-55182 React2Shell [{pkg_name}@{ver}]",
                            f"CVSS 10.0 RCE。{pkg_name} {ver} 在受影响范围。",
                            str(pkg_file), f'"{pkg_name}": "{version_spec}"',
                            f"立即升级 {pkg_name}。"))
                except ValueError: pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# MCP deep scan + Agent-Scan (built-in engine + optional ai-infra-guard)
# ═══════════════════════════════════════════════════════════════════════════════
def _ext_installed() -> bool: return shutil.which("ai-infra-guard") is not None
def _ext_version() -> str:
    if not _ext_installed(): return "not installed (using built-in engine)"
    try:
        r = subprocess.run(["ai-infra-guard", "--version"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
    except Exception: return "unknown"


def run_mcp_deep_scan(code_path: Path, model: str = "", token: str = "",
                      base_url: str = "") -> list[Finding]:
    """
    MCP Server source code deep analysis.

    Strategy: built-in engine always runs; ai-infra-guard binary enhances if installed.
    """
    from ..scanners.mcp_deep import scan_mcp_source

    # Always run built-in engine
    findings = scan_mcp_source(code_path)

    # If ai-infra-guard is installed AND model/token provided, run as enhancement
    if _ext_installed() and model and token:
        ext_findings = _run_ext_mcp(code_path, model, token, base_url)
        if ext_findings:
            findings.append(Finding("mcp_deep", INFO,
                "ai-infra-guard 增强扫描结果 (ReAct agent 语义分析)",
                f"以下 {len(ext_findings)} 项由外部扫描器补充。"))
            findings.extend(ext_findings)

    return findings


def run_agent_scan(model: str = "", token: str = "", base_url: str = "",
                   config: dict = None, code_path: Path = None,
                   enable_llm: bool = False) -> list[Finding]:
    """
    OWASP ASI 14-category Agent security scan.

    Strategy:
    - Built-in engine always runs applicable layers
    """
    from ..scanners.agent_scan import scan_agent

    findings = scan_agent(
        config=config, code_path=code_path, llm_model=model, llm_token=token,
        llm_base_url=base_url or "https://api.anthropic.com", enable_llm=enable_llm)

    return findings


def _run_ext_mcp(code_path: Path, model: str, token: str, base_url: str) -> list[Finding]:
    """Run ai-infra-guard mcp binary as optional enhancer."""
    import tempfile
    out_path = os.path.join(tempfile.gettempdir(), "clawlock_mcp_ext.json")
    cmd = ["ai-infra-guard", "mcp", "--code", str(code_path),
           "--model", model, "--token", token, "--json", out_path]
    if base_url: cmd += ["--base-url", base_url]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        results = json.loads(Path(out_path).read_text()).get("results", [])
        return [Finding("mcp_deep_ext", CRIT if str(it.get("severity", "")).lower() in ("critical", "high") else WARN,
            f"[AIG] {it.get('title', '')}", it.get("description", "")[:200],
            remediation=it.get("remediation", "")) for it in results]
    except Exception:
        return []

