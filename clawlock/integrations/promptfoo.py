"""ClawLock Red-Team Module — wraps promptfoo for LLM red-teaming."""
from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path
from typing import Optional
import yaml
from ..scanners import Finding, CRIT, HIGH, WARN

CLAW_AGENT_PLUGINS = ["prompt-injection", "hijacking", "excessive-agency", "pii",
    "harmful:privacy", "agentic:memory-poisoning", "harmful:hate", "rbac", "ssrf", "tool-discovery"]
ENCODING_STRATEGIES = ["base64", "rot13", "leetspeak", "jailbreak-templates"]
DEEP_STRATEGIES = ["jailbreak", "jailbreak:tree", "jailbreak:meta", "crescendo",
                   "indirect-web-pwn", *ENCODING_STRATEGIES]
QUICK_STRATEGIES = ["jailbreak", "jailbreak-templates", "base64"]

def _check_promptfoo(): return shutil.which("promptfoo") is not None or shutil.which("npx") is not None

def build_redteam_config(endpoint, purpose="Claw-family AI agent", num_tests=10, deep=False):
    return {"providers": [{"id": "openai:chat:gpt-4o-mini",
        "config": {"apiBaseUrl": endpoint, "headers": {"Content-Type": "application/json"}}}],
        "prompts": ["{{query}}"], "redteam": {"purpose": purpose, "numTests": num_tests,
        "plugins": CLAW_AGENT_PLUGINS,
        "strategies": DEEP_STRATEGIES if deep else QUICK_STRATEGIES, "language": ["en", "zh"]}}

def run_redteam(endpoint, purpose="Claw-family AI agent", num_tests=10, deep=False, output_json=None):
    findings = []
    if not _check_promptfoo():
        return [Finding("redteam", "info", "promptfoo 未安装", "安装: npm install -g promptfoo")]
    cfg = build_redteam_config(endpoint, purpose, num_tests, deep)
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "promptfooconfig.yaml"
        cfg_path.write_text(yaml.dump(cfg, allow_unicode=True))
        out = output_json or Path(tmpdir) / "results.json"
        bin_ = "promptfoo" if shutil.which("promptfoo") else "npx"
        cmd = [bin_] + (["promptfoo@latest"] if bin_ == "npx" else [])
        cmd += ["redteam", "run", "--config", str(cfg_path), "--output", str(out)]
        try: subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except Exception as e: return [Finding("redteam", "info", f"promptfoo 异常: {e}", "")]
        if out.exists():
            try:
                for item in json.loads(out.read_text()).get("results", {}).get("results", []):
                    if not item.get("success", True):
                        plugin = item.get("metadata", {}).get("pluginId", "unknown")
                        findings.append(Finding("redteam", WARN, f"红队测试失败: {plugin}",
                            f"agent 对 [{plugin}] 攻击响应不符合预期。",
                            snippet=str(item.get("prompt", {}).get("raw", ""))[:80],
                            remediation=f"检查 {plugin} 类攻击防护。"))
            except Exception: pass
    return findings

def generate_redteam_config_file(output_path, endpoint, purpose, num_tests=10, deep=False):
    cfg = build_redteam_config(endpoint, purpose, num_tests, deep)
    output_path.write_text(yaml.dump(cfg, allow_unicode=True))
