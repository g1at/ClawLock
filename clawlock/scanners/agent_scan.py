"""
ClawLock built-in OWASP ASI 14-category Agent security scanner.

Three-layer detection architecture:
  Layer 1: Static config analysis (zero-cost, always runs)
  Layer 2: Known-pattern regex/AST detection on agent code (zero-cost, always runs)
  Layer 3: LLM-assisted semantic assessment (opt-in, requires API key)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

import httpx

from ..scanners import CRIT, HIGH, INFO, WARN, Finding
from .mcp_deep import scan_package_manifest_risks

# =============================================================================
# OWASP ASI 14 categories
# =============================================================================
ASI_CATEGORIES = {
    "ASI-01": ("Unauthorized Action Execution", "未授权操作执行"),
    "ASI-02": ("Data Exfiltration via Agent", "通过 Agent 数据泄露"),
    "ASI-03": ("Indirect Prompt Injection", "间接提示词注入"),
    "ASI-04": ("Tool Abuse and Misuse", "工具滥用与误用"),
    "ASI-05": ("Authorization Bypass", "授权绕过"),
    "ASI-06": ("Memory Poisoning", "记忆投毒"),
    "ASI-07": ("SSRF via Agent Tools", "通过 Agent 工具的 SSRF"),
    "ASI-08": ("Credential Theft via Agent", "通过 Agent 凭证窃取"),
    "ASI-09": ("Excessive Agency", "过度代理权限"),
    "ASI-10": ("Insecure Plugin/Skill Design", "不安全的插件/技能设计"),
    "ASI-11": ("Inadequate Sandboxing", "沙箱隔离不足"),
    "ASI-12": ("Sensitive Data in Prompts", "提示词中的敏感数据"),
    "ASI-13": ("Rug Pull / Supply Chain", "Rug Pull / 供应链攻击"),
    "ASI-14": ("Cross-Agent Trust Exploitation", "跨 Agent 信任利用"),
}


# =============================================================================
# Layer 1: Static config analysis
# =============================================================================
@dataclass
class ConfigCheck:
    asi: str
    path: str
    check: Any  # callable(value) -> bool means vulnerable
    level: str
    title_zh: str
    detail_zh: str
    remediation: str = ""


_CONFIG_CHECKS: List[ConfigCheck] = [
    ConfigCheck(
        "ASI-01",
        "tools.exec.security",
        lambda v: v in (None, "allow", ""),
        CRIT,
        "执行策略未限制",
        "tools.exec.security 未设为 deny/allowlist，agent 可执行任意命令。",
        "设为 security: deny 或 security: allowlist。",
    ),
    ConfigCheck(
        "ASI-01",
        "tools.exec.ask",
        lambda v: v in (None, "off", "never"),
        HIGH,
        "命令执行无需审批",
        "tools.exec.ask 未开启，命令执行不弹审批提示。",
        "设为 ask: always 或 ask: on-miss。",
    ),
    ConfigCheck(
        "ASI-05",
        "gateway.auth.token",
        lambda v: not v,
        CRIT,
        "Gateway 无认证",
        "未配置 gateway.auth.token/password，服务端口完全开放。",
        "设置强随机 gateway.auth.token。",
    ),
    ConfigCheck(
        "ASI-05",
        "gateway.bind",
        lambda v: v and v not in ("loopback", "127.0.0.1", "localhost"),
        HIGH,
        "Gateway 绑定非回环地址",
        "Gateway 暴露到网络，增加攻击面。",
        "设为 bind: loopback 或通过 SSH/Tailscale 隧道访问。",
    ),
    ConfigCheck(
        "ASI-09",
        "allowedDirectories",
        lambda v: isinstance(v, list) and "/" in v,
        CRIT,
        "文件访问范围含根目录",
        "Agent 可读写系统全部文件。",
        "限制到项目目录。",
    ),
    ConfigCheck(
        "ASI-09",
        "tools.browser.enabled",
        lambda v: v is True,
        WARN,
        "浏览器控制已开启",
        "Agent 可操控浏览器，带来 cookie 窃取等风险。",
        "仅在需要时开启。",
    ),
    ConfigCheck(
        "ASI-09",
        "tools.sessions.visibility",
        lambda v: v in (None, "all"),
        WARN,
        "会话可见性过宽",
        "会话工具可跨会话访问对话内容。",
        "设为 visibility: self 或 visibility: tree。",
    ),
    ConfigCheck(
        "ASI-11",
        "agents.defaults.sandbox.mode",
        lambda v: v in (None, "off", ""),
        HIGH,
        "沙箱模式未开启",
        "Agent 直接在宿主环境执行，无容器隔离。",
        "设为 sandbox.mode: docker。",
    ),
    ConfigCheck(
        "ASI-11",
        "agents.defaults.sandbox.docker.network",
        lambda v: v and v != "none",
        WARN,
        "沙箱容器有网络访问",
        "沙箱网络未隔离，容器可访问网络。",
        "设为 docker.network: none。",
    ),
    ConfigCheck(
        "ASI-12",
        "commands.ownerDisplay",
        lambda v: v in (None, "visible", ""),
        WARN,
        "所有者信息暴露在提示词中",
        "所有者身份可能被第三方模型提供者看到。",
        "设为 ownerDisplay: hash 并配置 ownerDisplaySecret。",
    ),
    ConfigCheck(
        "ASI-08",
        "hooks.allowRequestSessionKey",
        lambda v: v is True,
        HIGH,
        "Hook 允许指定 sessionKey",
        "外部可通过 hook 定向路由消息到指定会话。",
        "设为 allowRequestSessionKey: false。",
    ),
]


def _get_nested(data: dict, path: str) -> Any:
    """Get nested dict value by dot-separated path."""
    curr: Any = data
    for part in path.split("."):
        if not isinstance(curr, dict):
            return None
        curr = curr.get(part)
    return curr


def scan_agent_config(config: dict) -> List[Finding]:
    """Layer 1: Static configuration analysis against ASI categories."""
    findings: List[Finding] = []
    for check in _CONFIG_CHECKS:
        value = _get_nested(config, check.path)
        try:
            if not check.check(value):
                continue
            _, asi_zh = ASI_CATEGORIES.get(check.asi, (check.asi, check.asi))
            findings.append(
                Finding(
                    scanner="agent_scan",
                    level=check.level,
                    title=f"[{check.asi}] {check.title_zh}",
                    detail=f"{asi_zh}: {check.detail_zh}",
                    location=f"config:{check.path}",
                    remediation=check.remediation,
                    metadata={"asi": check.asi},
                )
            )
        except Exception:
            continue
    return findings


# =============================================================================
# Layer 2: Known-pattern detection on agent/skill code
# =============================================================================
@dataclass
class AsiPattern:
    asi: str
    level: str
    pattern: re.Pattern[str]
    title_zh: str
    detail_zh: str


_ASI_CODE_PATTERNS: List[AsiPattern] = [
    AsiPattern(
        "ASI-01",
        CRIT,
        re.compile(
            r"(?:exec|system|spawn|popen)\s*\([^)]*(?:tool_input|args|params)", re.I
        ),
        "工具直接执行外部输入",
        "工具参数未经验证即传入系统命令。",
    ),
    AsiPattern(
        "ASI-02",
        HIGH,
        re.compile(
            r"(?:fetch|axios|requests?\.(?:get|post)|httpx?\.\w+)\s*\([^)]*(?:tool_input|args|params|body)",
            re.I,
        ),
        "工具可向用户指定 URL 发送数据",
        "Agent 工具可能被用于将内部数据外泄到攻击者服务器。",
    ),
    AsiPattern(
        "ASI-03",
        HIGH,
        re.compile(
            r"(?:description|prompt|instruction)\s*[:=]\s*[^;]*(?:fetch|read|load|get)\s*\(",
            re.I,
        ),
        "工具描述引用外部数据",
        "工具元数据中引用外部内容加载，可被间接提示词注入。",
    ),
    AsiPattern(
        "ASI-03",
        HIGH,
        re.compile(
            r'(?:system_prompt|system_message)\s*[:=]\s*[^;]*(?:\+\s*|f["\'].*?\{|`.*?\$\{).*?(?:user|input|req)',
            re.I,
        ),
        "系统提示词拼接了用户输入",
        "用户可控数据流入系统提示词。",
    ),
    AsiPattern(
        "ASI-04",
        WARN,
        re.compile(r"(?:tools?\s*[:=]\s*\[)[^]]{2000,}", re.S),
        "注册工具数量异常多",
        "单个 agent 注册了大量工具，增加误用风险。",
    ),
    AsiPattern(
        "ASI-06",
        HIGH,
        re.compile(
            r"(?:memory|history|context)\s*\.\s*(?:push|append|add|set)\s*\([^)]*(?:tool_|user_|external)",
            re.I,
        ),
        "外部内容直接写入 Agent 记忆",
        "不受信任的数据注入到 agent 持久化记忆中。",
    ),
    AsiPattern(
        "ASI-07",
        HIGH,
        re.compile(
            r"(?:fetch|request|get|post)\s*\(\s*(?:url|endpoint|target)\s*[,)]", re.I
        ),
        "HTTP 请求目标由参数控制",
        "工具的 HTTP 请求目标可被用户控制，存在 SSRF 风险。",
    ),
    AsiPattern(
        "ASI-08",
        CRIT,
        re.compile(
            r"(?:api[_-]?key|token|secret|password|credential)\s*[:=]\s*[^;]*(?:tool_input|args|params|env\[)",
            re.I,
        ),
        "凭证来源不安全",
        "凭证从用户输入或未加保护的环境变量获取。",
    ),
    AsiPattern(
        "ASI-10",
        WARN,
        re.compile(
            r'(?:permissions?|capabilities?|scopes?)\s*[:=]\s*\[?\s*["\']?\*["\']?\s*\]?',
            re.I,
        ),
        "插件/技能声明了通配符权限",
        "使用 * 权限声明，违反最小权限原则。",
    ),
    AsiPattern(
        "ASI-13",
        CRIT,
        re.compile(
            r"(?:npm\s+install|pip\s+install|curl\s.*?\|\s*(?:sh|bash)|wget\s.*?&&\s*(?:chmod|sh|bash))",
            re.I,
        ),
        "运行时动态安装依赖",
        "运行时通过 shell 安装包，存在供应链攻击风险。",
    ),
    AsiPattern(
        "ASI-14",
        HIGH,
        re.compile(
            r"(?:trust|delegate|forward|proxy)\s*[:=]\s*[^;]*(?:agent|server|peer|remote)",
            re.I,
        ),
        "存在跨 Agent 信任委托",
        "Agent 将操作委托给其他 agent/server 时未验证信任关系。",
    ),
]


def scan_agent_code(code_path: Path) -> List[Finding]:
    """Layer 2: Pattern-based code analysis for ASI categories."""
    findings: List[Finding] = []
    extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".mjs",
        ".cjs",
        ".md",
        ".yaml",
        ".yml",
        ".json",
    }
    skip_dirs = {"node_modules", ".git", "__pycache__", "dist", "build"}

    if code_path.is_file():
        files = [code_path] if code_path.suffix in extensions else []
    else:
        files = []
        for root, dirs, filenames in os.walk(code_path):
            dirs[:] = [name for name in dirs if name not in skip_dirs]
            for filename in filenames:
                file_path = Path(root) / filename
                if file_path.suffix not in extensions:
                    continue
                if file_path.stat().st_size > 512 * 1024:
                    continue
                files.append(file_path)

    for file_path in files:
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            continue

        rel = str(file_path.relative_to(code_path)) if code_path.is_dir() else file_path.name
        for pattern in _ASI_CODE_PATTERNS:
            for match in pattern.pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                _, asi_zh = ASI_CATEGORIES.get(pattern.asi, (pattern.asi, pattern.asi))
                findings.append(
                    Finding(
                        scanner="agent_scan",
                        level=pattern.level,
                        title=f"[{pattern.asi}] {pattern.title_zh}",
                        detail=f"{asi_zh}: {pattern.detail_zh}",
                        location=f"{rel}:{line_no}",
                        snippet=match.group(0)[:80].strip(),
                        metadata={"asi": pattern.asi},
                    )
                )
    return findings


# =============================================================================
# Layer 3: LLM-assisted semantic assessment (opt-in)
# =============================================================================
_LLM_SYSTEM_PROMPT = """You are a security auditor. Analyze the following AI agent code/config for OWASP ASI vulnerabilities.
For each finding, output one JSON object per line with fields: asi (e.g. ASI-01), severity (critical/high/medium/info), title, detail, remediation.
Only output valid JSON lines. No markdown, no explanation."""


async def scan_agent_llm(
    code_or_config: str,
    model: str = "claude-sonnet-4-20250514",
    api_key: str = "",
    base_url: str = "https://api.anthropic.com",
) -> List[Finding]:
    """Layer 3: LLM-assisted semantic analysis. Requires API key."""
    if not api_key:
        api_key = os.environ.get(
            "ANTHROPIC_API_KEY",
            os.environ.get("OPENAI_API_KEY", ""),
        )
    if not api_key:
        return [
            Finding(
                "agent_scan_llm",
                INFO,
                "LLM 辅助分析需要 API 密钥",
                "设置 ANTHROPIC_API_KEY 或 OPENAI_API_KEY 环境变量，或通过 --token 参数传入。",
            )
        ]

    truncated = code_or_config[:8000]
    if len(code_or_config) > 8000:
        truncated += "\n... [truncated]"

    try:
        if "anthropic" in base_url.lower() or api_key.startswith("sk-ant-"):
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{base_url.rstrip('/')}/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 2000,
                        "system": _LLM_SYSTEM_PROMPT,
                        "messages": [
                            {
                                "role": "user",
                                "content": (
                                    "Analyze this agent code for OWASP ASI vulnerabilities:\n\n"
                                    f"```\n{truncated}\n```"
                                ),
                            }
                        ],
                    },
                )
                response.raise_for_status()
                result_text = response.json()["content"][0]["text"]
        else:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{base_url.rstrip('/')}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 2000,
                        "messages": [
                            {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                            {
                                "role": "user",
                                "content": (
                                    "Analyze this agent code for OWASP ASI vulnerabilities:\n\n"
                                    f"```\n{truncated}\n```"
                                ),
                            },
                        ],
                    },
                )
                response.raise_for_status()
                result_text = response.json()["choices"][0]["message"]["content"]
    except Exception as exc:
        return [
            Finding(
                "agent_scan_llm",
                INFO,
                f"LLM 分析请求失败: {str(exc)[:80]}",
                "请检查 API 密钥和网络连接。",
            )
        ]

    findings: List[Finding] = []
    for line in result_text.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            asi = obj.get("asi", "")
            severity = obj.get("severity", "medium").lower()
            level = {"critical": CRIT, "high": HIGH, "medium": WARN}.get(
                severity, INFO
            )
            _, asi_zh = ASI_CATEGORIES.get(asi, (asi, asi))
            findings.append(
                Finding(
                    scanner="agent_scan_llm",
                    level=level,
                    title=f"[{asi}] {obj.get('title', '')}",
                    detail=f"{asi_zh}: {obj.get('detail', '')}",
                    remediation=obj.get("remediation", ""),
                    metadata={"asi": asi, "source": "llm"},
                )
            )
        except (json.JSONDecodeError, KeyError):
            continue

    if not findings:
        findings.append(
            Finding(
                "agent_scan_llm",
                INFO,
                "LLM 分析完成，未发现高危问题",
                "模型未返回可解析的安全发现。",
            )
        )
    return findings


# =============================================================================
# Unified entry point
# =============================================================================
def scan_agent(
    config: Optional[dict] = None,
    code_path: Optional[Path] = None,
    llm_model: str = "",
    llm_token: str = "",
    llm_base_url: str = "https://api.anthropic.com",
    enable_llm: bool = False,
) -> List[Finding]:
    """
    Unified Agent-Scan entry point. Runs applicable layers:

    - Layer 1 (config): always runs if config provided
    - Layer 2 (code patterns): always runs if code_path provided
    - Layer 3 (LLM): runs if enable_llm=True and token available

    Returns all findings across layers, sorted by severity.
    """
    findings: List[Finding] = []

    if config:
        findings.extend(scan_agent_config(config))

    if code_path and code_path.exists():
        findings.extend(scan_agent_code(code_path))
        findings.extend(scan_package_manifest_risks(code_path))

    if enable_llm and (
        llm_token
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    ):
        import asyncio

        code_text = ""
        if code_path and code_path.exists():
            if code_path.is_file():
                code_text = code_path.read_text(errors="ignore")
            else:
                for file_path in sorted(code_path.rglob("*"))[:10]:
                    if not file_path.is_file():
                        continue
                    if file_path.suffix not in {".py", ".js", ".ts", ".yaml", ".json"}:
                        continue
                    code_text += (
                        f"\n--- {file_path.name} ---\n"
                        + file_path.read_text(errors="ignore")[:2000]
                    )
        elif config:
            code_text = json.dumps(config, indent=2, ensure_ascii=False)

        if code_text:
            findings.extend(
                asyncio.run(
                    scan_agent_llm(
                        code_text,
                        model=llm_model or "claude-sonnet-4-20250514",
                        api_key=llm_token,
                        base_url=llm_base_url,
                    )
                )
            )

    seen = set()
    unique: List[Finding] = []
    for finding in findings:
        key = (finding.title, finding.location)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    severity_order = {CRIT: 0, HIGH: 1, WARN: 2, INFO: 3}
    unique.sort(key=lambda finding: severity_order.get(finding.level, 9))

    covered_asis = {
        finding.metadata.get("asi", "")
        for finding in unique
        if finding.metadata.get("asi")
    }
    layers_used = []
    if config:
        layers_used.append("配置分析")
    if code_path:
        layers_used.append("代码扫描")
    if enable_llm:
        layers_used.append("LLM 评估")

    unique.insert(
        0,
        Finding(
            scanner="agent_scan",
            level=INFO,
            title=f"Agent-Scan 完成: {len(unique)} 项发现, 覆盖 {len(covered_asis)}/14 ASI 类别",
            detail=(
                f"检测层: {' + '.join(layers_used)}。"
                f" 覆盖: {', '.join(sorted(covered_asis)) if covered_asis else '无'}。"
            ),
            metadata={"layers": layers_used, "covered_asis": list(covered_asis)},
        ),
    )

    return unique
