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
from typing import Any, Dict, List, Optional

import httpx

from ..i18n import t
from ..scanners import CONFIG_RULES, CRIT, HIGH, INFO, WARN, Finding
from .mcp_deep import scan_package_manifest_risks

# =============================================================================
# OWASP ASI 14 categories
# =============================================================================
ASI_CATEGORIES = {
    "ASI-01": ("Unauthorized Action Execution", t("未授权操作执行", "Unauthorized Action Execution")),
    "ASI-02": ("Data Exfiltration via Agent", t("通过 Agent 数据泄露", "Data Leakage via Agent")),
    "ASI-03": ("Indirect Prompt Injection", t("间接提示词注入", "Indirect Prompt Injection")),
    "ASI-04": ("Tool Abuse and Misuse", t("工具滥用与误用", "Tool Abuse and Misuse")),
    "ASI-05": ("Authorization Bypass", t("授权绕过", "Authorization Bypass")),
    "ASI-06": ("Memory Poisoning", t("记忆投毒", "Memory Poisoning")),
    "ASI-07": ("SSRF via Agent Tools", t("通过 Agent 工具的 SSRF", "SSRF via Agent Tools")),
    "ASI-08": ("Credential Theft via Agent", t("通过 Agent 凭证窃取", "Credential Theft via Agent")),
    "ASI-09": ("Excessive Agency", t("过度代理权限", "Excessive Agent Permissions")),
    "ASI-10": ("Insecure Plugin/Skill Design", t("不安全的插件/技能设计", "Insecure Plugin/Skill Design")),
    "ASI-11": ("Inadequate Sandboxing", t("沙箱隔离不足", "Insufficient Sandbox Isolation")),
    "ASI-12": ("Sensitive Data in Prompts", t("提示词中的敏感数据", "Sensitive Data in Prompts")),
    "ASI-13": ("Rug Pull / Supply Chain", t("Rug Pull / 供应链攻击", "Rug Pull / Supply Chain Attack")),
    "ASI-14": ("Cross-Agent Trust Exploitation", t("跨 Agent 信任利用", "Cross-Agent Trust Exploitation")),
}


# =============================================================================
# Layer 1: Static config analysis  — driven by the unified ``CONFIG_RULES``
# registry in ``clawlock.scanners``. Rules with an ``asi`` tag belong to this
# scanner; rules without one are ``scan_config``'s territory.
# =============================================================================


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
    for rule in CONFIG_RULES:
        if rule.asi is None:
            continue
        value = _get_nested(config, rule.key)
        if value is None and not rule.check(value):
            # ``check`` may legitimately fire on None (e.g. "approval not set"),
            # so we only short-circuit when both value is missing AND the
            # check rejects None.
            continue
        try:
            if not rule.check(value):
                continue
        except Exception:
            continue
        _, asi_zh = ASI_CATEGORIES.get(rule.asi, (rule.asi, rule.asi))
        metadata: Dict[str, Any] = {"asi": rule.asi, "category": "ASI"}
        if rule.measure_ids:
            metadata["measure_ids"] = list(rule.measure_ids)
        findings.append(
            Finding(
                scanner="agent_scan",
                level=rule.level,
                title=f"[{rule.asi}] {rule.title}",
                detail=f"{asi_zh}: {rule.detail}",
                location=f"config:{rule.key}",
                remediation=rule.remediation,
                metadata=metadata,
            )
        )
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
        t("工具直接执行外部输入", "Tool directly executes external input"),
        t("工具参数未经验证即传入系统命令。", "Tool parameters passed to system commands without validation."),
    ),
    AsiPattern(
        "ASI-02",
        HIGH,
        re.compile(
            r"(?:fetch|axios|requests?\.(?:get|post)|httpx?\.\w+)\s*\([^)]*(?:tool_input|args|params|body)",
            re.I,
        ),
        t("工具可向用户指定 URL 发送数据", "Tool can send data to user-specified URL"),
        t("Agent 工具可能被用于将内部数据外泄到攻击者服务器。", "Agent tool may be used to exfiltrate internal data to attacker server."),
    ),
    AsiPattern(
        "ASI-03",
        HIGH,
        re.compile(
            r"(?:description|prompt|instruction)\s*[:=]\s*[^;]*(?:fetch|read|load|get)\s*\(",
            re.I,
        ),
        t("工具描述引用外部数据", "Tool description references external data"),
        t("工具元数据中引用外部内容加载，可被间接提示词注入。", "Tool metadata references external content loading, vulnerable to indirect prompt injection."),
    ),
    AsiPattern(
        "ASI-03",
        HIGH,
        re.compile(
            r'(?:system_prompt|system_message)\s*[:=]\s*[^;]*(?:\+\s*|f["\'].*?\{|`.*?\$\{).*?(?:user|input|req)',
            re.I,
        ),
        t("系统提示词拼接了用户输入", "System prompt concatenates user input"),
        t("用户可控数据流入系统提示词。", "User-controllable data flows into system prompt."),
    ),
    AsiPattern(
        "ASI-03",
        HIGH,
        re.compile(
            r"(?:show|print|reveal|dump|output|display|输出|显示|打印|泄露|公开)[^\n]{0,80}"
            r"(?:system prompt|developer message|internal rules?|hidden prompt|系统提示词|开发者消息|内部规则)",
            re.I,
        ),
        t("请求提取系统提示词或内部规则", "Prompt asks to reveal system prompt or internal rules"),
        t("代码或文档中包含提示词提取指令，可用于窃取隐藏系统规则。", "Code or docs contain prompt-extraction instructions that may disclose hidden system rules."),
    ),
    AsiPattern(
        "ASI-03",
        HIGH,
        re.compile(
            r"(?:system_prompt|system_message|prompt|instructions?)\s*[:=]\s*[^;\n]*"
            r"(?:tool_output|stdout|response\.text|result(?:\.content)?)",
            re.I,
        ),
        t("工具输出直接进入提示词", "Tool output flows directly into prompt text"),
        t("未清洗的工具输出直接注入到 prompt/instructions，容易触发间接提示词攻击。", "Untrusted tool output is injected directly into prompt/instructions, enabling indirect prompt injection."),
    ),
    AsiPattern(
        "ASI-04",
        WARN,
        re.compile(r"(?:tools?\s*[:=]\s*\[)[^]]{2000,}", re.S),
        t("注册工具数量异常多", "Abnormally high number of registered tools"),
        t("单个 agent 注册了大量工具，增加误用风险。", "A single agent registers a large number of tools, increasing misuse risk."),
    ),
    AsiPattern(
        "ASI-05",
        HIGH,
        re.compile(
            r"(?:auto_approve|skip_approval|skip_confirmation|assume\s+(?:approval|permission)\s+granted|"
            r"do\s+not\s+ask\s+for\s+(?:approval|confirmation)|不要请求确认|无需确认|默认已获批准)",
            re.I,
        ),
        t("审批或确认流程被绕过", "Approval or confirmation flow is bypassed"),
        t("代码或文档中包含跳过审批或确认的指令或开关。", "Code or docs contain instructions or toggles that bypass approval or confirmation."),
    ),
    AsiPattern(
        "ASI-06",
        HIGH,
        re.compile(
            r"(?:memory|history|context)\s*\.\s*(?:push|append|add|set)\s*\([^)]*(?:tool_|user_|external)",
            re.I,
        ),
        t("外部内容直接写入 Agent 记忆", "External content written directly to agent memory"),
        t("不受信任的数据注入到 agent 持久化记忆中。", "Untrusted data injected into agent persistent memory."),
    ),
    AsiPattern(
        "ASI-06",
        HIGH,
        re.compile(
            r"(?:save|store|persist)\w*memory\s*\([^)]*(?:tool_output|stdout|response\.text|result(?:\.content)?)",
            re.I,
        ),
        t("工具响应被持久化写入记忆", "Tool response persisted into memory"),
        t("外部工具返回内容被直接保存到长期记忆，存在记忆投毒风险。", "External tool responses are written into long-term memory, creating memory-poisoning risk."),
    ),
    AsiPattern(
        "ASI-07",
        HIGH,
        re.compile(
            r"(?:fetch|request|get|post)\s*\(\s*(?:url|endpoint|target)\s*[,)]", re.I
        ),
        t("HTTP 请求目标由参数控制", "HTTP request target controlled by parameter"),
        t("工具的 HTTP 请求目标可被用户控制，存在 SSRF 风险。", "Tool HTTP request target can be user-controlled, posing SSRF risk."),
    ),
    AsiPattern(
        "ASI-08",
        CRIT,
        re.compile(
            r"(?:api[_-]?key|token|secret|password|credential)\s*[:=]\s*[^;]*(?:tool_input|args|params|env\[)",
            re.I,
        ),
        t("凭证来源不安全", "Insecure credential source"),
        t("凭证从用户输入或未加保护的环境变量获取。", "Credentials obtained from user input or unprotected environment variables."),
    ),
    AsiPattern(
        "ASI-08",
        HIGH,
        re.compile(
            r"(?:logger\.(?:debug|info|warning|warn|error)|console\.log|print)\s*\([^)]*"
            r"(?:api[_-]?key|token|secret|password|credential)",
            re.I,
        ),
        t("敏感凭证被写入日志", "Sensitive credentials logged"),
        t("代码将 token、password 或 secret 等敏感凭证写入日志或输出。", "Code writes token/password/secret-like credentials into logs or stdout."),
    ),
    AsiPattern(
        "ASI-10",
        WARN,
        re.compile(
            r'(?:permissions?|capabilities?|scopes?)\s*[:=]\s*\[?\s*["\']?\*["\']?\s*\]?',
            re.I,
        ),
        t("插件/技能声明了通配符权限", "Plugin/skill declares wildcard permissions"),
        t("使用 * 权限声明，违反最小权限原则。", "Uses * permission declaration, violating principle of least privilege."),
    ),
    AsiPattern(
        "ASI-10",
        HIGH,
        re.compile(
            r"(?:importlib\.import_module|__import__|require)\s*\([^)]*(?:tool_input|args|params|req|request|body|plugin|module)",
            re.I,
        ),
        t("动态加载插件模块由外部输入控制", "Dynamic plugin/module loading controlled by external input"),
        t("外部参数决定要加载的 module 或 plugin，容易引入非预期供应链或 RCE 风险。", "External parameters decide which module/plugin is loaded, creating supply-chain and RCE risk."),
    ),
    AsiPattern(
        "ASI-12",
        HIGH,
        re.compile(
            r"(?:logger\.(?:debug|info|warning|warn|error)|console\.log|print)\s*\([^)]*"
            r"(?:system_prompt|prompt|conversation|chat_history|messages?)",
            re.I,
        ),
        t("提示词或对话历史被写入日志", "Prompt or conversation history logged"),
        t("system prompt、对话历史或 message 内容被输出到日志，容易泄露内部敏感信息。", "System prompts or conversation history are written to logs, risking sensitive prompt disclosure."),
    ),
    AsiPattern(
        "ASI-13",
        CRIT,
        re.compile(
            r"(?:npm\s+install|pip\s+install|curl\s.*?\|\s*(?:sh|bash)|wget\s.*?&&\s*(?:chmod|sh|bash))",
            re.I,
        ),
        t("运行时动态安装依赖", "Runtime dynamic dependency installation"),
        t("运行时通过 shell 安装包，存在供应链攻击风险。", "Packages installed via shell at runtime, posing supply chain attack risk."),
    ),
    AsiPattern(
        "ASI-13",
        HIGH,
        re.compile(
            r"(?:npx|uvx|pipx\s+run|npm\s+exec|pip\s+install\s+git\+https?://)",
            re.I,
        ),
        t("运行时下载或执行远程依赖", "Runtime fetch or execution of remote dependencies"),
        t("运行时使用 npx、uvx、pipx run、npm exec 或 git+ pip 依赖，会增加供应链风险。", "Using npx/uvx/pipx run/npm exec or git+ pip dependencies at runtime increases supply-chain risk."),
    ),
    AsiPattern(
        "ASI-14",
        HIGH,
        re.compile(
            r"(?:trust|delegate|forward|proxy)\s*[:=]\s*[^;]*(?:agent|server|peer|remote)",
            re.I,
        ),
        t("存在跨 Agent 信任委托", "Cross-agent trust delegation exists"),
        t("Agent 将操作委托给其他 agent/server 时未验证信任关系。", "Agent delegates operations to other agents/servers without verifying trust relationship."),
    ),
    AsiPattern(
        "ASI-14",
        HIGH,
        re.compile(
            r"(?:forward|delegate|proxy|handoff|relay)\w*\s*\([^)]*(?:agent|peer|remote|server)[^)]*"
            r"(?:tool_input|user_input|prompt|request|message)",
            re.I,
        ),
        t("未验证的跨 Agent 指令转发", "Instruction forwarding across agents without trust checks"),
        t("代码将用户指令、prompt 或请求直接转交其他 agent 或 server，但没有明确的信任验证逻辑。", "User instructions or prompts are forwarded to other agents/servers without explicit trust verification."),
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

_REDACTED = "[REDACTED]"
_SECRET_KEY_RE = re.compile(
    r"(?:token|secret|password|api[_-]?key|authorization|credential|cookie|private[_-]?key|session[_-]?key)",
    re.I,
)
_SECRET_VALUE_RE = re.compile(
    r"^(?:Bearer\s+.+|Basic\s+.+|sk-ant-[A-Za-z0-9._-]+|sk-[A-Za-z0-9._-]+|"
    r"github_pat_[A-Za-z0-9_]+|gh[opusr]_[A-Za-z0-9_]+|tp-[A-Za-z0-9._-]+)$",
    re.I,
)


def _redact_for_llm(value: Any, key: str = "") -> Any:
    """Remove secret-like values before sending code/config to third-party LLMs."""
    if isinstance(value, dict):
        return {k: _redact_for_llm(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_for_llm(v, key) for v in value]
    if key and _SECRET_KEY_RE.search(key):
        return _REDACTED if value not in (None, "") else value
    if isinstance(value, str) and _SECRET_VALUE_RE.match(value.strip()):
        return _REDACTED
    return value


def _resolve_llm_transport(
    api_key: str,
    base_url: str,
) -> tuple[str, str, str]:
    """Pick a provider/base URL pair without leaking payloads to the wrong vendor."""
    explicit_base = bool(base_url)
    if explicit_base:
        provider = "anthropic" if "anthropic" in base_url.lower() else "openai"
        if not api_key:
            env_name = "ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY"
            api_key = os.environ.get(env_name, "")
        return provider, base_url.rstrip("/"), api_key

    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get(
            "OPENAI_API_KEY", ""
        )

    if api_key.startswith("sk-ant-"):
        return "anthropic", "https://api.anthropic.com", api_key
    return "openai", "https://api.openai.com", api_key


async def scan_agent_llm(
    code_or_config: str,
    model: str = "claude-sonnet-4-20250514",
    api_key: str = "",
    base_url: str = "",
) -> List[Finding]:
    """Layer 3: LLM-assisted semantic analysis. Requires API key."""
    provider, resolved_base_url, api_key = _resolve_llm_transport(api_key, base_url)
    if not api_key:
        return [
            Finding(
                "agent_scan_llm",
                INFO,
                t("LLM 辅助分析需要 API 密钥", "LLM-assisted analysis requires an API key"),
                t("设置 ANTHROPIC_API_KEY 或 OPENAI_API_KEY 环境变量，或通过 --token 参数传入。",
                  "Set the ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable, or pass via --token."),
            )
        ]

    truncated = code_or_config[:8000]
    if len(code_or_config) > 8000:
        truncated += "\n... [truncated]"

    try:
        if provider == "anthropic":
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{resolved_base_url}/v1/messages",
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
                    f"{resolved_base_url}/v1/chat/completions",
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
                t("LLM 分析请求失败", "LLM analysis request failed") + f": {str(exc)[:80]}",
                t("请检查 API 密钥和网络连接。", "Please check the API key and network connection."),
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
                t("LLM 分析完成，未发现高危问题", "LLM analysis complete, no high-risk issues found"),
                t("模型未返回可解析的安全发现。", "Model did not return parseable security findings."),
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
    llm_base_url: str = "",
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
            code_text = json.dumps(
                _redact_for_llm(config),
                indent=2,
                ensure_ascii=False,
            )

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
        layers_used.append(t("配置分析", "Config Analysis"))
    if code_path:
        layers_used.append(t("代码扫描", "Code Scan"))
    if enable_llm:
        layers_used.append(t("LLM 评估", "LLM Assessment"))

    unique.insert(
        0,
        Finding(
            scanner="agent_scan",
            level=INFO,
            title=t(
                f"Agent-Scan 完成: {len(unique)} 项发现, 覆盖 {len(covered_asis)}/14 ASI 类别",
                f"Agent-Scan complete: {len(unique)} findings, covering {len(covered_asis)}/14 ASI categories",
            ),
            detail=t(
                f"检测层: {' + '.join(layers_used)}。"
                f" 覆盖: {', '.join(sorted(covered_asis)) if covered_asis else '无'}。",
                f"Layers: {' + '.join(layers_used)}."
                f" Covered: {', '.join(sorted(covered_asis)) if covered_asis else 'None'}.",
            ),
            metadata={"layers": layers_used, "covered_asis": list(covered_asis)},
        ),
    )

    return unique
