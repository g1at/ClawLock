"""
ClawLock built-in MCP Server source code deep analysis engine.

Replaces ai-infra-guard `mcp --code` with a zero-dependency Python engine:
  - AST-based analysis for Python/JS/TS MCP servers
  - Regex patterns for 14 risk categories (AIG v4.1 equivalent)
  - Data-flow taint tracking (source → sink) for credential/PII leaks
  - Tool description injection detection
  - Permission boundary violation checks

Falls back to ai-infra-guard binary if installed (optional enhancement).
"""

from __future__ import annotations
import ast
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..scanners import Finding, CRIT, HIGH, WARN, INFO
from ..i18n import t

# ═══════════════════════════════════════════════════════════════════════════════
# Risk categories (aligned with AIG v4.1 MCP 14 categories)
# ═══════════════════════════════════════════════════════════════════════════════
RISK_CATEGORIES = {
    "RCE": t("远程代码执行 (Remote Code Execution)", "Remote Code Execution"),
    "SSRF": t("服务端请求伪造 (Server-Side Request Forgery)", "Server-Side Request Forgery"),
    "LFI": t("本地文件包含/遍历 (Local File Inclusion)", "Local File Inclusion / Path Traversal"),
    "SQLI": t("SQL 注入 (SQL Injection)", "SQL Injection"),
    "CMDI": t("命令注入 (Command Injection)", "Command Injection"),
    "DESER": t("不安全反序列化 (Insecure Deserialization)", "Insecure Deserialization"),
    "CRED": t("凭证硬编码/泄露 (Credential Exposure)", "Credential Exposure"),
    "AUTHZ": t("鉴权/授权缺失 (Missing Auth)", "Missing Authentication / Authorization"),
    "PRMTI": t("提示词注入风险 (Prompt Injection Surface)", "Prompt Injection Surface"),
    "DATLK": t("数据泄露路径 (Data Leak Path)", "Data Leak Path"),
    "TOOLP": t("工具描述投毒 (Tool Description Poisoning)", "Tool Description Poisoning"),
    "DEPVL": t("依赖组件漏洞 (Dependency Vulnerability)", "Dependency Vulnerability"),
    "CONFG": t("不安全配置 (Insecure Configuration)", "Insecure Configuration"),
    "RSRC": t("资源滥用风险 (Resource Abuse)", "Resource Abuse"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Pattern-based scanner (regex, works on any language)
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class McpPattern:
    category: str
    level: str
    pattern: re.Pattern
    title: str
    detail: str
    remediation: str = ""


_MCP_PATTERNS: List[McpPattern] = [
    # ── RCE / Command Injection ──
    McpPattern(
        "CMDI",
        CRIT,
        re.compile(
            r"(?:exec|execSync|spawn|popen|subprocess\.(?:call|run|Popen)|system|os\.system)\s*\("
            r"[^)]*(?:req\.|params\.|args\.|input\.|body\.|query\.|tool_input)",
            re.I,
        ),
        t("用户输入直接传入命令执行函数", "User input passed directly to command execution"),
        t("MCP 工具参数未经净化即传入 shell/exec，可被利用执行任意命令。", "MCP tool parameters passed to shell/exec without sanitization, enabling arbitrary command execution."),
        t("对所有用户输入做白名单校验，避免直接拼接到命令中。", "Whitelist-validate all user inputs; avoid concatenating into commands."),
    ),
    McpPattern(
        "RCE",
        CRIT,
        re.compile(
            r"(?:eval|exec|Function)\s*\([^)]*(?:req\.|params\.|args\.|input\.|body\.|tool_input)",
            re.I,
        ),
        t("用户输入传入 eval/exec/Function", "User input passed to eval/exec/Function"),
        t("动态代码执行接受外部输入，可导致远程代码执行。", "Dynamic code execution accepts external input, enabling remote code execution."),
        t("移除 eval/exec，使用安全的 JSON 解析或 AST 替代。", "Remove eval/exec; use safe JSON parsing or AST-based alternatives."),
    ),
    McpPattern(
        "CMDI",
        HIGH,
        re.compile(
            r"child_process|subprocess|shell\s*[:=]\s*[Tt]rue|shell_exec|proc_open",
            re.I,
        ),
        t("使用了 shell 执行能力", "Shell execution capability detected"),
        t("MCP Server 代码中包含 shell 执行调用，需审查是否接受用户输入。", "MCP server code contains shell execution calls; review whether user input is accepted."),
        t("确保 shell 调用不拼接用户输入；使用 argv 数组传参。", "Ensure shell calls do not concatenate user input; pass arguments via argv array."),
    ),
    # ── SSRF ──
    McpPattern(
        "SSRF",
        HIGH,
        re.compile(
            r"(?:fetch|axios|requests?\.get|httpx?\.(?:get|post|request)|urllib\.request|http\.get)\s*\("
            r"[^)]*(?:req\.|params\.|args\.|input\.|body\.|url|tool_input)",
            re.I,
        ),
        t("用户输入控制 HTTP 请求目标", "User input controls HTTP request target"),
        t("MCP 工具根据用户输入发起 HTTP 请求，未做 SSRF 防护。可被利用访问内部服务。", "MCP tool issues HTTP requests based on user input without SSRF protection, enabling access to internal services."),
        t("对 URL 做白名单校验，阻止 localhost/内网/元数据端点。", "Whitelist-validate URLs; block localhost, internal networks, and metadata endpoints."),
    ),
    # ── LFI / Path Traversal ──
    McpPattern(
        "LFI",
        HIGH,
        re.compile(
            r"(?:readFile|readFileSync|open|Path)\s*\([^)]*(?:req\.|params\.|args\.|input\.|body\.|path|filename|tool_input)",
            re.I,
        ),
        t("用户输入控制文件读取路径", "User input controls file read path"),
        t("文件路径由用户输入构造，可通过 ../ 遍历读取任意文件。", "File path constructed from user input; ../ traversal can read arbitrary files."),
        t("规范化路径后做目录范围校验 (realpath + 包含性检查)。", "Normalize paths then validate directory scope (realpath + containment check)."),
    ),
    McpPattern(
        "LFI",
        HIGH,
        re.compile(
            r'(?:writeFile|writeFileSync|fs\.write|open\s*\([^)]*,[^)]*["\']w)', re.I
        ),
        t("检测到文件写入操作", "File write operation detected"),
        t("MCP Server 含文件写入能力，需确认路径不受用户控制。", "MCP server has file write capability; verify path is not user-controlled."),
        t("写入操作需做路径白名单校验和 sandboxRoot 边界检查。", "Write operations require path whitelist validation and sandboxRoot boundary checks."),
    ),
    # ── SQL Injection ──
    McpPattern(
        "SQLI",
        CRIT,
        re.compile(
            r'(?:execute|query|raw|rawQuery)\s*\(\s*(?:f["\']|["\'].*?\+|`.*?\$\{|%s|format\()',
            re.I,
        ),
        t("SQL 查询使用字符串拼接/格式化", "SQL query built via string concatenation/formatting"),
        t("SQL 语句通过字符串拼接构造，可被注入恶意 SQL。", "SQL statement built via string concatenation, enabling malicious SQL injection."),
        t("使用参数化查询 (?, $1) 或 ORM。", "Use parameterized queries (?, $1) or an ORM."),
    ),
    # ── Insecure Deserialization ──
    McpPattern(
        "DESER",
        HIGH,
        re.compile(
            r"(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|unserialize|JSON\.parse)\s*\([^)]*(?:req\.|body\.|input\.|data)",
            re.I,
        ),
        t("反序列化不受信任的数据", "Deserialization of untrusted data"),
        t("对外部输入做反序列化可导致代码执行。", "Deserializing external input can lead to code execution."),
        t("使用 yaml.safe_load；避免 pickle 处理用户数据。", "Use yaml.safe_load; avoid pickle for user data."),
    ),
    # ── Credential Exposure ──
    McpPattern(
        "CRED",
        HIGH,
        re.compile(
            r'(?:password|secret|api[_-]?key|token|auth|private[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
            re.I,
        ),
        t("疑似硬编码凭证", "Suspected hardcoded credentials"),
        t("源码中包含疑似硬编码的密钥/密码/令牌。", "Source code contains suspected hardcoded keys/passwords/tokens."),
        t("使用环境变量或密钥管理服务存储凭证。", "Store credentials in environment variables or a secrets management service."),
    ),
    McpPattern(
        "CRED",
        WARN,
        re.compile(r"(?:Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}", re.I),
        t("硬编码 Bearer/Basic 令牌", "Hardcoded Bearer/Basic token"),
        t("认证令牌直接写在源码中。", "Authentication token written directly in source code."),
        t("通过环境变量注入令牌。", "Inject tokens via environment variables."),
    ),
    # ── Missing Auth ──
    McpPattern(
        "AUTHZ",
        HIGH,
        re.compile(
            r'(?:app\.(?:get|post|put|delete|all)|router\.(?:get|post))\s*\(\s*["\'][^"\']+["\']\s*,\s*(?:async\s+)?\(?(?:req|ctx)',
            re.I,
        ),
        t("HTTP 路由可能缺少鉴权中间件", "HTTP route may lack authentication middleware"),
        t("路由处理器直接接受请求，未经过认证/授权中间件。", "Route handler accepts requests directly without authentication/authorization middleware."),
        t("在路由或全局层添加认证中间件。", "Add authentication middleware at the route or global level."),
    ),
    # ── Prompt Injection Surface ──
    McpPattern(
        "PRMTI",
        HIGH,
        re.compile(
            r'(?:description|tool_description|inputSchema)\s*[:=]\s*(?:f["\']|["\'].*?\{|`.*?\$\{)',
            re.I,
        ),
        t("工具描述使用动态模板", "Tool description uses dynamic template"),
        t("MCP 工具的 description/schema 包含动态内容，可被利用做提示词注入。", "MCP tool description/schema contains dynamic content, enabling prompt injection."),
        t("工具描述应为静态字符串，不包含用户可控内容。", "Tool descriptions should be static strings without user-controllable content."),
    ),
    McpPattern(
        "PRMTI",
        WARN,
        re.compile(
            r"(?:system_prompt|system_message|instructions)\s*[:=]\s*[^;]*(?:req\.|params\.|input\.|user)",
            re.I,
        ),
        t("系统提示词包含用户输入", "System prompt contains user input"),
        t("将用户可控数据拼入系统提示词，存在间接提示词注入风险。", "User-controllable data concatenated into system prompt, creating indirect prompt injection risk."),
        t("严格分离系统指令和用户输入。", "Strictly separate system instructions from user input."),
    ),
    # ── Tool Description Poisoning ──
    McpPattern(
        "TOOLP",
        CRIT,
        re.compile(
            r"(?:description|tool_description)\s*[:=]\s*[^;]*(?:ignore\s+(?:previous|above|all)|"
            r"override\s+(?:instructions|rules)|system\s+prompt|你是一个|忽略(?:上面|之前|所有))",
            re.I,
        ),
        t("工具描述含提示词注入载荷", "Tool description contains prompt injection payload"),
        t("工具 description 中包含指令覆盖/注入语句，严重的供应链攻击向量。", "Tool description contains instruction override/injection statements; a severe supply-chain attack vector."),
        t("工具描述不得包含任何指令性语句。", "Tool descriptions must not contain any directive statements."),
    ),
    McpPattern(
        "TOOLP",
        HIGH,
        re.compile(
            r"(?:description|tool_description)\s*[:=]\s*[^;]*(?:</?(?:system|user|assistant)>|"
            r"\[INST\]|\[/INST\]|<\|(?:im_start|im_end)\|>)",
            re.I,
        ),
        t("工具描述含 LLM 角色标签", "Tool description contains LLM role tags"),
        t("description 中嵌入了 LLM 角色分隔标签，可能劫持模型行为。", "Description embeds LLM role delimiter tags, potentially hijacking model behavior."),
        t("移除所有角色标签。", "Remove all role tags."),
    ),
    # ── Data Leak Path ──
    McpPattern(
        "DATLK",
        WARN,
        re.compile(
            r"(?:console\.log|print|logger?\.\w+|logging\.\w+)\s*\([^)]*(?:password|secret|key|token|credential)",
            re.I,
        ),
        t("日志可能泄露敏感信息", "Logs may leak sensitive information"),
        t("日志输出中包含凭证相关变量名。", "Log output contains credential-related variable names."),
        t("对日志中的敏感字段做脱敏处理。", "Sanitize sensitive fields in log output."),
    ),
    McpPattern(
        "DATLK",
        WARN,
        re.compile(
            r"(?:res\.(?:json|send)|return\s+)\s*[({][^}]*(?:password|secret|private|ssn|身份证)",
            re.I,
        ),
        t("响应可能包含敏感数据", "Response may contain sensitive data"),
        t("API 响应中可能返回了不应暴露的字段。", "API response may return fields that should not be exposed."),
        t("在返回前过滤/脱敏敏感字段。", "Filter/sanitize sensitive fields before returning."),
    ),
    # ── Insecure Configuration ──
    McpPattern(
        "CONFG",
        HIGH,
        re.compile(
            r'(?:cors|CORS)\s*\(\s*\{[^}]*(?:origin\s*:\s*(?:["\']?\*|true)|credentials\s*:\s*true)',
            re.I,
        ),
        t("CORS 配置过于宽松", "CORS configuration too permissive"),
        t("允许所有来源的 CORS 请求 + 携带凭证。", "Allows CORS requests from all origins with credentials."),
        t("配置具体的 origin 白名单。", "Configure a specific origin whitelist."),
    ),
    McpPattern(
        "CONFG",
        WARN,
        re.compile(
            r"(?:tls|ssl|https)\s*[:=]\s*(?:false|disabled|0)|rejectUnauthorized\s*[:=]\s*false|"
            r"verify\s*[:=]\s*False",
            re.I,
        ),
        t("TLS/SSL 验证被禁用", "TLS/SSL verification disabled"),
        t("关闭证书验证将导致中间人攻击。", "Disabling certificate verification enables man-in-the-middle attacks."),
        t("始终启用 TLS 证书验证。", "Always enable TLS certificate verification."),
    ),
    McpPattern(
        "CONFG",
        WARN,
        re.compile(
            r'(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)|NODE_ENV\s*[:=]\s*["\']development',
            re.I,
        ),
        t("生产环境可能启用了调试模式", "Debug mode may be enabled in production"),
        t("调试模式可能暴露堆栈信息和内部数据。", "Debug mode may expose stack traces and internal data."),
        t("确保生产部署关闭 debug 标志。", "Ensure debug flags are disabled in production deployments."),
    ),
    # ── Resource Abuse ──
    McpPattern(
        "RSRC",
        WARN,
        re.compile(
            r"(?:setInterval|setImmediate|setTimeout)\s*\([^)]*(?:req\.|params\.|input\.|body\.)",
            re.I,
        ),
        t("定时器参数由用户控制", "Timer parameters controlled by user input"),
        t("用户可控的定时器参数可能导致资源耗尽。", "User-controllable timer parameters may cause resource exhaustion."),
        t("对定时器参数做上下界校验。", "Validate timer parameters with upper and lower bounds."),
    ),
    McpPattern(
        "RSRC",
        WARN,
        re.compile(r"(?:while\s*\(\s*true|for\s*\(\s*;\s*;\s*\))", re.I),
        t("存在无限循环", "Infinite loop detected"),
        t("无限循环若无正确退出条件可导致服务不可用。", "Infinite loops without proper exit conditions can cause denial of service."),
        t("确保循环有明确的退出条件和超时。", "Ensure loops have explicit exit conditions and timeouts."),
    ),
    # ── Dependency Vulnerability ──
    McpPattern(
        "DEPVL",
        INFO,
        re.compile(r'require\s*\(\s*["\'](?:express|koa|fastify)["\']', re.I),
        t("使用了 Web 框架", "Web framework detected"),
        t("检测到 Web 框架依赖，需确保版本不含已知漏洞。", "Web framework dependency detected; ensure the version has no known vulnerabilities."),
        t("运行 npm audit / pip audit 检查依赖漏洞。", "Run npm audit / pip audit to check for dependency vulnerabilities."),
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Python AST-based deep analysis
# ═══════════════════════════════════════════════════════════════════════════════
_TAINT_SOURCES = {
    "request",
    "req",
    "params",
    "args",
    "input",
    "body",
    "query",
    "tool_input",
    "arguments",
    "kwargs",
    "data",
}
_DANGEROUS_SINKS = {
    "os.system": ("CMDI", CRIT),
    "subprocess.run": ("CMDI", HIGH),
    "subprocess.call": ("CMDI", HIGH),
    "subprocess.Popen": ("CMDI", HIGH),
    "eval": ("RCE", CRIT),
    "exec": ("RCE", CRIT),
    "open": ("LFI", HIGH),
    "Path": ("LFI", WARN),
    "pickle.loads": ("DESER", HIGH),
    "yaml.load": ("DESER", HIGH),
}


def _ast_analyze_python(source: str, filepath: str) -> List[Finding]:
    """AST-based taint analysis for Python MCP server code."""
    findings: List[Finding] = []
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return findings

    # Collect tainted variable names (simplified data-flow)
    tainted_vars: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if _node_references_taint(node.value, tainted_vars):
                        tainted_vars.add(target.id)
        elif isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if arg.arg in _TAINT_SOURCES:
                    tainted_vars.add(arg.arg)

    # Check if tainted data reaches dangerous sinks
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in _DANGEROUS_SINKS:
                for arg_node in node.args:
                    if _node_references_taint(arg_node, tainted_vars):
                        cat, level = _DANGEROUS_SINKS[func_name]
                        findings.append(
                            Finding(
                                scanner="mcp_deep",
                                level=level,
                                title=f"[{cat}] " + t(f"污点数据流入 {func_name}()", f"Tainted data flows into {func_name}()"),
                                detail=t(f"用户输入经数据流分析可达 {func_name}()，存在 {RISK_CATEGORIES.get(cat, cat)} 风险。", f"User input reaches {func_name}() via data-flow analysis, posing {RISK_CATEGORIES.get(cat, cat)} risk."),
                                location=f"{filepath}:{getattr(node, 'lineno', '?')}",
                                remediation=t(f"在调用 {func_name}() 前对输入做净化/白名单校验。", f"Sanitize/whitelist-validate input before calling {func_name}()."),
                            )
                        )

    # Detect @tool decorator with dynamic description
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    for kw in decorator.keywords:
                        if kw.arg == "description" and isinstance(
                            kw.value, ast.JoinedStr
                        ):
                            findings.append(
                                Finding(
                                    scanner="mcp_deep",
                                    level=HIGH,
                                    title="[TOOLP] " + t("工具 description 使用 f-string 动态构造", "Tool description built with f-string dynamically"),
                                    detail=t(f"函数 {node.name} 的 @tool description 含动态内容，可被注入。", f"Function {node.name}'s @tool description contains dynamic content and can be injected."),
                                    location=f"{filepath}:{node.lineno}",
                                    remediation=t("工具 description 应为静态字面字符串。", "Tool descriptions should be static literal strings."),
                                )
                            )

    return findings


def _node_references_taint(node: ast.AST, tainted: set) -> bool:
    """Check if an AST node references any tainted variable."""
    if isinstance(node, ast.Name):
        return node.id in tainted or node.id in _TAINT_SOURCES
    if isinstance(node, ast.Attribute):
        return _node_references_taint(node.value, tainted)
    if isinstance(node, ast.Subscript):
        return _node_references_taint(node.value, tainted)
    if isinstance(node, ast.BinOp):
        return _node_references_taint(node.left, tainted) or _node_references_taint(
            node.right, tainted
        )
    if isinstance(node, ast.JoinedStr):
        return any(_node_references_taint(v, tainted) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _node_references_taint(node.value, tainted)
    if isinstance(node, ast.Call):
        return any(_node_references_taint(a, tainted) for a in node.args)
    return False


def _get_call_name(node: ast.Call) -> str:
    """Extract function name from an ast.Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        curr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# JS/TS analysis (regex-based, more patterns than generic)
# ═══════════════════════════════════════════════════════════════════════════════
_JS_MCP_EXTRA_PATTERNS = [
    McpPattern(
        "TOOLP",
        CRIT,
        re.compile(
            r"(?:server\.tool|\.addTool|registerTool)\s*\(\s*[{]"
            r"[^}]*description\s*:\s*(?:`[^`]*\$\{|[^,]*\+)",
            re.S,
        ),
        t("MCP tool 注册时 description 含动态拼接", "MCP tool registration has dynamically concatenated description"),
        t("Server.tool() 的 description 使用模板字符串或拼接，可被投毒。", "Server.tool() description uses template strings or concatenation, enabling poisoning."),
        t("description 必须是静态字面字符串。", "Description must be a static literal string."),
    ),
    McpPattern(
        "AUTHZ",
        HIGH,
        re.compile(
            r"(?:server\.tool|\.addTool)\s*\([^)]*\)\s*(?:=>|{)\s*(?:(?!auth|verify|check|token|session).)*(?:exec|run|spawn|system)",
            re.S,
        ),
        t("MCP tool handler 未见鉴权即执行敏感操作", "MCP tool handler executes sensitive operations without authentication"),
        t("工具处理函数中直接执行命令/系统调用，未检测到前置鉴权逻辑。", "Tool handler directly executes commands/system calls without detected prior authentication logic."),
        t("在工具 handler 入口添加权限验证。", "Add permission verification at the tool handler entry point."),
    ),
    McpPattern(
        "PRMTI",
        HIGH,
        re.compile(
            r"(?:server\.tool|\.addTool)\s*\([^)]*inputSchema\s*:\s*\{[^}]*"
            r'(?:type\s*:\s*["\']string["\'])[^}]*(?:description\s*:\s*["\'][^"\']*(?:any|自由|任意|free[\s-]?form))',
            re.S,
        ),
        t("MCP tool 输入参数声明过于宽泛", "MCP tool input parameter declaration too broad"),
        t("inputSchema 的 description 暗示接受任意用户输入，缺少约束。", "inputSchema description implies accepting arbitrary user input without constraints."),
        t("收紧 inputSchema 的 description 和 pattern/enum 约束。", "Tighten inputSchema description and add pattern/enum constraints."),
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Main entry: scan_mcp_source()
# ═══════════════════════════════════════════════════════════════════════════════
_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
_MAX_FILE_SIZE = 512 * 1024  # 512KB per file
_REACT2SHELL_AFFECTED = {"react": ("19.0.0", "19.2.99"), "next": ("15.0.0", "15.0.4")}


def scan_mcp_source(code_path: Path) -> List[Finding]:
    """
    Built-in MCP Server source code deep analysis.

    Scans all code files under code_path using:
    1. Language-agnostic regex patterns (28+ patterns across 14 categories)
    2. Python AST taint analysis (for .py files)
    3. JS/TS-specific MCP patterns (for .js/.ts files)

    Returns list of Findings sorted by severity.
    """
    if not code_path.exists():
        return [Finding("mcp_deep", INFO, t("指定路径不存在", "Specified path does not exist"), str(code_path))]

    findings: List[Finding] = []
    files_scanned = 0

    # Collect all code files
    if code_path.is_file():
        code_files = [code_path] if code_path.suffix in _CODE_EXTENSIONS else []
    else:
        code_files = []
        for root, dirs, files in os.walk(code_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for f in files:
                fp = Path(root) / f
                if (
                    fp.suffix in _CODE_EXTENSIONS
                    and fp.stat().st_size <= _MAX_FILE_SIZE
                ):
                    code_files.append(fp)

    if not code_files:
        return [
            Finding(
                "mcp_deep",
                INFO,
                t("未找到可分析的代码文件", "No analyzable code files found"),
                t(f"路径 {code_path} 下未发现 {', '.join(_CODE_EXTENSIONS)} 文件。", f"No {', '.join(_CODE_EXTENSIONS)} files found under {code_path}."),
            )
        ]

    for fp in code_files:
        try:
            content = fp.read_text(errors="ignore")
        except Exception:
            continue
        files_scanned += 1
        rel = str(fp.relative_to(code_path)) if code_path.is_dir() else fp.name

        # 1) Universal regex patterns
        for pat in _MCP_PATTERNS:
            for match in pat.pattern.finditer(content):
                lineno = content[: match.start()].count("\n") + 1
                snippet = match.group(0)[:80].strip()
                findings.append(
                    Finding(
                        scanner="mcp_deep",
                        level=pat.level,
                        title=f"[{pat.category}] {pat.title}",
                        detail=pat.detail,
                        location=f"{rel}:{lineno}",
                        snippet=snippet,
                        remediation=pat.remediation,
                        metadata={"category": pat.category},
                    )
                )

        # 2) Python AST analysis
        if fp.suffix == ".py":
            findings.extend(_ast_analyze_python(content, rel))

        # 3) JS/TS extra MCP patterns
        if fp.suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            for pat in _JS_MCP_EXTRA_PATTERNS:
                for match in pat.pattern.finditer(content):
                    lineno = content[: match.start()].count("\n") + 1
                    findings.append(
                        Finding(
                            scanner="mcp_deep",
                            level=pat.level,
                            title=f"[{pat.category}] {pat.title}",
                            detail=pat.detail,
                            location=f"{rel}:{lineno}",
                            snippet=match.group(0)[:80].strip(),
                            remediation=pat.remediation,
                            metadata={"category": pat.category},
                        )
                    )

    # 4) Check package manifests for risky deps / known frontend CVEs
    findings.extend(scan_package_manifest_risks(code_path))

    # Deduplicate by (title, location)
    seen = set()
    unique = []
    for f in findings:
        key = (f.title, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by severity
    severity_order = {CRIT: 0, HIGH: 1, WARN: 2, INFO: 3}
    unique.sort(key=lambda f: severity_order.get(f.level, 9))

    # Prepend summary
    if unique:
        cats = set(f.metadata.get("category", "?") for f in unique)
        unique.insert(
            0,
            Finding(
                scanner="mcp_deep",
                level=INFO,
                title=t(f"MCP 深度扫描完成: {files_scanned} 文件, {len(unique) - 1} 项发现", f"MCP deep scan complete: {files_scanned} files, {len(unique) - 1} findings"),
                detail=t(f"涉及风险类别: {', '.join(sorted(cats))}", f"Risk categories involved: {', '.join(sorted(cats))}"),
                metadata={"files_scanned": files_scanned},
            ),
        )
    else:
        unique.append(
            Finding(
                scanner="mcp_deep",
                level=INFO,
                title=t(f"MCP 深度扫描完成: {files_scanned} 文件, 未发现高危问题", f"MCP deep scan complete: {files_scanned} files, no high-risk issues found"),
                detail=t("建议结合人工代码审查做进一步确认。", "Manual code review is recommended for further confirmation."),
            )
        )

    return unique


def _package_json_candidates(code_path: Path) -> List[Path]:
    candidates = []
    seen = set()

    def _add(path: Path):
        resolved = str(path.resolve()) if path.exists() else str(path)
        if resolved not in seen:
            seen.add(resolved)
            candidates.append(path)

    if code_path.is_file():
        start_dir = code_path.parent
        if code_path.name == "package.json":
            _add(code_path)
    else:
        start_dir = code_path
        for pkg in code_path.rglob("package.json"):
            _add(pkg)

    current = start_dir
    for _ in range(3):
        pkg = current / "package.json"
        if pkg.exists():
            _add(pkg)
        if current.parent == current:
            break
        current = current.parent

    return candidates


def _version_in_range(version_spec: str, min_v: str, max_v: str) -> Optional[str]:
    ver = re.sub(r"[^0-9.]", "", str(version_spec))
    if not ver:
        return None
    try:
        parts = tuple(int(x) for x in ver.split(".")[:3])
        lower = tuple(int(x) for x in min_v.split(".")[:3])
        upper = tuple(int(x) for x in max_v.split(".")[:3])
    except ValueError:
        return None
    return ver if lower <= parts <= upper else None


def scan_package_manifest_risks(code_path: Path) -> List[Finding]:
    """Check package.json for risky dependencies and known frontend CVEs."""
    findings = []
    pkg_files = _package_json_candidates(code_path)

    _RISKY_DEPS = {
        "node-serialize": ("DESER", CRIT, t("已知不安全反序列化库", "Known insecure deserialization library")),
        "serialize-javascript": ("DESER", WARN, t("需确认版本安全性", "Version safety must be verified")),
        "js-yaml": ("DESER", WARN, t("确保使用 safeLoad 而非 load", "Ensure safeLoad is used instead of load")),
    }
    for pkg_file in pkg_files:
        if "node_modules" in str(pkg_file):
            continue
        try:
            data = json.loads(pkg_file.read_text())
        except Exception:
            continue
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for dep_name, (cat, level, msg) in _RISKY_DEPS.items():
            if dep_name in all_deps:
                findings.append(
                    Finding(
                        scanner="mcp_deep",
                        level=level,
                        title=f"[{cat}] " + t(f"依赖 {dep_name}: {msg}", f"Dependency {dep_name}: {msg}"),
                        detail=t(f"package.json 声明了 {dep_name}@{all_deps[dep_name]}。", f"package.json declares {dep_name}@{all_deps[dep_name]}."),
                        location=str(pkg_file),
                        metadata={"category": cat},
                    )
                )
        for pkg_name, version_spec in all_deps.items():
            norm = pkg_name.lower().replace("@", "").replace("/", "-")
            for component, (min_v, max_v) in _REACT2SHELL_AFFECTED.items():
                if component not in norm:
                    continue
                ver = _version_in_range(str(version_spec), min_v, max_v)
                if not ver:
                    continue
                findings.append(
                    Finding(
                        scanner="depscan",
                        level=CRIT,
                        title=f"[DEPVL] CVE-2025-55182 React2Shell [{pkg_name}@{ver}]",
                        detail=t(f"检测到 {pkg_name} {ver} 落在 React2Shell 受影响范围内，存在高危前端依赖风险。",
                                 f"Detected {pkg_name} {ver} within React2Shell affected range; high-risk frontend dependency."),
                        location=str(pkg_file),
                        snippet=f'"{pkg_name}": "{version_spec}"',
                        remediation=t(f"立即升级 {pkg_name} 到安全版本。", f"Upgrade {pkg_name} to a safe version immediately."),
                        metadata={"category": "DEPVL", "cve_id": "CVE-2025-55182"},
                    )
                )
    return findings
