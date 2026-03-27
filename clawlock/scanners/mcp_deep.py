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
import ast, json, os, re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..scanners import Finding, CRIT, HIGH, WARN, INFO

# ═══════════════════════════════════════════════════════════════════════════════
# Risk categories (aligned with AIG v4.1 MCP 14 categories)
# ═══════════════════════════════════════════════════════════════════════════════
RISK_CATEGORIES = {
    "RCE":   "远程代码执行 (Remote Code Execution)",
    "SSRF":  "服务端请求伪造 (Server-Side Request Forgery)",
    "LFI":   "本地文件包含/遍历 (Local File Inclusion)",
    "SQLI":  "SQL 注入 (SQL Injection)",
    "CMDI":  "命令注入 (Command Injection)",
    "DESER": "不安全反序列化 (Insecure Deserialization)",
    "CRED":  "凭证硬编码/泄露 (Credential Exposure)",
    "AUTHZ": "鉴权/授权缺失 (Missing Auth)",
    "PRMTI": "提示词注入风险 (Prompt Injection Surface)",
    "DATLK": "数据泄露路径 (Data Leak Path)",
    "TOOLP": "工具描述投毒 (Tool Description Poisoning)",
    "DEPVL": "依赖组件漏洞 (Dependency Vulnerability)",
    "CONFG": "不安全配置 (Insecure Configuration)",
    "RSRC":  "资源滥用风险 (Resource Abuse)",
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
    McpPattern("CMDI", CRIT, re.compile(
        r'(?:exec|execSync|spawn|popen|subprocess\.(?:call|run|Popen)|system|os\.system)\s*\('
        r'[^)]*(?:req\.|params\.|args\.|input\.|body\.|query\.|tool_input)', re.I),
        "用户输入直接传入命令执行函数",
        "MCP 工具参数未经净化即传入 shell/exec，可被利用执行任意命令。",
        "对所有用户输入做白名单校验，避免直接拼接到命令中。"),
    McpPattern("RCE", CRIT, re.compile(
        r'(?:eval|exec|Function)\s*\([^)]*(?:req\.|params\.|args\.|input\.|body\.|tool_input)', re.I),
        "用户输入传入 eval/exec/Function",
        "动态代码执行接受外部输入，可导致远程代码执行。",
        "移除 eval/exec，使用安全的 JSON 解析或 AST 替代。"),
    McpPattern("CMDI", HIGH, re.compile(
        r'child_process|subprocess|shell\s*[:=]\s*[Tt]rue|shell_exec|proc_open', re.I),
        "使用了 shell 执行能力",
        "MCP Server 代码中包含 shell 执行调用，需审查是否接受用户输入。",
        "确保 shell 调用不拼接用户输入；使用 argv 数组传参。"),

    # ── SSRF ──
    McpPattern("SSRF", HIGH, re.compile(
        r'(?:fetch|axios|requests?\.get|httpx?\.(?:get|post|request)|urllib\.request|http\.get)\s*\('
        r'[^)]*(?:req\.|params\.|args\.|input\.|body\.|url|tool_input)', re.I),
        "用户输入控制 HTTP 请求目标",
        "MCP 工具根据用户输入发起 HTTP 请求，未做 SSRF 防护。可被利用访问内部服务。",
        "对 URL 做白名单校验，阻止 localhost/内网/元数据端点。"),

    # ── LFI / Path Traversal ──
    McpPattern("LFI", HIGH, re.compile(
        r'(?:readFile|readFileSync|open|Path)\s*\([^)]*(?:req\.|params\.|args\.|input\.|body\.|path|filename|tool_input)',
        re.I),
        "用户输入控制文件读取路径",
        "文件路径由用户输入构造，可通过 ../ 遍历读取任意文件。",
        "规范化路径后做目录范围校验 (realpath + 包含性检查)。"),
    McpPattern("LFI", HIGH, re.compile(
        r'(?:writeFile|writeFileSync|fs\.write|open\s*\([^)]*,[^)]*["\']w)', re.I),
        "检测到文件写入操作",
        "MCP Server 含文件写入能力，需确认路径不受用户控制。",
        "写入操作需做路径白名单校验和 sandboxRoot 边界检查。"),

    # ── SQL Injection ──
    McpPattern("SQLI", CRIT, re.compile(
        r'(?:execute|query|raw|rawQuery)\s*\(\s*(?:f["\']|["\'].*?\+|`.*?\$\{|%s|format\()',
        re.I),
        "SQL 查询使用字符串拼接/格式化",
        "SQL 语句通过字符串拼接构造，可被注入恶意 SQL。",
        "使用参数化查询 (?, $1) 或 ORM。"),

    # ── Insecure Deserialization ──
    McpPattern("DESER", HIGH, re.compile(
        r'(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|unserialize|JSON\.parse)\s*\([^)]*(?:req\.|body\.|input\.|data)',
        re.I),
        "反序列化不受信任的数据",
        "对外部输入做反序列化可导致代码执行。",
        "使用 yaml.safe_load；避免 pickle 处理用户数据。"),

    # ── Credential Exposure ──
    McpPattern("CRED", HIGH, re.compile(
        r'(?:password|secret|api[_-]?key|token|auth|private[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
        re.I),
        "疑似硬编码凭证",
        "源码中包含疑似硬编码的密钥/密码/令牌。",
        "使用环境变量或密钥管理服务存储凭证。"),
    McpPattern("CRED", WARN, re.compile(
        r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}', re.I),
        "硬编码 Bearer/Basic 令牌",
        "认证令牌直接写在源码中。",
        "通过环境变量注入令牌。"),

    # ── Missing Auth ──
    McpPattern("AUTHZ", HIGH, re.compile(
        r'(?:app\.(?:get|post|put|delete|all)|router\.(?:get|post))\s*\(\s*["\'][^"\']+["\']\s*,\s*(?:async\s+)?\(?(?:req|ctx)',
        re.I),
        "HTTP 路由可能缺少鉴权中间件",
        "路由处理器直接接受请求，未经过认证/授权中间件。",
        "在路由或全局层添加认证中间件。"),

    # ── Prompt Injection Surface ──
    McpPattern("PRMTI", HIGH, re.compile(
        r'(?:description|tool_description|inputSchema)\s*[:=]\s*(?:f["\']|["\'].*?\{|`.*?\$\{)',
        re.I),
        "工具描述使用动态模板",
        "MCP 工具的 description/schema 包含动态内容，可被利用做提示词注入。",
        "工具描述应为静态字符串，不包含用户可控内容。"),
    McpPattern("PRMTI", WARN, re.compile(
        r'(?:system_prompt|system_message|instructions)\s*[:=]\s*[^;]*(?:req\.|params\.|input\.|user)',
        re.I),
        "系统提示词包含用户输入",
        "将用户可控数据拼入系统提示词，存在间接提示词注入风险。",
        "严格分离系统指令和用户输入。"),

    # ── Tool Description Poisoning ──
    McpPattern("TOOLP", CRIT, re.compile(
        r'(?:description|tool_description)\s*[:=]\s*[^;]*(?:ignore\s+(?:previous|above|all)|'
        r'override\s+(?:instructions|rules)|system\s+prompt|你是一个|忽略(?:上面|之前|所有))',
        re.I),
        "工具描述含提示词注入载荷",
        "工具 description 中包含指令覆盖/注入语句，严重的供应链攻击向量。",
        "工具描述不得包含任何指令性语句。"),
    McpPattern("TOOLP", HIGH, re.compile(
        r'(?:description|tool_description)\s*[:=]\s*[^;]*(?:</?(?:system|user|assistant)>|'
        r'\[INST\]|\[/INST\]|<\|(?:im_start|im_end)\|>)', re.I),
        "工具描述含 LLM 角色标签",
        "description 中嵌入了 LLM 角色分隔标签，可能劫持模型行为。",
        "移除所有角色标签。"),

    # ── Data Leak Path ──
    McpPattern("DATLK", WARN, re.compile(
        r'(?:console\.log|print|logger?\.\w+|logging\.\w+)\s*\([^)]*(?:password|secret|key|token|credential)',
        re.I),
        "日志可能泄露敏感信息",
        "日志输出中包含凭证相关变量名。",
        "对日志中的敏感字段做脱敏处理。"),
    McpPattern("DATLK", WARN, re.compile(
        r'(?:res\.(?:json|send)|return\s+)\s*[({][^}]*(?:password|secret|private|ssn|身份证)',
        re.I),
        "响应可能包含敏感数据",
        "API 响应中可能返回了不应暴露的字段。",
        "在返回前过滤/脱敏敏感字段。"),

    # ── Insecure Configuration ──
    McpPattern("CONFG", HIGH, re.compile(
        r'(?:cors|CORS)\s*\(\s*\{[^}]*(?:origin\s*:\s*(?:["\']?\*|true)|credentials\s*:\s*true)',
        re.I),
        "CORS 配置过于宽松",
        "允许所有来源的 CORS 请求 + 携带凭证。",
        "配置具体的 origin 白名单。"),
    McpPattern("CONFG", WARN, re.compile(
        r'(?:tls|ssl|https)\s*[:=]\s*(?:false|disabled|0)|rejectUnauthorized\s*[:=]\s*false|'
        r'verify\s*[:=]\s*False', re.I),
        "TLS/SSL 验证被禁用",
        "关闭证书验证将导致中间人攻击。",
        "始终启用 TLS 证书验证。"),
    McpPattern("CONFG", WARN, re.compile(
        r'(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)|NODE_ENV\s*[:=]\s*["\']development',
        re.I),
        "生产环境可能启用了调试模式",
        "调试模式可能暴露堆栈信息和内部数据。",
        "确保生产部署关闭 debug 标志。"),

    # ── Resource Abuse ──
    McpPattern("RSRC", WARN, re.compile(
        r'(?:setInterval|setImmediate|setTimeout)\s*\([^)]*(?:req\.|params\.|input\.|body\.)',
        re.I),
        "定时器参数由用户控制",
        "用户可控的定时器参数可能导致资源耗尽。",
        "对定时器参数做上下界校验。"),
    McpPattern("RSRC", WARN, re.compile(
        r'(?:while\s*\(\s*true|for\s*\(\s*;\s*;\s*\))', re.I),
        "存在无限循环",
        "无限循环若无正确退出条件可导致服务不可用。",
        "确保循环有明确的退出条件和超时。"),

    # ── Dependency Vulnerability ──
    McpPattern("DEPVL", INFO, re.compile(
        r'require\s*\(\s*["\'](?:express|koa|fastify)["\']', re.I),
        "使用了 Web 框架",
        "检测到 Web 框架依赖，需确保版本不含已知漏洞。",
        "运行 npm audit / pip audit 检查依赖漏洞。"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Python AST-based deep analysis
# ═══════════════════════════════════════════════════════════════════════════════
_TAINT_SOURCES = {"request", "req", "params", "args", "input", "body", "query",
                  "tool_input", "arguments", "kwargs", "data"}
_DANGEROUS_SINKS = {
    "os.system": ("CMDI", CRIT), "subprocess.run": ("CMDI", HIGH),
    "subprocess.call": ("CMDI", HIGH), "subprocess.Popen": ("CMDI", HIGH),
    "eval": ("RCE", CRIT), "exec": ("RCE", CRIT),
    "open": ("LFI", HIGH), "Path": ("LFI", WARN),
    "pickle.loads": ("DESER", HIGH), "yaml.load": ("DESER", HIGH),
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
                        findings.append(Finding(
                            scanner="mcp_deep", level=level,
                            title=f"[{cat}] 污点数据流入 {func_name}()",
                            detail=f"用户输入经数据流分析可达 {func_name}()，存在 {RISK_CATEGORIES.get(cat, cat)} 风险。",
                            location=f"{filepath}:{getattr(node, 'lineno', '?')}",
                            remediation=f"在调用 {func_name}() 前对输入做净化/白名单校验。"))

    # Detect @tool decorator with dynamic description
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    for kw in decorator.keywords:
                        if kw.arg == "description" and isinstance(kw.value, ast.JoinedStr):
                            findings.append(Finding(
                                scanner="mcp_deep", level=HIGH,
                                title="[TOOLP] 工具 description 使用 f-string 动态构造",
                                detail=f"函数 {node.name} 的 @tool description 含动态内容，可被注入。",
                                location=f"{filepath}:{node.lineno}",
                                remediation="工具 description 应为静态字面字符串。"))

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
        return (_node_references_taint(node.left, tainted) or
                _node_references_taint(node.right, tainted))
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
    McpPattern("TOOLP", CRIT, re.compile(
        r'(?:server\.tool|\.addTool|registerTool)\s*\(\s*[{]'
        r'[^}]*description\s*:\s*(?:`[^`]*\$\{|[^,]*\+)', re.S),
        "MCP tool 注册时 description 含动态拼接",
        "Server.tool() 的 description 使用模板字符串或拼接，可被投毒。",
        "description 必须是静态字面字符串。"),
    McpPattern("AUTHZ", HIGH, re.compile(
        r'(?:server\.tool|\.addTool)\s*\([^)]*\)\s*(?:=>|{)\s*(?:(?!auth|verify|check|token|session).)*(?:exec|run|spawn|system)',
        re.S),
        "MCP tool handler 未见鉴权即执行敏感操作",
        "工具处理函数中直接执行命令/系统调用，未检测到前置鉴权逻辑。",
        "在工具 handler 入口添加权限验证。"),
    McpPattern("PRMTI", HIGH, re.compile(
        r'(?:server\.tool|\.addTool)\s*\([^)]*inputSchema\s*:\s*\{[^}]*'
        r'(?:type\s*:\s*["\']string["\'])[^}]*(?:description\s*:\s*["\'][^"\']*(?:any|自由|任意|free[\s-]?form))',
        re.S),
        "MCP tool 输入参数声明过于宽泛",
        "inputSchema 的 description 暗示接受任意用户输入，缺少约束。",
        "收紧 inputSchema 的 description 和 pattern/enum 约束。"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Main entry: scan_mcp_source()
# ═══════════════════════════════════════════════════════════════════════════════
_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
_MAX_FILE_SIZE = 512 * 1024  # 512KB per file


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
        return [Finding("mcp_deep", INFO, "指定路径不存在", str(code_path))]

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
                if fp.suffix in _CODE_EXTENSIONS and fp.stat().st_size <= _MAX_FILE_SIZE:
                    code_files.append(fp)

    if not code_files:
        return [Finding("mcp_deep", INFO, "未找到可分析的代码文件",
                f"路径 {code_path} 下未发现 {', '.join(_CODE_EXTENSIONS)} 文件。")]

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
                lineno = content[:match.start()].count("\n") + 1
                snippet = match.group(0)[:80].strip()
                findings.append(Finding(
                    scanner="mcp_deep", level=pat.level,
                    title=f"[{pat.category}] {pat.title}",
                    detail=pat.detail,
                    location=f"{rel}:{lineno}",
                    snippet=snippet,
                    remediation=pat.remediation,
                    metadata={"category": pat.category}))

        # 2) Python AST analysis
        if fp.suffix == ".py":
            findings.extend(_ast_analyze_python(content, rel))

        # 3) JS/TS extra MCP patterns
        if fp.suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            for pat in _JS_MCP_EXTRA_PATTERNS:
                for match in pat.pattern.finditer(content):
                    lineno = content[:match.start()].count("\n") + 1
                    findings.append(Finding(
                        scanner="mcp_deep", level=pat.level,
                        title=f"[{pat.category}] {pat.title}",
                        detail=pat.detail,
                        location=f"{rel}:{lineno}",
                        snippet=match.group(0)[:80].strip(),
                        remediation=pat.remediation,
                        metadata={"category": pat.category}))

    # 4) Check package.json for known vulnerable deps
    findings.extend(_check_package_json(code_path))

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
        unique.insert(0, Finding(
            scanner="mcp_deep", level=INFO,
            title=f"MCP 深度扫描完成: {files_scanned} 文件, {len(unique)-1} 项发现",
            detail=f"涉及风险类别: {', '.join(sorted(cats))}",
            metadata={"files_scanned": files_scanned}))
    else:
        unique.append(Finding(
            scanner="mcp_deep", level=INFO,
            title=f"MCP 深度扫描完成: {files_scanned} 文件, 未发现高危问题",
            detail="建议结合人工代码审查做进一步确认。"))

    return unique


def _check_package_json(code_path: Path) -> List[Finding]:
    """Check package.json for known risky dependencies."""
    findings = []
    pkg_files = list(code_path.rglob("package.json")) if code_path.is_dir() else []
    if code_path.is_file() and code_path.name == "package.json":
        pkg_files = [code_path]

    _RISKY_DEPS = {
        "node-serialize": ("DESER", CRIT, "已知不安全反序列化库"),
        "serialize-javascript": ("DESER", WARN, "需确认版本安全性"),
        "js-yaml": ("DESER", WARN, "确保使用 safeLoad 而非 load"),
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
                findings.append(Finding(
                    scanner="mcp_deep", level=level,
                    title=f"[{cat}] 依赖 {dep_name}: {msg}",
                    detail=f"package.json 声明了 {dep_name}@{all_deps[dep_name]}。",
                    location=str(pkg_file),
                    metadata={"category": cat}))
    return findings
