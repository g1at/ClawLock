"""
ClawLock built-in MCP Server source code deep analysis engine.

A zero-dependency Python engine providing:
  - AST-based analysis for Python/JS/TS MCP servers
  - Regex patterns covering 14 risk categories
  - Data-flow taint tracking (source → sink) for credential/PII leaks
  - Tool description injection detection
  - Permission boundary violation checks
"""

from __future__ import annotations
import ast
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..scanners import Finding, CRIT, HIGH, WARN, INFO
from ..i18n import t

# ═══════════════════════════════════════════════════════════════════════════════
# Risk categories (MCP 14 categories)
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
    suppress_if_auth_present: bool = False


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
    McpPattern(
        "DEPVL",
        HIGH,
        re.compile(
            r"(?:npm|pnpm|yarn|pip|uv|poetry)\s+install\b|pip\s+install\s+git\+https?://|(?:npx|uvx|pipx\s+run|npm\s+exec)\b",
            re.I,
        ),
        t("运行时拉取并执行依赖", "Runtime dependency fetch and execution"),
        t("源码中包含运行时安装或执行外部依赖的逻辑，存在供应链攻击面。", "Source code installs or executes external dependencies at runtime, creating supply-chain risk."),
        t("将依赖固定在构建阶段安装，并锁定版本来源。", "Install dependencies during build time and lock their versions and sources."),
    ),
    McpPattern(
        "RCE",
        HIGH,
        re.compile(
            r"(?:importlib\.import_module|__import__|require)\s*\([^)]*(?:req\.|params\.|args\.|input\.|body\.|tool_input|plugin|module)",
            re.I,
        ),
        t("用户输入控制动态模块加载", "User input controls dynamic module loading"),
        t("模块名/插件名可能由用户输入决定，可导致加载任意代码。", "Module or plugin name may be controlled by user input, enabling arbitrary code loading."),
        t("仅允许从固定白名单中加载模块或插件。", "Only load modules or plugins from a fixed allowlist."),
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
    McpPattern(
        "SSRF",
        HIGH,
        re.compile(
            # Cloud instance-metadata endpoints (AWS / GCP / Azure / OCI / Alibaba)
            r"\b(?:"
            r"169\.254\.169\.254"
            r"|metadata\.google\.internal"
            r"|metadata\.azure\.com"
            r"|169\.254\.169\.123"
            r"|metadata\.aliyun(?:cs)?\.com"
            r"|metadata\.tencentyun\.com"
            r"|100\.100\.100\.200"
            r")\b",
            re.I,
        ),
        t("引用云元数据服务端点", "Cloud metadata endpoint referenced"),
        t("代码直接引用云实例元数据端点。若与用户可控 URL 组合，SSRF 可窃取实例临时凭证。", "Code references a cloud instance-metadata endpoint. Combined with user-controlled URLs this is exploitable via SSRF to steal instance credentials."),
        t("在网络层封禁元数据端点；如必须访问，使用 IMDSv2 + 强制 hop-limit。", "Block metadata endpoints at the network layer; if required, use IMDSv2 + enforced hop-limit."),
    ),
    McpPattern(
        "SSRF",
        HIGH,
        re.compile(
            # Loopback / private-net encoded in non-canonical forms used to slip past blacklists.
            r"(?:"
            r"\b127\.(?:0\.0\.)?1\b(?!\.\d)"          # 127.1 short form
            r"|\b0177\.(?:[0-9]+\.){2,3}[0-9]+\b"     # 0177.0.0.1 octal
            r"|\b0x7[fF](?:\.[0-9a-fA-F]+){0,3}\b"    # 0x7f.0.0.1 hex
            r"|\b2130706433\b"                         # 127.0.0.1 as 32-bit int
            r"|\[::1\]"                                # IPv6 loopback
            r"|\[::ffff:127\.0\.0\.1\]"                # IPv4-mapped IPv6 loopback
            r"|\[fe80::"                               # IPv6 link-local
            r")",
        ),
        t("可疑 IP 编码（疑似 SSRF 绕过）", "Suspicious IP encoding (suspected SSRF bypass)"),
        t("出现非标准形式的回环/内网/链路本地 IP 编码——绕过 SSRF 黑名单的典型手法。", "Non-canonical loopback / private-net / link-local IP encoding detected — a typical SSRF allowlist-bypass technique."),
        t("用 ipaddress.ip_address() 等解析后做地址族判断，禁止字符串黑名单。", "Use ipaddress.ip_address() (or equivalent) and reason about address family — never rely on string blacklists."),
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
        suppress_if_auth_present=True,
    ),
    McpPattern(
        "AUTHZ",
        HIGH,
        re.compile(
            r'(?:app\.(?:get|post|all)|router\.(?:get|post|use))\s*\(\s*["\']/(?:tools?|invoke|call)(?:/[^"\']*)?["\']\s*,\s*(?:async\s+)?\(?\s*(?:req|ctx)\b',
            re.I,
        ),
        t("公开暴露 MCP 工具调用路由", "Publicly exposed MCP tool invocation route"),
        t("检测到 /tools、/invoke 或 /call 等工具调用路由直接对外暴露。", "Detected a public /tools, /invoke, or /call style route exposed directly."),
        t("仅在经过鉴权后暴露工具调用路由。", "Expose tool invocation routes only after authentication and authorization."),
        suppress_if_auth_present=True,
    ),
    # ── Prompt Injection Surface ──
    McpPattern(
        "PRMTI",
        HIGH,
        re.compile(
            r'(?:description|tool_description|inputSchema)\s*[:=]\s*(?:'
            r'(?:[rRbB]{0,2}f|f[rRbB]{0,2})["\']'   # Python f-string (also rf"", fr"", bf"" prefixes)
            r"|`[^`]*\$\{"                            # JS template literal with ${...}
            r'|["\'][^"\']*["\']\s*\+\s*\w'           # string + variable concatenation
            r")",
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
    McpPattern(
        "PRMTI",
        HIGH,
        re.compile(
            r"(?:prompt|system_prompt|system_message|instructions?|description)\s*[:=]\s*[^;\n]*(?:tool_output|stdout|response(?:\.text)?|result(?:\.content)?)",
            re.I,
        ),
        t("工具输出直接拼入提示词或描述", "Tool output fed directly into prompts or descriptions"),
        t("将工具输出直接拼接到提示词或描述中，存在间接提示词注入风险。", "Tool output is concatenated directly into prompts or descriptions, creating indirect prompt injection risk."),
        t("对工具输出做净化，并与系统提示词严格隔离。", "Sanitize tool output and keep it isolated from system prompts."),
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
    McpPattern(
        "TOOLP",
        CRIT,
        re.compile(
            # description = "...invisible-char..." — zero-width, bidi, BOM, tag chars.
            # \U000E0000-\U000E007F is the Tag block (often used for AI poisoning).
            r"(?:description|tool_description)\s*[:=]\s*[\"'][^\"']*"
            r"[​-‏‪-‮⁠-⁯﻿\U000E0020-\U000E007F]"
            r"[^\"']*[\"']",
        ),
        t("工具描述含零宽 / 不可见字符", "Tool description contains zero-width / invisible characters"),
        t("description 字面量中嵌入了零宽空格、双向控制字符、BOM 或 Tag 块字符。这些在 UI 中不可见，但 LLM 会读取——是已知的 MCP 工具投毒载体（OWASP ASI-03 / 13）。", "Description literal embeds zero-width spaces, bidi controls, BOM, or Tag-block characters. Invisible in UIs but read by the LLM — a known MCP tool-poisoning vector (OWASP ASI-03 / 13)."),
        t("从描述中删除所有 Cf/Mn 类 Unicode 字符；只保留可打印字符。", "Strip every Cf/Mn-class Unicode codepoint from the description; keep only printable characters."),
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
        HIGH,
        re.compile(
            r'Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\']|Access-Control-Allow-Credentials\s*[:=]\s*true',
            re.I,
        ),
        t("响应头显式放宽跨域访问", "Response headers explicitly relax cross-origin access"),
        t("源码中显式设置了宽松的 CORS 响应头，可能允许跨站工具调用。", "Source code explicitly sets permissive CORS response headers, potentially allowing cross-site tool invocation."),
        t("限制允许的来源，并避免在通配符下允许凭证。", "Restrict allowed origins and avoid allowing credentials with wildcard origins."),
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
    # Generic HTTP-ish names
    "request", "req", "params", "args", "input", "body", "query",
    "arguments", "kwargs", "data",
    # MCP / agent-framework conventions
    "tool_input", "tool_use_block", "tool_args", "tool_call",
    "ctx", "context",
    # Webhooks / messaging
    "payload", "event", "msg", "message",
    "update",  # Telegram-bot convention
    "webhook_payload", "envelope",
}

# Primitive type names — when a parameter's annotation root is one of these,
# the parameter is NOT treated as an implicit taint source.
_PRIMITIVE_TYPE_NAMES = {
    "str", "int", "float", "bool", "bytes", "None", "Any",
    "List", "Dict", "Set", "Tuple", "Optional", "Union", "Literal", "Iterable",
    "list", "dict", "set", "tuple", "frozenset",
}

# FastAPI / Starlette / similar request-source markers. When used as the default
# value of a function parameter, the parameter is fed from the HTTP request and
# is therefore tainted.
_REQUEST_PARAM_MARKERS = {
    "Body", "Query", "Path", "Header", "Form", "File", "Cookie", "Depends",
}

# Functions whose return value is considered safe even when applied to tainted
# input. Calls to these short-circuit taint propagation.
_SANITIZERS = {
    # Shell escaping
    "shlex.quote", "shlex.split", "shlex.join",
    "pipes.quote", "subprocess.list2cmdline",
    # Regex / HTML / URL escaping
    "re.escape", "html.escape", "html.unescape",
    "urllib.parse.quote", "urllib.parse.quote_plus", "urllib.parse.urlencode",
    # Path normalization (callers still need a containment check, but the
    # normalized result alone is not the threat).
    "os.path.realpath", "os.path.abspath", "os.path.normpath",
    # Type coercion — discards anything that isn't the requested type.
    "int", "float", "bool",
    "uuid.UUID", "ipaddress.ip_address", "ipaddress.IPv4Address",
}

# Method-name suffixes that, when invoked, untaint the result. Covers patterns
# like ``Path(x).resolve()`` and ``re.compile(p).escape(x)`` without needing
# the full dotted name.
_SANITIZER_METHOD_SUFFIXES = (
    ".resolve", ".escape", ".quote", ".quote_plus",
)

_DANGEROUS_SINKS = {
    "os.system": ("CMDI", CRIT),
    "subprocess.run": ("CMDI", HIGH),
    "subprocess.call": ("CMDI", HIGH),
    "subprocess.Popen": ("CMDI", HIGH),
    "subprocess.check_output": ("CMDI", HIGH),
    "subprocess.check_call": ("CMDI", HIGH),
    "eval": ("RCE", CRIT),
    "exec": ("RCE", CRIT),
    "importlib.import_module": ("RCE", HIGH),
    "__import__": ("RCE", HIGH),
    "open": ("LFI", HIGH),
    "Path": ("LFI", WARN),
    "pickle.loads": ("DESER", HIGH),
    "yaml.load": ("DESER", HIGH),
    "yaml.unsafe_load": ("DESER", CRIT),
    "marshal.loads": ("DESER", HIGH),
    # SQL raw execution variants (parameterised execute() is fine; the
    # f-string check in regex patterns covers the formatted-SQL case).
    "cursor.executescript": ("SQLI", HIGH),
}


def _annotation_root_name(annot: Optional[ast.AST]) -> str:
    """Return the outermost name of a parameter annotation, ignoring subscripts
    and attribute access. ``ToolArgs`` → ``ToolArgs``;
    ``Optional[ToolArgs]`` → ``Optional``; ``models.ToolArgs`` → ``ToolArgs``."""
    if annot is None:
        return ""
    if isinstance(annot, ast.Name):
        return annot.id
    if isinstance(annot, ast.Subscript):
        return _annotation_root_name(annot.value)
    if isinstance(annot, ast.Attribute):
        return annot.attr
    return ""


def _is_tainted_param(arg: ast.arg, default: Optional[ast.expr]) -> bool:
    """Return True if a function parameter should be considered an implicit
    user-controlled (tainted) source.

    The parameter is tainted when ANY of the following hold:
      * its name is a known taint source (``request``, ``payload``, ...);
      * the default is a FastAPI / Starlette request-source marker call
        (``Body(...)``, ``Query(...)``, ``Depends(get_user)``, ...);
      * the annotation root is a custom class — i.e. NOT a primitive type —
        which strongly suggests a Pydantic / dataclass model carrying the
        request payload.
    """
    if arg.arg in _TAINT_SOURCES:
        return True
    if isinstance(default, ast.Call):
        marker = _annotation_root_name(default.func) or ""
        if not marker and isinstance(default.func, ast.Name):
            marker = default.func.id
        if marker in _REQUEST_PARAM_MARKERS:
            return True
    type_root = _annotation_root_name(arg.annotation)
    if (
        type_root
        and type_root not in _PRIMITIVE_TYPE_NAMES
        and type_root[0].isupper()
    ):
        return True
    return False


def _is_sanitizer_call(node: ast.AST) -> bool:
    """Return True if ``node`` is a call whose return value is considered safe."""
    if not isinstance(node, ast.Call):
        return False
    name = _get_call_name(node)
    if name in _SANITIZERS:
        return True
    return any(name.endswith(suffix) for suffix in _SANITIZER_METHOD_SUFFIXES)


def _node_references_taint(node: ast.AST, tainted: set) -> bool:
    """Check if an AST node's *value* should be considered tainted.

    Sanitizer calls short-circuit propagation: ``shlex.quote(tainted)`` is
    treated as untainted regardless of its argument.
    """
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
        if _is_sanitizer_call(node):
            return False
        return any(_node_references_taint(a, tainted) for a in node.args)
    return False


def _expr_uses_name(node: ast.AST, name: str) -> bool:
    """Return True if ``node`` references the identifier ``name`` anywhere."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id == name:
            return True
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


def _function_initial_taints(
    func: ast.AST,
) -> Tuple[set, Dict[str, int]]:
    """Compute the initial set of tainted parameter names for one function,
    plus a mapping of each tainted positional parameter to its 0-based index.
    """
    tainted: set = set()
    name_to_idx: Dict[str, int] = {}
    args_list = list(func.args.args)
    defaults = list(func.args.defaults)
    offset = len(args_list) - len(defaults)
    for i, arg in enumerate(args_list):
        default = defaults[i - offset] if i >= offset else None
        if _is_tainted_param(arg, default):
            tainted.add(arg.arg)
            name_to_idx[arg.arg] = i
    for j, arg in enumerate(func.args.kwonlyargs):
        kw_default = func.args.kw_defaults[j] if j < len(func.args.kw_defaults) else None
        if _is_tainted_param(arg, kw_default):
            tainted.add(arg.arg)
    return tainted, name_to_idx


def _function_all_params(func: ast.AST) -> Dict[str, int]:
    """Map every positional parameter name to its 0-based index. Used for
    wrapper-sink discovery (where ANY param flowing to a sink makes the
    function dangerous, regardless of whether its name looks tainted)."""
    return {arg.arg: i for i, arg in enumerate(func.args.args)}


def _contributors_in(node: ast.AST, provenance: Dict[str, set]) -> set:
    """Return the set of original parameter names whose taint propagates into
    *node*. Honours sanitizer-call short-circuiting (mirrors the value-level
    truthiness logic in ``_node_references_taint``)."""
    if isinstance(node, ast.Call):
        if _is_sanitizer_call(node):
            return set()
        result: set = set()
        for arg in node.args:
            result.update(_contributors_in(arg, provenance))
        return result
    if isinstance(node, ast.Name):
        return set(provenance.get(node.id, ()))
    if isinstance(node, ast.Attribute):
        return _contributors_in(node.value, provenance)
    if isinstance(node, ast.Subscript):
        return _contributors_in(node.value, provenance)
    if isinstance(node, ast.BinOp):
        return _contributors_in(node.left, provenance) | _contributors_in(
            node.right, provenance
        )
    if isinstance(node, ast.JoinedStr):
        result = set()
        for v in node.values:
            result.update(_contributors_in(v, provenance))
        return result
    if isinstance(node, ast.FormattedValue):
        return _contributors_in(node.value, provenance)
    return set()


def _build_provenance(func: ast.AST, all_params: Dict[str, int]) -> Dict[str, set]:
    """Walk a function body in source order, building a map from each local
    variable to the set of parameter names whose taint flows into it.

    ``def foo(a, b): x = a + 1; y = x.upper()`` produces
    ``{'a': {'a'}, 'b': {'b'}, 'x': {'a'}, 'y': {'a'}}``.
    """
    provenance: Dict[str, set] = {name: {name} for name in all_params}

    def _walk(stmts):
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                contributors = _contributors_in(stmt.value, provenance)
                if contributors:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            provenance[target.id] = contributors
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name):
                    contributors = _contributors_in(stmt.value, provenance)
                    if contributors:
                        provenance.setdefault(stmt.target.id, set()).update(contributors)
            elif isinstance(stmt, ast.AnnAssign):
                if (
                    isinstance(stmt.target, ast.Name)
                    and stmt.value is not None
                ):
                    contributors = _contributors_in(stmt.value, provenance)
                    if contributors:
                        provenance[stmt.target.id] = contributors
            # Recurse into nested blocks, but skip nested function defs so
            # their parameter scopes don't leak.
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for attr in ("body", "orelse", "finalbody"):
                sub = getattr(stmt, attr, None)
                if isinstance(sub, list):
                    _walk(sub)
            if isinstance(stmt, ast.Try):
                for handler in stmt.handlers:
                    _walk(handler.body)

    _walk(func.body)
    return provenance


def _ast_analyze_python(source: str, filepath: str) -> List[Finding]:
    """AST-based taint analysis for Python MCP server code.

    Implements per-function scoping, sanitizer recognition (so properly
    escaped flows don't trigger), Pydantic / FastAPI parameter-source
    detection, and one-level intra-file inter-procedural propagation: a
    function that passes a parameter into a dangerous sink is registered
    as a "wrapper sink" so call sites that pass tainted data to it also
    fire.
    """
    findings: List[Finding] = []
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return findings

    all_funcs: List[ast.AST] = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    # Module-level tainted vars seed: explicit names plus anything assigned
    # from a known source at module scope.
    tainted_vars: set = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and _node_references_taint(node.value, tainted_vars):
                    tainted_vars.add(target.id)

    # Pass 1: per-function taint analysis. We track two related but distinct
    # things:
    #
    #   * ``func_locals[func]`` — the set of variables tainted by an *entry*
    #     source (heuristic-matched param names, Pydantic types, FastAPI
    #     markers, ...) plus assignment-propagation from those. Used to emit
    #     direct findings in Pass 2.
    #
    #   * ``wrapper_sinks`` — for any function, which positional parameters
    #     (whether or not they're heuristically tainted) flow into a dangerous
    #     sink. A function that satisfies this becomes a wrapper sink for
    #     callers — i.e. ``def execute(cmd): os.system(cmd)`` makes any
    #     caller passing tainted data on position 0 dangerous, regardless of
    #     whether ``cmd`` matches a taint-source name pattern.
    wrapper_sinks: Dict[str, Dict[int, Tuple[str, str]]] = {}
    func_locals: Dict[ast.AST, set] = {}

    for func in all_funcs:
        entry_tainted, _entry_idx = _function_initial_taints(func)
        all_params = _function_all_params(func)
        provenance = _build_provenance(func, all_params)

        # Entry-source taint propagation (for finding emission). Run
        # alongside provenance — both rely on assignment order, but entry
        # taint may include names from outside the param set.
        entry_local = set(entry_tainted) | set(tainted_vars)
        for node in ast.walk(func):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node is not func
            ):
                continue
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _node_references_taint(
                        node.value, entry_local
                    ):
                        entry_local.add(target.id)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and _node_references_taint(
                    node.value, entry_local
                ):
                    entry_local.add(node.target.id)
        func_locals[func] = entry_local

        # Wrapper-sink discovery: scan for sinks, attribute back to the
        # original parameters via provenance.
        for node in ast.walk(func):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node is not func
            ):
                continue
            if isinstance(node, ast.Call):
                call_name = _get_call_name(node)
                cat_level = _DANGEROUS_SINKS.get(call_name)
                if not cat_level:
                    continue
                for arg_node in node.args:
                    contributors = _contributors_in(arg_node, provenance)
                    for pname in contributors:
                        pidx = all_params.get(pname)
                        if pidx is not None:
                            wrapper_sinks.setdefault(func.name, {})[pidx] = cat_level

    def _emit(level, cat, title, detail, node, remediation):
        findings.append(
            Finding(
                scanner="mcp_deep",
                level=level,
                title=f"[{cat}] {title}",
                detail=detail,
                location=f"{filepath}:{getattr(node, 'lineno', '?')}",
                remediation=remediation,
            )
        )

    # Pass 2: at every call site (anywhere in the module), flag direct sinks
    # and wrapper sinks that receive tainted data. We use each function's
    # local taint set so we don't leak cross-function taint.
    def _taints_at(call_node: ast.Call) -> set:
        for func, local in func_locals.items():
            if any(call_node is c for c in ast.walk(func)):
                return local
        return tainted_vars

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _get_call_name(node)
        active_tainted = _taints_at(node)

        # Direct dangerous sink
        if call_name in _DANGEROUS_SINKS:
            cat, level = _DANGEROUS_SINKS[call_name]
            for arg_node in node.args:
                if _node_references_taint(arg_node, active_tainted):
                    _emit(
                        level,
                        cat,
                        t(f"污点数据流入 {call_name}()", f"Tainted data flows into {call_name}()"),
                        t(
                            f"用户输入经数据流分析可达 {call_name}()，存在 {RISK_CATEGORIES.get(cat, cat)} 风险。",
                            f"User input reaches {call_name}() via data-flow analysis, posing {RISK_CATEGORIES.get(cat, cat)} risk.",
                        ),
                        node,
                        t(
                            f"在调用 {call_name}() 前对输入做净化/白名单校验。",
                            f"Sanitize/whitelist-validate input before calling {call_name}().",
                        ),
                    )
                    break

        # Wrapper sink (function defined in this file that passes its arg to a sink)
        if call_name in wrapper_sinks:
            for arg_idx, arg_node in enumerate(node.args):
                if arg_idx not in wrapper_sinks[call_name]:
                    continue
                if not _node_references_taint(arg_node, active_tainted):
                    continue
                cat, level = wrapper_sinks[call_name][arg_idx]
                _emit(
                    level,
                    cat,
                    t(
                        f"污点数据经包装函数 {call_name}() 流入 {cat} sink",
                        f"Tainted data flows through wrapper {call_name}() into {cat} sink",
                    ),
                    t(
                        f"调用 {call_name}() 时传入的污点参数会被该函数内部的危险调用消费。",
                        f"The tainted argument passed to {call_name}() is consumed by a dangerous call inside that function.",
                    ),
                    node,
                    t(
                        f"在 {call_name}() 内部或调用前完成输入净化/白名单校验。",
                        f"Sanitize/whitelist-validate input inside {call_name}() or before calling it.",
                    ),
                )
                break

    # @tool decorator with dynamic description (unchanged behavior)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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


# ═══════════════════════════════════════════════════════════════════════════════
# JS/TS taint analysis — file-local destructuring + aliased request inputs
#
# The universal regex patterns above only fire when a sink call literally
# contains substrings like ``req.`` or ``body.``. Modern Express/Koa/Anthropic
# SDK code routinely separates the binding from the use:
#
#     const { cmd } = req.body;
#     exec(cmd);              // ← would be missed by raw-regex patterns
#
# This pre-scan extracts names bound from a request-like source and looks for
# sinks that consume them. Lightweight (regex only) so we keep the
# "no tree-sitter dependency" property of the engine.
# ═══════════════════════════════════════════════════════════════════════════════
_JS_REQUEST_SOURCES = (
    r"req|request|ctx|context|event|payload|message|update"
    r"|tool_input|tool_use|webhook|envelope"
)
_JS_DESTRUCTURE_RE = re.compile(
    r"(?:const|let|var)\s*\{\s*([^}]+?)\s*\}\s*=\s*"
    r"(?:[\w.]+\.)?(?:" + _JS_REQUEST_SOURCES + r"|body|params|query|args)\b",
    re.I,
)
_JS_REQ_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:[\w.]+\.)?(?:" + _JS_REQUEST_SOURCES + r")(?:\.[\w$.]+)?\s*[;\n]",
    re.I,
)

_JS_TAINT_SINKS = (
    (
        r"\b(?:child_process\.)?(?:exec(?:Sync)?|spawn(?:Sync)?|execFile(?:Sync)?)\s*\("
        r"[^)]*\b(?:NAMES)\b",
        "CMDI",
        CRIT,
        t("解构出的用户输入流入命令执行", "Destructured user input flows into command execution"),
    ),
    (
        r"\b(?:eval|Function)\s*\([^)]*\b(?:NAMES)\b",
        "RCE",
        CRIT,
        t("解构出的用户输入传入 eval/Function", "Destructured user input passed to eval/Function"),
    ),
    (
        r"\b(?:fs\.)?(?:readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|createWriteStream)\s*\("
        r"[^)]*\b(?:NAMES)\b",
        "LFI",
        HIGH,
        t("解构出的用户输入控制文件读写路径", "Destructured user input controls file path"),
    ),
    (
        r"\b(?:fetch|axios\.(?:get|post|put|delete|request)|http(?:s)?\.(?:get|request))\s*\("
        r"[^)]*\b(?:NAMES)\b",
        "SSRF",
        HIGH,
        t("解构出的用户输入控制 HTTP 请求目标", "Destructured user input controls HTTP request target"),
    ),
)


def _scan_js_destructured_taint(content: str, rel: str) -> List[Finding]:
    """Catch sinks that consume request data through a local binding,
    e.g. ``const { cmd } = req.body; exec(cmd)``."""
    findings: List[Finding] = []
    tainted: set = set()

    for m in _JS_DESTRUCTURE_RE.finditer(content):
        for raw in m.group(1).split(","):
            piece = raw.strip()
            if not piece:
                continue
            # Strip rest spread (``...rest`` → ``rest``).
            piece = piece.lstrip(". ").strip()
            # In ``name: alias`` syntax the alias (right side) is the real
            # local binding. Default values (``name = 0``) follow it.
            if ":" in piece:
                piece = piece.split(":", 1)[1]
            piece = piece.split("=", 1)[0].strip()
            if piece and re.fullmatch(r"[A-Za-z_$][\w$]*", piece):
                tainted.add(piece)

    for m in _JS_REQ_ASSIGN_RE.finditer(content):
        tainted.add(m.group(1))

    if not tainted:
        return findings

    names_alt = "|".join(re.escape(n) for n in tainted)
    for sink_template, cat, level, title in _JS_TAINT_SINKS:
        sink_re = re.compile(sink_template.replace("NAMES", names_alt), re.I)
        for match in sink_re.finditer(content):
            lineno = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    scanner="mcp_deep",
                    level=level,
                    title=f"[{cat}] {title}",
                    detail=t(
                        f"通过解构/赋值得到的字段进入危险调用，构成 {RISK_CATEGORIES.get(cat, cat)} 风险。",
                        f"A field obtained via destructuring/assignment reaches a dangerous call, creating {RISK_CATEGORIES.get(cat, cat)} risk.",
                    ),
                    location=f"{rel}:{lineno}",
                    snippet=match.group(0)[:80].strip(),
                    remediation=t(
                        "对来自请求对象的字段做白名单 / 类型 / schema 校验后再使用。",
                        "Validate request-derived fields with an allowlist / type / schema before use.",
                    ),
                    metadata={"category": cat, "source": "js_destructure"},
                )
            )
    return findings


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

# Per-file auth-middleware indicators. If any of these match, we suppress
# AUTHZ patterns flagged with ``suppress_if_auth_present=True`` for that file,
# because the file demonstrably has *some* form of authentication wiring and
# the per-route negative lookahead approach is too brittle to assert otherwise.
_AUTH_INDICATORS = re.compile(
    r"(?i)("
    r"app\.use\s*\([^)]*(?:auth|passport|verify|jwt|session|require[A-Z]?[a-z]*(?:Auth|User|Login))"
    r"|passport\.authenticate\s*\("
    r"|verify(?:Token|Auth|JWT|Signature)\s*\("
    r"|require(?:Auth|User|Login)\s*\("
    r"|express(?:-|_)jwt|jwt-?middleware"
    r"|fastapi[.]security|Depends\s*\([^)]*(?:auth|verify|current_user|get_user)"
    r"|@(?:login_required|permission_required|auth_required|requires_auth|authenticated|protected)\b"
    r"|HTTPBearer\s*\(|OAuth2PasswordBearer\s*\("
    r"|@app\.middleware\s*\([\"']http[\"']\s*\)"
    r")"
)


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
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        files_scanned += 1
        rel = str(fp.relative_to(code_path)) if code_path.is_dir() else fp.name
        has_auth_middleware = bool(_AUTH_INDICATORS.search(content))

        # 1) Universal regex patterns
        for pat in _MCP_PATTERNS:
            if pat.suppress_if_auth_present and has_auth_middleware:
                continue
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

        # 3) JS/TS extra MCP patterns + destructuring taint
        if fp.suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            findings.extend(_scan_js_destructured_taint(content, rel))
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


# ═══════════════════════════════════════════════════════════════════════════════
# Hallucinated package / slopsquat detection
#
# AI-generated code routinely fabricates plausible-sounding package names that
# do not actually exist on the public registry. Attackers monitor for these
# names and squat them with malicious payloads. We detect by querying the
# registry for every declared dependency and flagging anything that returns
# 404. Results are cached for 24 h so repeat scans of the same project don't
# pound the registry.
# ═══════════════════════════════════════════════════════════════════════════════
_PACKAGE_CACHE_FILE = Path.home() / ".clawlock" / "cache" / "packages.json"
_PACKAGE_CACHE_TTL_SECONDS = 24 * 60 * 60
_PACKAGE_PROBE_TIMEOUT = 4.0
_PACKAGE_CHECK_DISABLED_ENV = "CLAWLOCK_NO_PKG_CHECK"


def _load_package_cache() -> Dict[str, Dict]:
    try:
        if _PACKAGE_CACHE_FILE.exists():
            return json.loads(_PACKAGE_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_package_cache(cache: Dict[str, Dict]) -> None:
    try:
        _PACKAGE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _PACKAGE_CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass


def _probe_package(ecosystem: str, name: str) -> Optional[bool]:
    """Return True if the package exists, False if confirmed missing, None on
    network failure / timeout (caller should treat as unknown, not fail)."""
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{name}"
    elif ecosystem == "pypi":
        url = f"https://pypi.org/pypi/{name}/json"
    else:
        return None
    try:
        import httpx  # lazy: keep clawlock importable when offline-first
        resp = httpx.get(
            url,
            timeout=_PACKAGE_PROBE_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "clawlock-pkg-check"},
        )
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        return None
    except Exception:
        return None


def check_package_exists(
    ecosystem: str, name: str, *, cache: Optional[Dict[str, Dict]] = None
) -> Optional[bool]:
    """Cached registry existence probe. Returns True / False / None (unknown)."""
    if os.environ.get(_PACKAGE_CHECK_DISABLED_ENV):
        return None
    cache_key = f"{ecosystem}:{name}"
    cache_obj = cache if cache is not None else _load_package_cache()
    entry = cache_obj.get(cache_key)
    now = time.time()
    if entry and now - entry.get("checked_at", 0) < _PACKAGE_CACHE_TTL_SECONDS:
        return entry.get("exists")
    result = _probe_package(ecosystem, name)
    if result is not None:
        cache_obj[cache_key] = {"exists": result, "checked_at": now}
        if cache is None:
            _save_package_cache(cache_obj)
    return result


def _parse_requirements_txt(text: str) -> List[str]:
    names: List[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # Strip extras "[foo]" and version specifiers
        name = re.split(r"[\[<>=!~;\s]", line, maxsplit=1)[0]
        if name:
            names.append(name.lower())
    return names


def _check_hallucinated_packages(
    pkg_specs: List[Tuple[str, str, str, Path]],
) -> List[Finding]:
    """``pkg_specs`` is a list of ``(ecosystem, name, version_or_blank, source_path)``."""
    findings: List[Finding] = []
    if not pkg_specs:
        return findings
    cache = _load_package_cache()
    for ecosystem, name, version, source in pkg_specs:
        # Local / git / file deps cannot be probed against the registry.
        if any(s in version for s in ("file:", "link:", "git+", "github:")):
            continue
        exists = check_package_exists(ecosystem, name, cache=cache)
        if exists is False:
            findings.append(
                Finding(
                    scanner="depscan",
                    level=HIGH,
                    title="[SUPPLY_CHAIN] " + t(
                        f"依赖在 {ecosystem} 注册表中不存在：{name}",
                        f"Dependency not found on {ecosystem} registry: {name}",
                    ),
                    detail=t(
                        f"{ecosystem} 注册表对 {name} 返回 404。AI 生成代码常虚构包名，攻击者会抢注成恶意包（slopsquatting）。",
                        f"{ecosystem} registry returned 404 for {name}. AI-generated code often hallucinates packages and attackers squat them with malicious payloads (slopsquatting).",
                    ),
                    location=str(source),
                    snippet=f"{name}{(' @ ' + version) if version else ''}",
                    remediation=t(
                        "立即移除该依赖；核实真实包名后再添加。",
                        "Remove the dependency immediately; verify the correct name before adding it back.",
                    ),
                    metadata={"category": "SUPPLY_CHAIN", "ecosystem": ecosystem, "package": name},
                )
            )
    _save_package_cache(cache)
    return findings


def scan_package_manifest_risks(code_path: Path, *, check_existence: bool = True) -> List[Finding]:
    """Check package.json / requirements.txt for risky deps, known CVEs, and
    hallucinated package names. Set ``check_existence=False`` to skip the
    network-backed registry probe."""
    findings = []
    pkg_files = _package_json_candidates(code_path)
    pkg_specs: List[Tuple[str, str, str, Path]] = []

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
            pkg_specs.append(("npm", pkg_name, str(version_spec), pkg_file))
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

    # Also collect Python deps from requirements*.txt files for the
    # hallucinated-package probe.
    if code_path.is_dir():
        for req_file in code_path.rglob("requirements*.txt"):
            if "node_modules" in str(req_file) or ".git" in str(req_file):
                continue
            try:
                names = _parse_requirements_txt(req_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            for n in names:
                pkg_specs.append(("pypi", n, "", req_file))

    if check_existence:
        findings.extend(_check_hallucinated_packages(pkg_specs))
    return findings
