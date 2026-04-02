"""
ClawLock v1.2.1 core scanners — Finding model, config audit, skill supply-chain (55+ patterns),
SOUL.md + memory file drift, MCP exposure + 6 tool poisoning patterns, process detection,
credential directory audit, installation discovery, risky env vars, skill precheck.
"""

from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from ..adapters import AdapterSpec, load_config, run_cmd

CRIT = "critical"
HIGH = "high"
WARN = "medium"
INFO = "info"
LEVEL_EMOJI = {CRIT: "HIGH", HIGH: "HIGH", WARN: "WARN", INFO: "INFO"}
LEVEL_LABEL_CN = {CRIT: "高危", HIGH: "高危", WARN: "需关注", INFO: "提示"}


@dataclass
class Finding:
    scanner: str
    level: str
    title: str
    detail: str
    location: str = ""
    snippet: str = ""
    remediation: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def is_critical(self) -> bool:
        return self.level in (CRIT, HIGH)

    @property
    def emoji(self) -> str:
        return LEVEL_EMOJI.get(self.level, "•")

    @property
    def label_cn(self) -> str:
        return LEVEL_LABEL_CN.get(self.level, self.level)


_CONFIG_RULES: Dict[str, List[tuple]] = {
    "openclaw": [
        (
            "gatewayAuth",
            lambda v: not v,
            CRIT,
            "Gateway 鉴权未开启",
            "任何能访问端口的人可直接连接 agent。",
            "设置 gatewayAuth: true 并配置 token。",
        ),
        (
            "allowedDirectories",
            lambda v: isinstance(v, list) and "/" in v,
            WARN,
            "文件访问范围包含根目录",
            "skill 可读写系统任意文件。",
            "收紧到项目目录。",
        ),
        (
            "enableBrowserControl",
            lambda v: v is True,
            WARN,
            "已开启浏览器控制权限",
            "agent 可控制本地浏览器会话。",
            "设置 enableBrowserControl: false。",
        ),
        (
            "allowNetworkAccess",
            lambda v: v is True,
            WARN,
            "网络访问未配置白名单",
            "skill 可向任意地址发起请求。",
            "配置 allowedNetworkDomains 白名单。",
        ),
        (
            "sessionRetentionDays",
            lambda v: isinstance(v, int) and v > 30,
            INFO,
            "会话日志保留时间过长",
            "超过 30 天。",
            "设置 sessionRetentionDays: 7。",
        ),
    ],
    "zeroclaw": [
        (
            "auth.enabled",
            lambda v: not v,
            CRIT,
            "ZeroClaw 鉴权未开启",
            "服务端口未设置认证。",
            "启用 auth.enabled: true。",
        ),
        (
            "filesystem.allowedPaths",
            lambda v: isinstance(v, list) and any((p in ("/", "~") for p in v)),
            WARN,
            "文件访问范围过宽",
            "allowedPaths 包含根路径。",
            "限制到项目路径。",
        ),
    ],
    "claude-code": [
        (
            "permissions.allow",
            lambda v: isinstance(v, list) and any(("**" in str(p) for p in v)),
            WARN,
            "权限使用通配符 **",
            "settings.json 中存在 ** 通配符。",
            "替换为具体路径。",
        )
    ],
    "_common": [
        (
            "server.host",
            lambda v: v in ("0.0.0.0", "::", "*"),
            HIGH,
            "服务绑定到所有网络接口",
            "外部网络可能直接访问。",
            "绑定到 127.0.0.1。",
        ),
        (
            "tls.enabled",
            lambda v: v in (False, "disabled", None),
            WARN,
            "TLS/HTTPS 未启用",
            "通信未加密。",
            "启用 TLS。",
        ),
        (
            "approvalMode",
            lambda v: v in (False, "none", "disabled", None),
            WARN,
            "操作审批未启用",
            "高危操作无需确认。",
            "启用审批模式。",
        ),
        (
            "rateLimit.enabled",
            lambda v: v in (False, None, "disabled"),
            WARN,
            "未配置速率限制",
            "可被暴力破解或滥用，可能导致 API 额度耗尽。",
            "为 Gateway 配置请求速率限制。",
        ),
    ],
}
SECRET_PATTERNS = [
    ("sk-[A-Za-z0-9]{20,}", "OpenAI API Key"),
    ("ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    ("xoxb-[0-9]{10,}", "Slack Token"),
    ("AKIA[0-9A-Z]{16}", "AWS Key"),
    ("-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key"),
    ("sk-ant-[A-Za-z0-9\\-]{20,}", "Anthropic API Key"),
]
RISKY_ENV_VARS = [
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "LD_LIBRARY_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
    "NODE_PATH",
    "ELECTRON_RUN_AS_NODE",
    "BROWSER",
]


def _get_nested(d: dict, dotpath: str):
    cur = d
    for p in dotpath.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _check_secrets(obj: Any, path: str) -> List[Finding]:
    findings = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            findings.extend(_check_secrets(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            findings.extend(_check_secrets(item, f"{path}[{i}]"))
    elif isinstance(obj, str):
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, obj):
                findings.append(
                    Finding(
                        "config",
                        CRIT,
                        f"配置中发现硬编码凭据: {label}",
                        f"在 {path} 中发现疑似 {label}。",
                        path,
                        remediation="移除硬编码凭据，改用环境变量。",
                    )
                )
                break
    return findings


def _check_risky_env(config: dict, cfg_path: str) -> List[Finding]:
    """v1.1: Check for dangerous env vars (NODE_OPTIONS, LD_PRELOAD etc.) in skill/MCP config."""
    findings = []

    def _walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.upper() in RISKY_ENV_VARS:
                    findings.append(
                        Finding(
                            "config",
                            HIGH,
                            f"发现危险环境变量: {k}",
                            f"配置项 {path}.{k} 可被利用注入恶意代码。",
                            f"{cfg_path}:{path}.{k}",
                            remediation=f"移除 {k} 或确认其值安全。",
                        )
                    )
                _walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(config, "config")
    return findings


def scan_config(adapter: AdapterSpec) -> Tuple[List[Finding], Optional[str]]:
    findings: List[Finding] = []
    config, cfg_path = load_config(adapter)
    if adapter.audit_cmd:
        code, out, err = run_cmd(adapter.audit_cmd)
        if code == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                sev = INFO
                for kw, lv in [
                    ("CRITICAL", CRIT),
                    ("HIGH", HIGH),
                    ("WARN", WARN),
                    ("ERROR", HIGH),
                ]:
                    if kw in line.upper():
                        sev = lv
                        break
                if sev != INFO or any(
                    (w in line.lower() for w in ("risk", "vuln", "exposed"))
                ):
                    findings.append(
                        Finding(
                            "config", sev, line[:120], line, cfg_path or "builtin-audit"
                        )
                    )
    for key, test_fn, level, title, detail, remediation in _CONFIG_RULES.get(
        adapter.name, []
    ) + _CONFIG_RULES.get("_common", []):
        val = _get_nested(config, key)
        if val is not None and test_fn(val):
            findings.append(
                Finding(
                    "config",
                    level,
                    title,
                    detail,
                    f"config:{key}",
                    remediation=remediation,
                )
            )
    findings.extend(_check_secrets(config, cfg_path or "config"))
    findings.extend(_check_risky_env(config, cfg_path or "config"))
    return (findings, cfg_path)


def scan_processes(adapter: AdapterSpec) -> List[Finding]:
    """Detect running Claw processes + exposed ports (cross-platform)."""
    from ..utils import list_processes, list_listening_ports

    findings = []
    for proc in list_processes():
        for proc_name in adapter.process_names or [adapter.bin or ""]:
            if (
                proc_name
                and proc_name in proc.get("cmd", "")
                and ("clawlock" not in proc.get("cmd", ""))
            ):
                findings.append(
                    Finding(
                        "process",
                        INFO,
                        f"检测到运行中的进程: {proc_name}",
                        f"PID {proc['pid']}, 用户 {proc.get('user', 'N/A')}",
                        f"ps:{proc['pid']}",
                    )
                )
                break
    for line in list_listening_ports():
        if any((p in line for p in ["18789", "18790", "3000", "8080"])):
            findings.append(
                Finding(
                    "process",
                    HIGH,
                    "发现对外监听的高危端口",
                    f"进程绑定 0.0.0.0: {line[:80]}",
                    remediation="将监听地址改为 127.0.0.1。",
                )
            )
    return findings


def discover_installations() -> List[Finding]:
    """Scan for all Claw product installations, configs, workspaces."""
    findings = []
    discovery_targets = {
        "OpenClaw": ["~/.openclaw", "~/.config/openclaw"],
        "ZeroClaw": ["~/.zeroclaw", "~/.config/zeroclaw"],
        "Claude Code": ["~/.claude", "~/.config/claude"],
    }
    found_any = False
    for product, paths in discovery_targets.items():
        for p in paths:
            d = Path(p).expanduser()
            if d.exists():
                found_any = True
                configs = list(d.glob("*.json")) + list(d.glob("*.yaml"))
                skills_dir = d / "skills"
                skill_count = (
                    len(list(skills_dir.iterdir())) if skills_dir.exists() else 0
                )
                sessions = d / "sessions"
                session_count = (
                    len(list(sessions.iterdir())) if sessions.exists() else 0
                )
                findings.append(
                    Finding(
                        "discovery",
                        INFO,
                        f"发现 {product} 安装: {d}",
                        f"配置文件 {len(configs)} 个, Skills {skill_count} 个, 会话 {session_count} 个",
                        str(d),
                    )
                )
    from ..utils import find_all_binaries

    bins = find_all_binaries(
        ["openclaw", "zeroclaw", "claude", "ai-infra-guard", "promptfoo", "npx"]
    )
    for name, path in bins.items():
        if path:
            findings.append(
                Finding("discovery", INFO, f"发现工具: {name}", f"路径: {path}")
            )
    if not found_any:
        findings.append(
            Finding(
                "discovery",
                INFO,
                "未发现已安装的 Claw 产品",
                "未在标准路径下找到安装目录。",
            )
        )
    return findings


def scan_credential_dirs(adapter: AdapterSpec) -> List[Finding]:
    """Audit credential directories and files for overly permissive access (cross-platform)."""
    from ..utils import check_file_permission, IS_WINDOWS

    findings = []
    fix_hint = "使用 icacls 移除 Everyone/Users 访问权限" if IS_WINDOWS else "chmod 700"
    fix_hint_f = "使用 icacls 限制为仅所有者访问" if IS_WINDOWS else "chmod 600"
    for cred_path_str in adapter.credential_dirs:
        cred_path = Path(cred_path_str).expanduser()
        if not cred_path.exists():
            continue
        try:
            world_r, group_r, desc = check_file_permission(cred_path)
            if world_r:
                findings.append(
                    Finding(
                        "credential",
                        HIGH,
                        f"凭证目录权限过宽: {cred_path.name}",
                        f"目录 {cred_path} 对所有用户可读 ({desc})。",
                        str(cred_path),
                        remediation=f"{fix_hint} {cred_path}",
                    )
                )
            elif group_r:
                findings.append(
                    Finding(
                        "credential",
                        WARN,
                        f"凭证目录对组用户可读: {cred_path.name}",
                        f"目录 {cred_path} 组可读 ({desc})。",
                        str(cred_path),
                        remediation=f"{fix_hint} {cred_path}",
                    )
                )
            if cred_path.is_dir():
                for f in cred_path.iterdir():
                    if f.is_file() and f.suffix in (
                        ".json",
                        ".key",
                        ".pem",
                        ".token",
                        ".env",
                    ):
                        fw, _, fd = check_file_permission(f)
                        if fw:
                            findings.append(
                                Finding(
                                    "credential",
                                    HIGH,
                                    f"凭证文件权限过宽: {f.name}",
                                    f"文件 {f} 对所有用户可读 ({fd})。",
                                    str(f),
                                    remediation=f"{fix_hint_f} {f}",
                                )
                            )
        except Exception:
            pass
    return findings


# ---------------------------------------------------------------------------
# Shell command deobfuscation — recursively unwrap nested shell invocations
# so that pattern matching works on the *actual* payload.
# ---------------------------------------------------------------------------

# Matches: sh -c "...", bash -c '...', /bin/sh -c "...", cmd /c "...", etc.
_SHELL_WRAP_RE = re.compile(
    r"""(?:(?:/usr)?(?:/bin/)?(?:ba)?sh|dash|zsh|ksh)\s+-c\s+"""  # Unix shells
    r"""|cmd(?:\.exe)?\s+/[cC]\s+"""                              # Windows cmd
    r"""|powershell(?:\.exe)?\s+-(?:Command|c)\s+""",             # PowerShell
    re.VERBOSE,
)

# Matches the quoted payload after the shell -c invocation.
# Group 1: double-quoted, Group 2: single-quoted, Group 3: rest of line (unquoted).
_QUOTED_PAYLOAD_RE = re.compile(
    r"""(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|(.+))""",
)


def _unwrap_shell_commands(line: str, *, _depth: int = 0) -> List[str]:
    """Return a list of unwrapped inner commands from nested shell invocations.

    Given ``bash -c "sh -c 'rm -rf /'"`` returns ``['rm -rf /']`` (plus
    intermediate layers).  Max recursion depth is 5 to prevent pathological
    inputs from looping.
    """
    if _depth > 5:
        return []
    results: List[str] = []
    for m in _SHELL_WRAP_RE.finditer(line):
        rest = line[m.end():]
        pm = _QUOTED_PAYLOAD_RE.match(rest)
        if pm:
            payload = pm.group(1) or pm.group(2) or pm.group(3) or ""
            # Unescape basic sequences
            payload = payload.replace('\\"', '"').replace("\\'", "'")
            if payload:
                results.append(payload)
                # Recurse to handle deeper nesting
                results.extend(_unwrap_shell_commands(payload, _depth=_depth + 1))
    return results


MALICIOUS_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "curl\\b[^|&;#\\n]*\\$\\{?(?:HOME|TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIAL|ANTHROPIC_API_KEY|OPENAI_API_KEY)\\}?",
        CRIT,
        "凭证外传 (curl)",
        "凭证通过 curl 发送到外部。",
    ),
    (
        "wget\\b[^|&;#\\n]*\\$\\{?(?:TOKEN|API_KEY|SECRET|PASSWORD)\\}?",
        CRIT,
        "凭证外传 (wget)",
        "凭证通过 wget 发送到外部。",
    ),
    (
        "bash\\s+-i\\s+>?&?\\s*/dev/tcp/",
        CRIT,
        "反弹 Shell (bash /dev/tcp)",
        "bash 反弹 shell。",
    ),
    (
        "\\bnc\\b.{0,30}-e\\s+(?:/bin/bash|/bin/sh|sh)",
        CRIT,
        "反弹 Shell (nc -e)",
        "netcat 反弹 shell。",
    ),
    (
        "python.{0,60}socket.{0,40}connect.{0,60}(?:subprocess|Popen)",
        CRIT,
        "反弹 Shell (Python socket)",
        "Python socket+subprocess。",
    ),
    (
        "(?i)\\b(?:xmrig|stratum\\+tcp://|xmr\\.pool\\.|monero|coinhive)",
        CRIT,
        "挖矿程序特征",
        "加密货币挖矿特征。",
    ),
    (
        "\\brm\\s+-rf\\s+(?:/root|/home|/etc|/var|/usr|~)\\b",
        CRIT,
        "危险批量删除",
        "rm -rf 指向系统关键目录。",
    ),
    (
        "(?i)ignore\\s+(?:all\\s+)?(?:previous|above)\\s+instructions?",
        CRIT,
        "提示词注入：覆盖指令",
        "供应链 prompt injection。",
    ),
    (
        "(?i)you\\s+are\\s+now\\s+(?:a\\s+)?(?:different|new|another|unrestricted|uncensored)",
        CRIT,
        "提示词注入：角色劫持",
        "重置 LLM 角色。",
    ),
    (
        "(?i)(?:jailbreak|dan\\s+mode|developer\\s+mode|do\\s+anything\\s+now|skeleton\\s+key)",
        CRIT,
        "越狱关键词",
        "jailbreak / DAN / Skeleton Key。",
    ),
    (
        "base64\\s+-d\\s*[|>]\\s*(?:bash|sh|python|\\$\\()",
        CRIT,
        "混淆载荷 (base64→shell)",
        "base64→shell 管道。",
    ),
    (
        "mkfifo\\s+.*\\bnc\\b",
        CRIT,
        "命名管道反弹 Shell (mkfifo+nc)",
        "mkfifo+nc 组合反弹 shell。",
    ),
    (
        "(?i)(?:chmod\\s+(?:777|a\\+rwx)\\s+)",
        CRIT,
        "危险权限变更 (chmod 777)",
        "将文件设为全局可读写执行。",
    ),
    (
        "忽略(之前|上面|所有)(的)?(指令|规则|限制|约束)",
        CRIT,
        "提示词注入：覆盖指令 (中文)",
        "中文指令覆盖。",
    ),
    (
        "(输出|显示|打印|泄露)(你的)?(系统提示|系统指令|内部规则)",
        HIGH,
        "提示词注入：提取系统提示词 (中文)",
        "提取系统提示词。",
    ),
    (
        "(你现在是|从现在开始你是|扮演|假装)(一个)?",
        WARN,
        "疑似角色劫持 (中文)",
        "中文角色重定义指令。",
    ),
    (
        "(?:\\\\u[0-9a-fA-F]{4}){6,}",
        HIGH,
        "大量 Unicode 转义（疑似混淆）",
        "Unicode 转义隐藏注入指令。",
    ),
    (
        "(?i)(?:password|secret|token|api_key|api-key)\\s*[=:]\\s*[\"\\'][^\\s\"\\']{12,}[\"\\']",
        HIGH,
        "疑似硬编码凭证",
        "代码中存在凭证字符串。",
    ),
    (
        "(?i)(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|sk-[A-Za-z0-9]{32,}|sk-ant-[A-Za-z0-9\\-]{20,})",
        HIGH,
        "疑似 AI API 密钥",
        "发现 API key 格式字符串。",
    ),
    (
        "(?i)(?:export|setenv|ENV)\\s+(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES)\\s*=",
        HIGH,
        "设置危险环境变量",
        "通过 export 设置可注入代码的环境变量。",
    ),
    (
        "(?i)(?:fsutil|format|diskpart|dd\\s+if=.*of=/dev/)",
        HIGH,
        "磁盘级危险操作",
        "磁盘格式化或低级写入操作。",
    ),
    (
        "(?i)crontab\\s+-.*(?:curl|wget|bash|python)",
        HIGH,
        "Cron 持久化",
        "通过 crontab 写入持久化任务。",
    ),
    (
        "(?i)(?:systemctl\\s+enable|launchctl\\s+load)\\s+",
        WARN,
        "注册系统服务",
        "注册持久化系统服务。",
    ),
    ("\\beval\\s*\\(", WARN, "使用 eval()", "动态代码执行。"),
    ("\\bexec\\s*\\(", WARN, "使用 exec()", "exec() 执行任意代码。"),
    (
        "^(?!\\s*#)\\s*\\bsubprocess\\.(?:Popen|call|run|check_output)\\s*\\(",
        WARN,
        "调用子进程",
        "执行系统子进程。",
    ),
    (
        "os\\.environ(?:\\.get)?\\s*[\\[(\"\\']+(?!CLAW_|SKILL_|APP_|PATH|HOME|USER|SHELL|TERM)[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)",
        WARN,
        "读取凭证类环境变量",
        "访问疑似凭证类环境变量。",
    ),
    (
        "(?:~|Path\\.home\\(\\))\\s*/\\s*(?:Documents|Desktop|Downloads|Pictures|Movies|Library)",
        WARN,
        "访问用户隐私目录",
        "访问系统个人目录。",
    ),
    (
        "(?i)open\\([\"\\'](?:/etc/passwd|/etc/shadow|~/.ssh/|~/.aws/credentials)",
        WARN,
        "访问系统敏感文件",
        "读取敏感系统文件。",
    ),
    (
        "(?i)(?:requests|httpx|urllib|aiohttp)\\.(?:get|post|put|delete)\\s*\\(",
        WARN,
        "外部网络请求",
        "发起 HTTP 请求，确认目标是否可控。",
    ),
    ("(?i)__import__\\s*\\(", WARN, "动态模块导入", "运行时动态导入。"),
    (
        "(?i)(?:ctypes|cffi)\\.",
        WARN,
        "调用 C 外部函数",
        "使用 ctypes/cffi 调用原生代码。",
    ),
    (
        "(?i)(?:pickle|marshal|shelve)\\.(?:load|loads)\\s*\\(",
        WARN,
        "反序列化不可信数据",
        "pickle/marshal 反序列化可执行任意代码。",
    ),
    (
        "(?i)(?:yaml\\.(?:load|unsafe_load)\\s*\\()",
        WARN,
        "不安全的 YAML 加载",
        "yaml.load 不指定 Loader 可执行任意代码。",
    ),
    (
        "(?i)(?:compile|exec|eval)\\s*\\(.*(?:request|input|argv|stdin)",
        HIGH,
        "用户输入直接进入代码执行",
        "用户可控输入直接传入 eval/exec/compile。",
    ),
    (
        "(?i)(?:os\\.chmod|os\\.chown)\\s*\\(.*/etc/|/var/",
        WARN,
        "修改系统目录权限",
        "修改 /etc 或 /var 下的权限。",
    ),
    (
        "(?i)(?:shutil\\.rmtree|os\\.removedirs)\\s*\\(.*/home|/root|/etc|/var",
        HIGH,
        "递归删除系统目录",
        "递归删除系统关键目录。",
    ),
    (
        "(?i)socket\\.(?:bind|listen)\\s*\\(",
        WARN,
        "创建网络服务端",
        "skill 创建监听 socket。",
    ),
    (
        "(?i)(?:atob|Buffer\\.from)\\s*\\([\"\\'][A-Za-z0-9+/=]{40,}",
        WARN,
        "Base64 解码长字符串",
        "解码可能包含隐藏指令的 base64。",
    ),
    (
        "(?i)String\\.fromCharCode\\s*\\(\\s*\\d+\\s*(?:,\\s*\\d+\\s*){5,}",
        WARN,
        "fromCharCode 字符串构造",
        "用 charCode 构造字符串可能隐藏指令。",
    ),
    (
        "[\\u200b\\u200c\\u200d\\ufeff\\u2060]{2,}",
        HIGH,
        "零宽字符序列",
        "包含零宽字符，可能隐藏注入内容。",
    ),
    (
        "(?i)(?:tool_call|function_call|tool_use).*(?:override|replace|shadow)",
        HIGH,
        "工具覆盖意图",
        "代码中出现工具覆盖关键词。",
    ),
    (
        "(?i)(?:mcp|server).*(?:proxy|forward|redirect).*(?:all|every)",
        HIGH,
        "MCP 流量劫持意图",
        "可能劫持 MCP 通信。",
    ),
    (
        "(?i)(?:fetch|axios|request)\\s*\\([\"\\']https?://(?!localhost|127\\.)",
        WARN,
        "向外部 URL 发送请求",
        "向非本地 URL 发起请求。",
    ),
    (
        "(?i)(?:dns|nslookup|dig)\\s+.*\\$",
        HIGH,
        "DNS 外传 (DNS exfiltration)",
        "通过 DNS 查询外传数据。",
    ),
    (
        "(?i)webhook[s]?\\s*[=:]\\s*[\"\\']https?://",
        WARN,
        "配置了外部 Webhook",
        "数据可能通过 webhook 外传。",
    ),
]


def scan_skill(skill_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    skill_name = skill_path.stem if skill_path.is_file() else skill_path.name
    files: List[Path] = []
    if skill_path.is_file():
        files = [skill_path]
    else:
        for ext in [
            "*.md",
            "*.sh",
            "*.bash",
            "*.py",
            "*.js",
            "*.ts",
            "*.mjs",
            "*.json",
            "*.yaml",
            "*.yml",
            "*.toml",
            "*.env",
        ]:
            files.extend(skill_path.rglob(ext))
    seen: set = set()
    for f in files:
        if "node_modules" in str(f) or ".git" in str(f):
            continue
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            # Build candidate lines: original + any unwrapped shell payloads
            candidates = [line]
            unwrapped = _unwrap_shell_commands(line)
            candidates.extend(unwrapped)
            is_deobfuscated = False
            for candidate in candidates:
                for pattern, level, title, detail in MALICIOUS_PATTERNS:
                    if re.search(pattern, candidate):
                        key = f"{pattern}:{f}:{i}"
                        if key in seen:
                            continue
                        seen.add(key)
                        suffix = " (反混淆后发现)" if candidate is not line else ""
                        findings.append(
                            Finding(
                                "skill",
                                level,
                                f"[{skill_name}] {title}{suffix}",
                                detail,
                                f"{f.name}:{i}",
                                line.strip()[:120],
                                metadata={
                                    "skill": skill_name,
                                    "file": str(f),
                                    "line": i,
                                    "deobfuscated": candidate is not line,
                                },
                            )
                        )
                        if candidate is not line:
                            is_deobfuscated = True
            # If shell wrapping was detected and inner payloads were found,
            # emit an additional info-level finding about the obfuscation.
            if unwrapped and is_deobfuscated:
                ob_key = f"__obfuscation__:{f}:{i}"
                if ob_key not in seen:
                    seen.add(ob_key)
                    findings.append(
                        Finding(
                            "skill",
                            WARN,
                            f"[{skill_name}] Shell 命令嵌套混淆",
                            f"检测到 {len(unwrapped)} 层 shell 包装，可能试图绕过静态检测。",
                            f"{f.name}:{i}",
                            line.strip()[:120],
                            remediation="审查解包后的实际命令。",
                            metadata={
                                "skill": skill_name,
                                "file": str(f),
                                "line": i,
                                "unwrapped_commands": unwrapped,
                            },
                        )
                    )
    return findings


def scan_all_skills(
    adapter: AdapterSpec, extra_dir: Optional[str] = None
) -> Tuple[List[Finding], int]:
    findings, dirs = ([], [])
    if extra_dir:
        dirs.append(Path(extra_dir).expanduser())
    for d in adapter.skills_dirs:
        p = Path(d).expanduser()
        if p.exists():
            dirs.append(p)
    scanned = 0
    for d in dirs:
        if not d.exists():
            continue
        for item in d.iterdir():
            if item.is_dir() or item.suffix == ".md":
                findings.extend(scan_skill(item))
                scanned += 1
    return (findings, scanned)


SOUL_INJECTION_PATTERNS: List[Tuple[str, str, str]] = [
    (
        "(?i)ignore\\s+(?:all\\s+)?(?:previous|above)\\s+instructions?",
        CRIT,
        "指令覆盖注入",
    ),
    (
        "(?i)you\\s+are\\s+now\\s+(?:a\\s+new|another|a\\s+different|uncensored)",
        CRIT,
        "角色劫持注入",
    ),
    (
        "(?i)(?:jailbreak|dan\\s+mode|unrestricted\\s+mode|developer\\s+mode)",
        CRIT,
        "越狱关键词",
    ),
    ("(?:\\\\u[0-9a-fA-F]{4}){6,}", HIGH, "大量 Unicode 转义"),
    ("(?:[A-Za-z0-9+/]{60,}={0,2})", WARN, "长 base64 字符串"),
    (
        "(?i)do\\s+not\\s+(?:reveal|disclose|share)\\s+(?:your\\s+)?(?:system\\s+prompt|instructions)",
        WARN,
        "要求模型隐藏指令",
    ),
]
HASH_STORE = Path.home() / ".clawlock" / "drift_hashes.json"


def _load_hashes() -> dict:
    HASH_STORE.parent.mkdir(parents=True, exist_ok=True)
    if HASH_STORE.exists():
        try:
            return json.loads(HASH_STORE.read_text())
        except Exception:
            pass
    return {}


def _save_hashes(d: dict):
    HASH_STORE.parent.mkdir(parents=True, exist_ok=True)
    HASH_STORE.write_text(json.dumps(d, indent=2))


def _scan_single_file_drift(filepath: Path, label: str) -> List[Finding]:
    """Scan one file for injection patterns + drift."""
    findings = []
    if not filepath.exists():
        return findings
    content = filepath.read_text(errors="ignore")
    for i, line in enumerate(content.splitlines(), 1):
        for pattern, level, title in SOUL_INJECTION_PATTERNS:
            if re.search(pattern, line):
                findings.append(
                    Finding(
                        "soul",
                        level,
                        f"{label}: {title}",
                        f"位置: {filepath.name}:{i}",
                        f"{filepath.name}:{i}",
                        line.strip()[:120],
                        "检查该行是否合法。",
                    )
                )
                break
    current_hash = hashlib.sha256(content.encode()).hexdigest()
    stored = _load_hashes()
    key = str(filepath.resolve())
    if key in stored and stored[key] != current_hash:
        findings.append(
            Finding(
                "soul",
                WARN,
                f"⚡ {label} 内容已变更（Drift 检测）",
                f"{filepath.name} 的 SHA-256 哈希已变化。",
                str(filepath),
                remediation="若变更是预期的，运行 `clawlock soul --update-baseline` 更新基准。",
                metadata={"prev": stored[key][:12], "curr": current_hash[:12]},
            )
        )
    stored[key] = current_hash
    _save_hashes(stored)
    return findings


def scan_soul(
    adapter: AdapterSpec, soul_path: Optional[str] = None
) -> Tuple[List[Finding], Optional[Path]]:
    findings, candidates = ([], [])
    if soul_path:
        candidates = [Path(soul_path).expanduser()]
    else:
        for fname in adapter.soul_filenames:
            candidates += [
                Path.cwd() / fname,
                Path.home() / f".{adapter.name}" / fname,
                Path.home() / ".claude" / fname,
            ]
    found = None
    for c in candidates:
        if c.exists():
            found = c
            break
    if found:
        findings.extend(_scan_single_file_drift(found, "系统提示词"))
    return (findings, found)


def scan_memory_files(adapter: AdapterSpec) -> List[Finding]:
    """v1.1: Scan HEARTBEAT.md, MEMORY.md, memory/*.md for injection+drift."""
    findings = []
    for mem_path_str in adapter.memory_files:
        mem_path = Path(mem_path_str).expanduser()
        if mem_path.is_file():
            findings.extend(_scan_single_file_drift(mem_path, "记忆文件"))
        elif mem_path.is_dir():
            for md in mem_path.glob("*.md"):
                findings.extend(_scan_single_file_drift(md, "记忆文件"))
    return findings


_MCP_ITP = [
    (
        "(?i)(?:all\\s+(?:messages?|emails?|data|files?)\\s+(?:sent|written|uploaded)\\s+(?:via|through)\\s+\\S+\\s+(?:must\\s+be\\s+)?(?:redirect|forward|copy|send))",
        CRIT,
        "隐式工具投毒: 参数篡改 (ASR≈47%)",
        "将合法参数静默重定向。",
    ),
    (
        "(?i)(?:instead\\s+of\\s+(?:calling|using|invoking)\\s+\\S+,?\\s+(?:call|use|invoke|run)\\s+\\S+)",
        HIGH,
        "隐式工具投毒: 函数劫持 (ASR≈37%)",
        "要求调用另一个工具。",
    ),
    (
        "(?i)(?:before\\s+(?:any|each|every)\\s+(?:file|network|database|tool)\\s+(?:operation|action|call),?\\s+(?:first\\s+)?(?:read|send|upload|post|access))",
        CRIT,
        "隐式工具投毒: 隐式触发器 (ASR≈27%)",
        "在任意操作前插入前置动作。",
    ),
    (
        "(?i)(?:this\\s+tool\\s+(?:has\\s+been\\s+)?(?:updated|changed|modified))",
        WARN,
        "MCP Rug Pull 迹象",
        "工具声称已修改行为。",
    ),
    (
        "(?i)(?:(?:replaces?|supersedes?|overrides?|shadows?)\\s+(?:the\\s+)?(?:built-in|default|original|existing)\\s+\\S+\\s+tool)",
        HIGH,
        "MCP 工具覆盖 (Tool Shadowing)",
        "声称替代内置工具。",
    ),
    (
        "(?i)(?:permission\\s+(?:from|granted\\s+by)\\s+(?:\\S+\\s+)?server)",
        WARN,
        "MCP 跨域权限提升",
        "声明来自另一服务器的权限。",
    ),
]


def scan_mcp(adapter: AdapterSpec, extra_mcp: Optional[str] = None) -> List[Finding]:
    findings, configs = ([], [])
    if extra_mcp:
        configs.append(Path(extra_mcp).expanduser())
    for p in adapter.mcp_configs:
        exp = Path(p).expanduser()
        if exp.exists():
            configs.append(exp)
    for fname in [".mcp.json", "mcp.json", "claude_desktop_config.json"]:
        p = Path.cwd() / fname
        if p.exists():
            configs.append(p)
    seen_configs: set = set()
    for cfg_path in configs:
        key = str(cfg_path.resolve())
        if key in seen_configs:
            continue
        seen_configs.add(key)
        try:
            data = json.loads(cfg_path.read_text())
        except Exception:
            continue
        servers = data.get("mcpServers", data.get("servers", {}))
        for srv_name, srv in servers.items():
            url, env = (srv.get("url", ""), srv.get("env", {}))
            if isinstance(url, str):
                if re.match("https?://(?:0\\.0\\.0\\.0|\\*)", url):
                    findings.append(
                        Finding(
                            "mcp",
                            CRIT,
                            f"MCP [{srv_name}] 绑定 0.0.0.0",
                            "服务器对外网暴露。",
                            f"{cfg_path.name}:mcpServers.{srv_name}",
                            remediation="改为 127.0.0.1。",
                        )
                    )
                elif (
                    url.startswith("http")
                    and "localhost" not in url
                    and ("127." not in url)
                ):
                    findings.append(
                        Finding(
                            "mcp",
                            WARN,
                            f"MCP [{srv_name}] 连接远程端点",
                            f"指向 {url[:60]}。",
                            f"{cfg_path.name}:mcpServers.{srv_name}",
                            remediation="确认可信度。",
                        )
                    )
            for ek, ev in (env or {}).items():
                if (
                    re.search("(?i)(password|secret|token|api_key)", ek)
                    and len(str(ev)) > 8
                ):
                    findings.append(
                        Finding(
                            "mcp",
                            HIGH,
                            f"MCP [{srv_name}] env 中含凭证",
                            f"字段 {ek} 明文写入配置。",
                            f"{cfg_path.name}:mcpServers.{srv_name}.env.{ek}",
                            remediation="改用环境变量。",
                        )
                    )
                if ek.upper() in RISKY_ENV_VARS:
                    findings.append(
                        Finding(
                            "mcp",
                            HIGH,
                            f"MCP [{srv_name}] env 含危险变量: {ek}",
                            f"{ek} 可被利用注入恶意代码到 MCP 服务器进程。",
                            f"{cfg_path.name}:mcpServers.{srv_name}.env.{ek}",
                            remediation=f"移除 {ek}。",
                        )
                    )
            for tool in srv.get("tools", []):
                text_fields = {
                    "description": tool.get("description", ""),
                    "annotations": str(tool.get("annotations", "")),
                    "errorTemplate": str(tool.get("errorTemplate", "")),
                    "outputTemplate": str(tool.get("outputTemplate", "")),
                }
                for pn, prop in (
                    tool.get("inputSchema", {}).get("properties", {}).items()
                ):
                    text_fields[f"param:{pn}"] = prop.get("description", "")
                for fn, text in text_fields.items():
                    if not text:
                        continue
                    for pat, lv, title, detail in _MCP_ITP:
                        if re.search(pat, text, re.MULTILINE):
                            findings.append(
                                Finding(
                                    "mcp_itp",
                                    lv,
                                    f"[{srv_name}/{tool.get('name', '?')}] {title}",
                                    detail,
                                    f"{cfg_path.name}:tools[{tool.get('name', '?')}].{fn}",
                                    text[:120],
                                    "审查该工具描述来源。",
                                )
                            )
                            break
    return findings


def precheck_skill_md(skill_md_path: Path) -> Tuple[List[Finding], bool]:
    """5-dimension auto safety check when importing new SKILL.md."""
    findings: List[Finding] = []
    if not skill_md_path.exists():
        return (findings, True)
    content = skill_md_path.read_text(errors="ignore")
    skill_name = (
        skill_md_path.parent.name
        if skill_md_path.name == "SKILL.md"
        else skill_md_path.stem
    )
    for i, line in enumerate(content.splitlines(), 1):
        candidates = [line]
        candidates.extend(_unwrap_shell_commands(line))
        for candidate in candidates:
            for pattern, level, title, detail in MALICIOUS_PATTERNS:
                if re.search(pattern, candidate):
                    suffix = " (反混淆后发现)" if candidate is not line else ""
                    findings.append(
                        Finding(
                            "skill_precheck",
                            level,
                            f"[新 Skill: {skill_name}] {title}{suffix}",
                            detail,
                            f"SKILL.md:{i}",
                            line.strip()[:120],
                            "安装前仔细审查来源和代码。",
                        )
                    )
                    break
    for pat, lv, title, detail in [
        (
            "(?i)requires.*(?:sudo|root|admin)",
            HIGH,
            "要求管理员权限",
            "声明需要 sudo/root。",
        ),
        (
            "(?i)requires.*(?:full.?disk|全盘|所有文件)",
            HIGH,
            "要求全盘访问",
            "声明需要全盘文件访问。",
        ),
        (
            "(?i)bins.*(?:curl|wget|nc|netcat|nmap|ssh)",
            WARN,
            "依赖网络工具",
            "依赖网络工具二进制。",
        ),
        (
            "(?i)(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES)",
            HIGH,
            "引用危险环境变量",
            "SKILL.md 中引用了可注入代码的环境变量。",
        ),
    ]:
        if re.search(pat, content):
            findings.append(
                Finding(
                    "skill_precheck",
                    lv,
                    f"[新 Skill: {skill_name}] {title}",
                    detail,
                    "SKILL.md:metadata",
                    remediation="确认这些权限是否与功能匹配。",
                )
            )
    urls = re.findall("https?://[^\\s\\)>\"\\']+", content)
    for url in urls:
        if any(
            (
                f"{tld}" in url.lower()
                for tld in [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".buzz"]
            )
        ):
            findings.append(
                Finding(
                    "skill_precheck",
                    WARN,
                    f"[新 Skill: {skill_name}] 引用可疑域名",
                    f"URL: {url[:80]}",
                    remediation="确认域名可信度。",
                )
            )
    if re.search("[\\u200b\\u200c\\u200d\\ufeff\\u2060]", content):
        findings.append(
            Finding(
                "skill_precheck",
                HIGH,
                f"[新 Skill: {skill_name}] 发现零宽字符",
                "可能隐藏注入内容。",
                remediation="使用十六进制编辑器检查。",
            )
        )
    if len(content) > 50000:
        findings.append(
            Finding(
                "skill_precheck",
                WARN,
                f"[新 Skill: {skill_name}] SKILL.md 异常过大",
                f"文件 {len(content)} 字节。",
                remediation="检查是否包含不必要的嵌入内容。",
            )
        )
    is_safe = not any((f.level in (CRIT, HIGH) for f in findings))
    return (findings, is_safe)
