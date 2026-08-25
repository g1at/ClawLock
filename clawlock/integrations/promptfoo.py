"""ClawLock Red-Team Module — wraps promptfoo for LLM red-teaming."""

from __future__ import annotations
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml
from ..scanners import Finding, INFO, WARN
from ..i18n import t
from ..utils import (
    BoundedCommandResult,
    CommandOutputTruncated,
    find_binary,
    run_bounded_command,
    scrub_command_diagnostic,
)

CLAW_AGENT_PLUGINS = [
    "prompt-injection",
    "hijacking",
    "excessive-agency",
    "pii",
    "harmful:privacy",
    "agentic:memory-poisoning",
    "harmful:hate",
    "rbac",
    "ssrf",
    "tool-discovery",
]
ENCODING_STRATEGIES = ["base64", "rot13", "leetspeak", "jailbreak-templates"]
DEEP_STRATEGIES = [
    "jailbreak",
    "jailbreak:tree",
    "jailbreak:meta",
    "crescendo",
    "indirect-web-pwn",
    *ENCODING_STRATEGIES,
]
QUICK_STRATEGIES = ["jailbreak", "jailbreak-templates", "base64"]


_PROMPTFOO_OUTPUT_LIMIT = 2 * 1024 * 1024


def _promptfoo_binary() -> Optional[str]:
    # Never download and execute an unpinned package implicitly.  Red-team
    # runs require a promptfoo binary the operator installed deliberately.
    return find_binary("promptfoo")


def _check_promptfoo():
    return _promptfoo_binary() is not None


def _execution_finding(title: str, detail: str, status: str) -> Finding:
    return Finding(
        "redteam",
        INFO,
        title,
        detail,
        metadata={
            "scan_status": status,
            "component": "promptfoo",
            "requested": True,
        },
    )


def _command_diagnostic(completed: BoundedCommandResult) -> str:
    return scrub_command_diagnostic(
        completed.stderr or completed.stdout or "", max_chars=500
    )


def _load_promptfoo_results(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("result document is not an object")
    result_block = payload.get("results")
    if isinstance(result_block, dict):
        result_items = result_block.get("results")
        stats = result_block.get("stats", {})
    else:
        # Older exports used a top-level result list. Accept that shape while
        # still rejecting documents that are not evaluation results at all.
        result_items = result_block
        stats = payload.get("stats", {})
    if not isinstance(result_items, list):
        raise ValueError("results.results is not a list")
    if not all(isinstance(item, dict) for item in result_items):
        raise ValueError("evaluation result rows must be objects")
    if not isinstance(stats, dict):
        raise ValueError("results.stats is not an object")
    return result_items, stats


def _result_error(item: Dict[str, Any]) -> str:
    candidates = [item.get("error")]
    for key in ("response", "gradingResult"):
        value = item.get(key)
        if isinstance(value, dict):
            candidates.append(value.get("error"))
    for candidate in candidates:
        if candidate:
            return scrub_command_diagnostic(candidate, max_chars=300)
    return ""


def _result_metadata(item: Dict[str, Any]) -> Dict[str, Any]:
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        return metadata
    test = item.get("test")
    if isinstance(test, dict) and isinstance(test.get("metadata"), dict):
        return test["metadata"]
    return {}


def _result_prompt(item: Dict[str, Any]) -> str:
    prompt = item.get("prompt", "")
    if isinstance(prompt, dict):
        prompt = prompt.get("raw", "")
    return str(prompt)[:80]


def build_redteam_config(
    endpoint, purpose="Claw-family AI agent", num_tests=10, deep=False
):
    return {
        "providers": [
            {
                "id": "openai:chat:gpt-4o-mini",
                "config": {
                    "apiBaseUrl": endpoint,
                    "headers": {"Content-Type": "application/json"},
                },
            }
        ],
        "prompts": ["{{query}}"],
        "redteam": {
            "purpose": purpose,
            "numTests": num_tests,
            "plugins": CLAW_AGENT_PLUGINS,
            "strategies": DEEP_STRATEGIES if deep else QUICK_STRATEGIES,
            "language": ["en", "zh"],
        },
    }


def run_redteam(
    endpoint, purpose="Claw-family AI agent", num_tests=10, deep=False, output_json=None
):
    findings = []
    promptfoo_bin = _promptfoo_binary()
    if not promptfoo_bin:
        return [
            _execution_finding(
                t("promptfoo 未安装，红队测试已跳过", "promptfoo is not installed; red-team testing was skipped"),
                t(
                    "请先显式安装并固定 promptfoo 版本；ClawLock 不会通过 npx 自动下载并执行 latest。",
                    "Install and pin promptfoo explicitly first; ClawLock will not download and execute latest through npx.",
                ),
                "skipped",
            )
        ]
    cfg = build_redteam_config(endpoint, purpose, num_tests, deep)
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "promptfooconfig.yaml"
        generated_path = Path(tmpdir) / "redteam.yaml"
        cfg_path.write_text(yaml.dump(cfg, allow_unicode=True), encoding="utf-8")
        out = Path(output_json) if output_json else Path(tmpdir) / "results.json"
        env = os.environ.copy()
        env["PROMPTFOO_DISABLE_SHARING"] = "true"
        generate_cmd = [
            promptfoo_bin,
            "redteam",
            "generate",
            "--config",
            str(cfg_path),
            "--output",
            str(generated_path),
        ]
        try:
            generated = run_bounded_command(
                generate_cmd,
                timeout=300,
                max_output_bytes=_PROMPTFOO_OUTPUT_LIMIT,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return [
                _execution_finding(
                    t("promptfoo 生成测试超时", "promptfoo test generation timed out"),
                    "promptfoo was terminated after exceeding the 300-second timeout",
                    "error",
                )
            ]
        except CommandOutputTruncated:
            return [
                _execution_finding(
                    t("promptfoo 生成输出过大", "promptfoo generation output was too large"),
                    f"promptfoo output exceeded the {_PROMPTFOO_OUTPUT_LIMIT}-byte safety limit",
                    "error",
                )
            ]
        except Exception as e:
            return [
                _execution_finding(
                    t("promptfoo 生成测试异常", "promptfoo test generation failed"),
                    scrub_command_diagnostic(e, max_chars=300),
                    "error",
                )
            ]
        if generated.returncode != 0:
            return [
                _execution_finding(
                    t("promptfoo 生成测试失败", "promptfoo test generation failed"),
                    _command_diagnostic(generated)
                    or f"exit code {generated.returncode}",
                    "error",
                )
            ]
        if not generated_path.exists():
            return [
                _execution_finding(
                    t("promptfoo 未生成测试", "promptfoo produced no generated tests"),
                    t(
                        "红队测试生成未完成，不能继续评测。",
                        "Red-team test generation did not complete, so evaluation cannot continue.",
                    ),
                    "error",
                )
            ]

        eval_cmd = [
            promptfoo_bin,
            "redteam",
            "eval",
            "--config",
            str(generated_path),
            "--output",
            str(out),
            "--no-share",
        ]
        try:
            if out.exists():
                out.unlink()
        except OSError as exc:
            return [
                _execution_finding(
                    t("promptfoo 结果路径无法写入", "promptfoo result path is not writable"),
                    scrub_command_diagnostic(exc, max_chars=300),
                    "error",
                )
            ]
        try:
            evaluated = run_bounded_command(
                eval_cmd,
                timeout=300,
                max_output_bytes=_PROMPTFOO_OUTPUT_LIMIT,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return [
                _execution_finding(
                    t("promptfoo 评测超时", "promptfoo evaluation timed out"),
                    "promptfoo was terminated after exceeding the 300-second timeout",
                    "error",
                )
            ]
        except CommandOutputTruncated:
            return [
                _execution_finding(
                    t("promptfoo 评测输出过大", "promptfoo evaluation output was too large"),
                    f"promptfoo output exceeded the {_PROMPTFOO_OUTPUT_LIMIT}-byte safety limit",
                    "error",
                )
            ]
        except Exception as e:
            return [
                _execution_finding(
                    t("promptfoo 评测异常", "promptfoo evaluation failed"),
                    scrub_command_diagnostic(e, max_chars=300),
                    "error",
                )
            ]
        if not out.exists():
            diagnostic = _command_diagnostic(evaluated)
            return [
                _execution_finding(
                    t("promptfoo 未生成结果", "promptfoo produced no result file"),
                    diagnostic
                    or t(
                        "红队测试结果不完整，不能视为通过。",
                        "The red-team run is incomplete and cannot be treated as a pass.",
                    ),
                    "error",
                )
            ]
        try:
            result_items, stats = _load_promptfoo_results(out)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            detail = scrub_command_diagnostic(exc, max_chars=300)
            diagnostic = _command_diagnostic(evaluated)
            if diagnostic:
                detail = f"{detail}; promptfoo: {diagnostic}"[:500]
            return [
                _execution_finding(
                    t("promptfoo 结果无法解析", "promptfoo result could not be parsed"),
                    detail,
                    "error",
                )
            ]

        row_errors = []
        for item in result_items:
            error = _result_error(item)
            if error:
                row_errors.append(error)
                continue
            success = item.get("success")
            if not isinstance(success, bool):
                row_errors.append(
                    "evaluation result row is missing a boolean success field"
                )
                continue
            if not success:
                metadata = _result_metadata(item)
                plugin = metadata.get("pluginId", "unknown")
                findings.append(
                    Finding(
                        "redteam",
                        WARN,
                        t(f"红队测试失败: {plugin}", f"Red team test failed: {plugin}"),
                        t(f"agent 对 [{plugin}] 攻击响应不符合预期。", f"Agent response to [{plugin}] attack did not meet expectations."),
                        snippet=_result_prompt(item),
                        remediation=t(f"检查 {plugin} 类攻击防护。", f"Review defenses against {plugin}-type attacks."),
                        metadata={
                            "plugin_id": plugin,
                            "strategy_id": metadata.get("strategyId", ""),
                        },
                    )
                )

        stats_errors = stats.get("errors", 0)
        has_stats_errors = isinstance(stats_errors, (int, float)) and stats_errors > 0
        configured_failure_code = env.get("PROMPTFOO_FAILED_TEST_EXIT_CODE", "100")
        try:
            expected_failure_code = int(configured_failure_code)
        except ValueError:
            expected_failure_code = 100
        if row_errors or has_stats_errors:
            detail = row_errors[0] if row_errors else f"results.stats.errors={stats_errors}"
            findings.append(
                _execution_finding(
                    t("promptfoo 评测包含执行错误", "promptfoo evaluation contains execution errors"),
                    detail,
                    "error",
                )
            )
        elif not result_items:
            findings.append(
                _execution_finding(
                    t("promptfoo 评测结果为空", "promptfoo evaluation returned no result rows"),
                    t(
                        "未得到任何红队用例结果，不能视为通过。",
                        "No red-team test rows were returned, so the run cannot be treated as a pass.",
                    ),
                    "error",
                )
            )
        elif evaluated.returncode != 0 and (
            not findings or evaluated.returncode != expected_failure_code
        ):
            # A failing assertion can intentionally produce a non-zero exit
            # code. Only that documented/configured code is explained by
            # parsed failing rows; other exits remain execution errors.
            findings.append(
                _execution_finding(
                    t("promptfoo 评测异常退出", "promptfoo evaluation exited unexpectedly"),
                    _command_diagnostic(evaluated)
                    or f"exit code {evaluated.returncode}",
                    "error",
                )
            )
    return findings


def generate_redteam_config_file(
    output_path, endpoint, purpose, num_tests=10, deep=False
):
    cfg = build_redteam_config(endpoint, purpose, num_tests, deep)
    output_path.write_text(yaml.dump(cfg, allow_unicode=True), encoding="utf-8")
