"""
LLM Agent Layer
Four-step analysis pipeline inspired by LLift:
  Agent 1: Code Understanding
  Agent 2: Path Analysis
  Agent 3: Vulnerability Judgment
  Agent 4: Fix Suggestion
"""
from __future__ import annotations
import json
import re
import logging
from typing import Any
from openai import OpenAI
from backend.config import get_settings

_env = get_settings()
logger = logging.getLogger(__name__)


def _get_runtime_cfg() -> dict[str, str]:
    """Read effective config from DB (falls back to env defaults if no DB override)."""
    try:
        from backend.database import SessionLocal
        from backend.models import SystemConfig
        from backend.api.settings_routes import DEFAULTS
        db = SessionLocal()
        try:
            rows = db.query(SystemConfig).all()
            cfg = dict(DEFAULTS)
            for row in rows:
                cfg[row.key] = row.value
            return cfg
        finally:
            db.close()
    except Exception as e:
        logger.warning("Cannot read runtime config from DB, using env defaults: %s", e)
        return {
            "llm_api_key":     _env.OPENAI_API_KEY,
            "llm_model":       _env.OPENAI_MODEL,
            "llm_base_url":    _env.OPENAI_BASE_URL,
            "llm_temperature": "0.2",
            "agent1_system":   AGENT1_SYSTEM,
            "agent2_system":   AGENT2_SYSTEM,
            "agent3_system":   AGENT3_SYSTEM,
            "agent4_system":   AGENT4_SYSTEM,
            "agent1_user_tmpl": AGENT1_USER_TMPL,
            "agent2_user_tmpl": AGENT2_USER_TMPL,
            "agent3_user_tmpl": AGENT3_USER_TMPL,
            "agent4_user_tmpl": AGENT4_USER_TMPL,
        }


def _get_client(cfg: dict | None = None) -> OpenAI:
    if cfg is None:
        cfg = _get_runtime_cfg()
    kwargs: dict = {"api_key": cfg["llm_api_key"]}
    if cfg.get("llm_base_url"):
        kwargs["base_url"] = cfg["llm_base_url"]
    return OpenAI(**kwargs)


def _chat(client: OpenAI, messages: list[dict], temperature: float = 0.2, model: str = "") -> str:
    if not model:
        model = _get_runtime_cfg()["llm_model"]
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
    )
    return response.choices[0].message.content or ""


def _extract_json(text: str) -> dict:
    """Try to extract JSON object from LLM response text."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to find JSON block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Last resort: find first {...}
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {}


# ─────────────────────────────────────────────────────────────
# Agent 1: Code Understanding
# ─────────────────────────────────────────────────────────────

AGENT1_SYSTEM = """\
你是一名资深 C/C++ 安全代码分析专家。
给定代码片段和一条 SAST 发现，请分析：
1. 关键变量及其作用
2. 控制流逻辑
3. 数据流路径
4. 可能存在风险的操作

所有输出必须使用简体中文。
请以纯文本返回简洁、技术化的分析结论。"""

AGENT1_USER_TMPL = """\
SAST 工具: {tool}
规则: {rule_id}
文件: {file_path}:{line}
消息: {message}
函数: {function_name}

代码片段:
```
{code_snippet}
```

请使用简体中文分析代码结构，并说明：
- 变量之间的关系
- 控制逻辑
- 与该问题相关的可疑模式"""


def agent_code_understanding(finding: dict, client: OpenAI | None = None) -> str:
    """Agent 1: Understand the code context."""
    cfg = _get_runtime_cfg()
    if client is None:
        client = _get_client(cfg)
    system = cfg["agent1_system"]
    tmpl = cfg["agent1_user_tmpl"]
    prompt = tmpl.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        file_path=finding.get("file_path", ""),
        line=finding.get("line_start", 0),
        message=finding.get("message", ""),
        function_name=finding.get("function_name", ""),
        code_snippet=finding.get("code_snippet", "（代码片段不可用）"),
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    try:
        return _chat(client, messages, float(cfg.get("llm_temperature", 0.2)), cfg["llm_model"])
    except Exception as e:
        logger.error("Agent1 error: %s", e)
        return f"代码理解分析失败: {e}"


# ─────────────────────────────────────────────────────────────
# Agent 2: Path Analysis
# ─────────────────────────────────────────────────────────────

AGENT2_SYSTEM = """\
你是一名程序分析专家，专注于执行路径可达性判断。
给定代码片段、执行轨迹和一条 SAST 发现，请判断：
1. 报告中的执行路径是否真实可达
2. 是否缺少必要的保护条件
3. 该路径是否会导向真实的漏洞状态

所有输出必须使用简体中文。
结论要准确，并基于证据。"""

AGENT2_USER_TMPL = """\
SAST 问题:
    工具: {tool}, 规则: {rule_id}
    消息: {message}

代码理解:
{code_understanding}

SAST 跟踪中的执行路径:
{execution_path}

代码片段:
```
{code_snippet}
```

请使用简体中文分析：
1. 这条执行路径是否可行？
2. 路径上的条件是否都可满足？
3. 是否缺少空指针检查、边界检查或其他保护条件？

请给出简洁的路径可行性评估。"""


def agent_path_analysis(finding: dict, code_understanding: str, client: OpenAI | None = None) -> str:
    """Agent 2: Analyze execution path feasibility."""
    cfg = _get_runtime_cfg()
    if client is None:
        client = _get_client(cfg)
    system = cfg["agent2_system"]
    tmpl = cfg["agent2_user_tmpl"]
    path_str = "\n".join(finding.get("execution_path", [])) or "（无可用执行轨迹）"
    prompt = tmpl.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        message=finding.get("message", ""),
        code_understanding=code_understanding,
        execution_path=path_str,
        code_snippet=finding.get("code_snippet", "（代码片段不可用）"),
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    try:
        return _chat(client, messages, float(cfg.get("llm_temperature", 0.2)), cfg["llm_model"])
    except Exception as e:
        logger.error("Agent2 error: %s", e)
        return f"执行路径分析失败: {e}"


# ─────────────────────────────────────────────────────────────
# Agent 3: Vulnerability Judgment
# ─────────────────────────────────────────────────────────────

AGENT3_SYSTEM = """\
你是一名漏洞评估专家。
请基于代码分析和路径分析，明确判断一条 SAST 发现是真实漏洞还是误报。

你必须只返回一个合法的 JSON 对象，格式必须严格如下，且其中的说明文字内容必须使用简体中文：
{
  "is_vulnerable": true or false,
  "confidence": 0.0 to 1.0,
    "reason": "简洁说明",
    "false_positive_indicators": ["如果是误报，请列出原因"],
    "true_positive_indicators": ["如果是真实漏洞，请列出原因"]
}"""

AGENT3_USER_TMPL = """\
SAST 问题:
    工具: {tool}
    规则: {rule_id}
    严重级别: {severity}
    文件: {file_path}:{line}
    消息: {message}

代码理解:
{code_understanding}

路径分析:
{path_analysis}

请基于全部证据判断这是真实漏洞还是误报。
只返回 JSON，不要附加其他文字；JSON 中的说明字段内容必须使用简体中文。"""


def agent_vulnerability_judgment(
    finding: dict,
    code_understanding: str,
    path_analysis: str,
    client: OpenAI | None = None,
) -> dict:
    """Agent 3: Judge whether finding is a real vulnerability."""
    cfg = _get_runtime_cfg()
    if client is None:
        client = _get_client(cfg)
    system = cfg["agent3_system"]
    tmpl = cfg["agent3_user_tmpl"]
    prompt = tmpl.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        severity=finding.get("sast_severity", "medium"),
        file_path=finding.get("file_path", ""),
        line=finding.get("line_start", 0),
        message=finding.get("message", ""),
        code_understanding=code_understanding,
        path_analysis=path_analysis,
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    try:
        raw = _chat(client, messages, 0.1, cfg["llm_model"])
        result = _extract_json(raw)
        return {
            "is_vulnerable": bool(result.get("is_vulnerable", True)),
            "confidence": float(result.get("confidence", 0.5)),
            "reason": result.get("reason", raw),
            "false_positive_indicators": result.get("false_positive_indicators", []),
            "true_positive_indicators": result.get("true_positive_indicators", []),
        }
    except Exception as e:
        logger.error("Agent3 error: %s", e)
        return {
            "is_vulnerable": True,
            "confidence": 0.5,
            "reason": f"LLM 分析失败: {e}",
            "false_positive_indicators": [],
            "true_positive_indicators": [],
        }


# ─────────────────────────────────────────────────────────────
# Agent 4: Fix Suggestion
# ─────────────────────────────────────────────────────────────

AGENT4_SYSTEM = """\
你是一名安全编码专家。对于已确认的问题，请提供：
1. 清晰的风险说明
2. 具体的修复建议以及示例补丁
3. 可用于避免类似问题的最佳实践

所有输出必须使用简体中文。
结论要具体、可执行。"""

AGENT4_USER_TMPL = """\
问题信息:
    工具: {tool}
    规则: {rule_id}
    文件: {file_path}:{line}
    消息: {message}

漏洞评估:
    是否为真实漏洞: {is_vulnerable}
    置信度: {confidence}
    原因: {reason}

代码片段:
```
{code_snippet}
```

请使用简体中文提供：
1. 风险说明（2 到 3 句话）
2. 带代码补丁示例的修复建议
3. 预防最佳实践"""


def agent_fix_suggestion(
    finding: dict,
    judgment: dict,
    client: OpenAI | None = None,
) -> dict:
    """Agent 4: Generate fix suggestions for confirmed vulnerabilities."""
    cfg = _get_runtime_cfg()
    if client is None:
        client = _get_client(cfg)
    system = cfg["agent4_system"]
    tmpl = cfg["agent4_user_tmpl"]
    prompt = tmpl.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        file_path=finding.get("file_path", ""),
        line=finding.get("line_start", 0),
        message=finding.get("message", ""),
        is_vulnerable=judgment.get("is_vulnerable", True),
        confidence=judgment.get("confidence", 0.5),
        reason=judgment.get("reason", ""),
        code_snippet=finding.get("code_snippet", "（代码片段不可用）"),
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    try:
        suggestion = _chat(client, messages, float(cfg.get("llm_temperature", 0.2)), cfg["llm_model"])
        patch_match = re.search(r"```(?:c|cpp|diff)?\s*(.*?)\s*```", suggestion, re.DOTALL)
        patch = patch_match.group(1) if patch_match else ""
        return {
            "fix_suggestion": suggestion,
            "patch_suggestion": patch,
        }
    except Exception as e:
        logger.error("Agent4 error: %s", e)
        return {
            "fix_suggestion": f"修复建议不可用: {e}",
            "patch_suggestion": "",
        }


# ─────────────────────────────────────────────────────────────
# Pipeline Runner
# ─────────────────────────────────────────────────────────────

def run_analysis_pipeline(finding: dict) -> dict:
    """
    Run the full 4-agent analysis pipeline on a finding.
    Config (API key, model, prompts) is read fresh from DB on each call.
    """
    cfg = _get_runtime_cfg()
    client = _get_client(cfg)
    result = dict(finding)

    logger.info("Agent1: Code Understanding for %s:%s", finding.get("file_path"), finding.get("line_start"))
    code_understanding = agent_code_understanding(finding, client)
    result["llm_code_understanding"] = code_understanding

    logger.info("Agent2: Path Analysis")
    path_analysis = agent_path_analysis(finding, code_understanding, client)
    result["llm_path_analysis"] = path_analysis

    logger.info("Agent3: Vulnerability Judgment")
    judgment = agent_vulnerability_judgment(finding, code_understanding, path_analysis, client)
    result["is_vulnerable"] = judgment["is_vulnerable"]
    result["llm_confidence"] = judgment["confidence"]
    result["llm_reason"] = judgment["reason"]

    logger.info("Agent4: Fix Suggestion")
    fix = agent_fix_suggestion(finding, judgment, client)
    result["fix_suggestion"] = fix["fix_suggestion"]
    result["patch_suggestion"] = fix["patch_suggestion"]

    return result
