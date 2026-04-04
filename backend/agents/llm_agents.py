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
from openai import OpenAI, AsyncOpenAI
from backend.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


def _get_client() -> OpenAI:
    kwargs: dict = {"api_key": settings.OPENAI_API_KEY}
    if settings.OPENAI_BASE_URL:
        kwargs["base_url"] = settings.OPENAI_BASE_URL
    return OpenAI(**kwargs)


def _chat(client: OpenAI, messages: list[dict], temperature: float = 0.2) -> str:
    response = client.chat.completions.create(
        model=settings.OPENAI_MODEL,
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
You are a senior C/C++ security code analyst.
Given a code snippet and a SAST finding, analyze:
1. Key variables and their roles
2. Control flow logic
3. Data flow paths
4. Potential dangerous operations
Return a concise technical summary in plain text."""

AGENT1_USER_TMPL = """\
SAST Tool: {tool}
Rule: {rule_id}
File: {file_path}:{line}
Message: {message}
Function: {function_name}

Code Snippet:
```
{code_snippet}
```

Please analyze the code structure and describe:
- Variable relationships
- Control logic
- Any suspicious patterns related to the finding"""


def agent_code_understanding(finding: dict, client: OpenAI | None = None) -> str:
    """Agent 1: Understand the code context."""
    if client is None:
        client = _get_client()
    prompt = AGENT1_USER_TMPL.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        file_path=finding.get("file_path", ""),
        line=finding.get("line_start", 0),
        message=finding.get("message", ""),
        function_name=finding.get("function_name", ""),
        code_snippet=finding.get("code_snippet", "(not available)"),
    )
    messages = [
        {"role": "system", "content": AGENT1_SYSTEM},
        {"role": "user", "content": prompt},
    ]
    try:
        return _chat(client, messages)
    except Exception as e:
        logger.error("Agent1 error: %s", e)
        return f"Error in code understanding: {e}"


# ─────────────────────────────────────────────────────────────
# Agent 2: Path Analysis
# ─────────────────────────────────────────────────────────────

AGENT2_SYSTEM = """\
You are a program analysis expert specializing in execution path feasibility.
Given a code snippet, execution trace, and a SAST finding, determine:
1. Whether the reported execution path is actually reachable
2. If there are missing guard conditions
3. Whether the path leads to a real vulnerability condition
Be precise and evidence-based."""

AGENT2_USER_TMPL = """\
SAST Finding:
  Tool: {tool}, Rule: {rule_id}
  Message: {message}

Code Understanding:
{code_understanding}

Execution Path from SAST Trace:
{execution_path}

Code Snippet:
```
{code_snippet}
```

Analyze:
1. Is this execution path feasible?
2. Are all conditions on the path satisfiable?
3. Is there a missing null-check, bounds check, or other guard?
Provide a concise path feasibility assessment."""


def agent_path_analysis(finding: dict, code_understanding: str, client: OpenAI | None = None) -> str:
    """Agent 2: Analyze execution path feasibility."""
    if client is None:
        client = _get_client()

    path_str = "\n".join(finding.get("execution_path", [])) or "(no trace available)"
    prompt = AGENT2_USER_TMPL.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        message=finding.get("message", ""),
        code_understanding=code_understanding,
        execution_path=path_str,
        code_snippet=finding.get("code_snippet", "(not available)"),
    )
    messages = [
        {"role": "system", "content": AGENT2_SYSTEM},
        {"role": "user", "content": prompt},
    ]
    try:
        return _chat(client, messages)
    except Exception as e:
        logger.error("Agent2 error: %s", e)
        return f"Error in path analysis: {e}"


# ─────────────────────────────────────────────────────────────
# Agent 3: Vulnerability Judgment
# ─────────────────────────────────────────────────────────────

AGENT3_SYSTEM = """\
You are a vulnerability assessment expert.
Based on code analysis and path analysis, make a definitive judgment on whether
a SAST finding represents a real vulnerability or a false positive.

You MUST respond with ONLY a valid JSON object in this exact format:
{
  "is_vulnerable": true or false,
  "confidence": 0.0 to 1.0,
  "reason": "concise explanation",
  "false_positive_indicators": ["list of reasons if false positive"],
  "true_positive_indicators": ["list of reasons if true positive"]
}"""

AGENT3_USER_TMPL = """\
SAST Finding:
  Tool: {tool}
  Rule: {rule_id}
  Severity: {severity}
  File: {file_path}:{line}
  Message: {message}

Code Understanding:
{code_understanding}

Path Analysis:
{path_analysis}

Based on all evidence, is this a real vulnerability or false positive?
Respond with JSON only."""


def agent_vulnerability_judgment(
    finding: dict,
    code_understanding: str,
    path_analysis: str,
    client: OpenAI | None = None,
) -> dict:
    """Agent 3: Judge whether finding is a real vulnerability."""
    if client is None:
        client = _get_client()

    prompt = AGENT3_USER_TMPL.format(
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
        {"role": "system", "content": AGENT3_SYSTEM},
        {"role": "user", "content": prompt},
    ]
    try:
        raw = _chat(client, messages, temperature=0.1)
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
            "reason": f"LLM analysis failed: {e}",
            "false_positive_indicators": [],
            "true_positive_indicators": [],
        }


# ─────────────────────────────────────────────────────────────
# Agent 4: Fix Suggestion
# ─────────────────────────────────────────────────────────────

AGENT4_SYSTEM = """\
You are a secure coding expert. Given a confirmed vulnerability, provide:
1. A clear explanation of the risk
2. A concrete fix suggestion with example patch
3. Best practices to prevent similar issues
Be specific and actionable."""

AGENT4_USER_TMPL = """\
Vulnerability:
  Tool: {tool}
  Rule: {rule_id}
  File: {file_path}:{line}
  Message: {message}

Vulnerability Assessment:
  Is Vulnerable: {is_vulnerable}
  Confidence: {confidence}
  Reason: {reason}

Code Snippet:
```
{code_snippet}
```

Please provide:
1. Risk explanation (2-3 sentences)
2. Fix suggestion with code patch
3. Prevention best practices"""


def agent_fix_suggestion(
    finding: dict,
    judgment: dict,
    client: OpenAI | None = None,
) -> dict:
    """Agent 4: Generate fix suggestions for confirmed vulnerabilities."""
    if client is None:
        client = _get_client()

    prompt = AGENT4_USER_TMPL.format(
        tool=finding.get("tool", ""),
        rule_id=finding.get("rule_id", ""),
        file_path=finding.get("file_path", ""),
        line=finding.get("line_start", 0),
        message=finding.get("message", ""),
        is_vulnerable=judgment.get("is_vulnerable", True),
        confidence=judgment.get("confidence", 0.5),
        reason=judgment.get("reason", ""),
        code_snippet=finding.get("code_snippet", "(not available)"),
    )
    messages = [
        {"role": "system", "content": AGENT4_SYSTEM},
        {"role": "user", "content": prompt},
    ]
    try:
        suggestion = _chat(client, messages)
        # Extract patch block if present
        patch_match = re.search(r"```(?:c|cpp|diff)?\s*(.*?)\s*```", suggestion, re.DOTALL)
        patch = patch_match.group(1) if patch_match else ""
        return {
            "fix_suggestion": suggestion,
            "patch_suggestion": patch,
        }
    except Exception as e:
        logger.error("Agent4 error: %s", e)
        return {
            "fix_suggestion": f"Fix suggestion unavailable: {e}",
            "patch_suggestion": "",
        }


# ─────────────────────────────────────────────────────────────
# Pipeline Runner
# ─────────────────────────────────────────────────────────────

def run_analysis_pipeline(finding: dict) -> dict:
    """
    Run the full 4-agent analysis pipeline on a finding.
    Returns an enriched finding dict with LLM analysis results.
    """
    client = _get_client()
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
