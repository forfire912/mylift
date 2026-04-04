"""
Risk Scoring Engine
Formula: Risk Score = SAST Severity + LLM Confidence + Exploitability + Code Context Risk
Final score is normalized to 0-100.
"""
from __future__ import annotations

SEVERITY_BASE_SCORE = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 5,
}

SEVERITY_THRESHOLDS = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
}

# Keywords suggesting high-risk code context
HIGH_RISK_KEYWORDS = [
    "memcpy", "strcpy", "sprintf", "gets", "scanf",
    "malloc", "free", "realloc", "alloca",
    "exec", "system", "popen", "fork",
    "password", "secret", "token", "auth",
    "sql", "query", "execute",
    "NULL", "nullptr", "null",
]


def compute_risk_score(
    sast_severity: str,
    llm_confidence: float | None,
    is_vulnerable: bool | None,
    code_snippet: str | None,
    execution_path: list | None,
) -> dict:
    """
    Compute a composite risk score for a finding.

    Returns:
        {
            "risk_score": float (0-100),
            "final_severity": str,
            "breakdown": dict
        }
    """
    # 1. Base score from SAST severity (0-40)
    severity_score = SEVERITY_BASE_SCORE.get(sast_severity.lower(), 20)

    # 2. LLM confidence adjustment (0-35)
    llm_score = 0.0
    if llm_confidence is not None and is_vulnerable is not None:
        if is_vulnerable:
            llm_score = llm_confidence * 35
        else:
            # False positive - reduce base score
            llm_score = -(llm_confidence * 20)

    # 3. Exploitability: trace depth (0-15)
    trace_depth = len(execution_path) if execution_path else 0
    exploitability_score = min(trace_depth * 3, 15)

    # 4. Code context risk (0-10)
    context_score = 0
    if code_snippet:
        snippet_lower = code_snippet.lower()
        matches = sum(1 for kw in HIGH_RISK_KEYWORDS if kw.lower() in snippet_lower)
        context_score = min(matches * 2, 10)

    raw_score = severity_score + llm_score + exploitability_score + context_score
    risk_score = max(0.0, min(100.0, raw_score))

    final_severity = _score_to_severity(risk_score)

    return {
        "risk_score": round(risk_score, 2),
        "final_severity": final_severity,
        "breakdown": {
            "severity_score": severity_score,
            "llm_score": round(llm_score, 2),
            "exploitability_score": exploitability_score,
            "context_score": context_score,
        },
    }


def _score_to_severity(score: float) -> str:
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    elif score >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    elif score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    elif score >= SEVERITY_THRESHOLDS["low"]:
        return "low"
    return "info"
