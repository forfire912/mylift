"""
Context Enhancement Layer
Extracts code snippets, function/class context, and execution paths
from source files to enrich findings for LLM analysis.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from backend.config import get_settings

settings = get_settings()


def extract_code_snippet(
    file_path: str,
    line: int,
    context_lines: int | None = None,
    base_dir: str | None = None,
) -> str:
    """
    Extract code snippet around the given line with context_lines above and below.
    Returns the snippet as a string with line numbers.
    """
    if context_lines is None:
        context_lines = settings.CODE_CONTEXT_LINES

    resolved = _resolve_path(file_path, base_dir)
    if resolved is None:
        return f"# File not found: {file_path}"

    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return f"# Error reading file: {e}"

    total = len(lines)
    start = max(0, line - 1 - context_lines)
    end = min(total, line - 1 + context_lines + 1)

    snippet_lines = []
    for i, src_line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == line else "   "
        snippet_lines.append(f"{i:5d} {marker} {src_line.rstrip()}")

    return "\n".join(snippet_lines)


def extract_function_name(
    file_path: str,
    line: int,
    base_dir: str | None = None,
) -> str:
    """
    Attempt to identify the enclosing function/method name using simple heuristics.
    Works for C/C++, Python, Java, JavaScript.
    """
    resolved = _resolve_path(file_path, base_dir)
    if resolved is None:
        return ""

    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""

    # Walk backwards from the target line to find function/method definition
    # C/C++ / Java / JS patterns
    c_func_re = re.compile(
        r"^\s*(?:[\w:*&<>]+\s+)+(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{"
    )
    # Python pattern
    py_func_re = re.compile(r"^\s*def\s+(\w+)\s*\(")
    # Java/JS method pattern
    java_func_re = re.compile(r"^\s*(?:public|private|protected|static|final|\s)+\s+\w+\s+(\w+)\s*\(")

    for i in range(min(line - 1, len(lines) - 1), -1, -1):
        src = lines[i]
        for pattern in [py_func_re, c_func_re, java_func_re]:
            m = pattern.match(src)
            if m:
                return m.group(1)

    return ""


def build_execution_path(trace: list[dict]) -> list[str]:
    """
    Build a human-readable execution path description from trace steps.
    """
    if not trace:
        return []

    steps = []
    for i, step in enumerate(trace, 1):
        msg = step.get("msg", "")
        file_name = Path(step.get("file", "")).name
        line = step.get("line", 0)
        if msg:
            steps.append(f"Step {i}: [{file_name}:{line}] {msg}")
        else:
            steps.append(f"Step {i}: [{file_name}:{line}]")

    return steps


def enrich_finding(
    finding: dict,
    base_dir: str | None = None,
) -> dict:
    """
    Given a normalized finding dict, enrich it with code snippet,
    function name, and execution path.

    Returns an updated copy of the finding dict.
    """
    enriched = dict(finding)
    file_path = finding.get("file_path", "")
    line = finding.get("line_start", 0) or 0

    if file_path and line:
        enriched["code_snippet"] = extract_code_snippet(file_path, line, base_dir=base_dir)
        enriched["function_name"] = extract_function_name(file_path, line, base_dir=base_dir)
    else:
        enriched.setdefault("code_snippet", "")
        enriched.setdefault("function_name", "")

    code_flows = finding.get("code_flows", [])
    trace = []
    for cf in code_flows:
        for tf in cf.get("threadFlows", []):
            for loc in tf.get("locations", []):
                phys = loc.get("location", {}).get("physicalLocation", {})
                trace.append({
                    "file": phys.get("artifactLocation", {}).get("uri", ""),
                    "line": phys.get("region", {}).get("startLine", 0),
                    "msg": loc.get("location", {}).get("message", {}).get("text", ""),
                })

    enriched["execution_path"] = build_execution_path(trace)
    return enriched


def _resolve_path(file_path: str, base_dir: str | None) -> str | None:
    """Try to resolve a file path, optionally relative to base_dir."""
    if os.path.isabs(file_path) and os.path.exists(file_path):
        return file_path
    if base_dir:
        candidate = os.path.join(base_dir, file_path)
        if os.path.exists(candidate):
            return candidate
    if os.path.exists(file_path):
        return file_path
    return None
