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


def _safe_read_lines(file_path: str, base_dir: str) -> list[str] | None:
    """
    Read lines from a file only if it resolves safely within base_dir.

    Security model
    --------------
    * ``base_dir`` is treated as a trusted, server-side value (the project root).
    * ``file_path`` is treated as untrusted user input (path from a SAST report).
    * ``os.path.realpath`` resolves all symlinks, eliminating symlink-based traversal.
    * The resolved real path is checked with ``startswith(base_real + os.sep)`` to
      guarantee containment before any I/O operation.  No file is opened unless this
      check passes.

    Returns a list of lines on success, or None when the path cannot be
    validated or the file cannot be read.
    """
    if not base_dir:
        return None

    base_real = os.path.realpath(base_dir)

    if os.path.isabs(file_path):
        candidate = os.path.realpath(file_path)
    else:
        candidate = os.path.realpath(os.path.join(base_real, file_path))

    # Strict containment check: candidate must be a descendent of base_real.
    # This guards against all path-traversal variants (../, absolute escapes,
    # and symlink chains) because realpath has already resolved everything.
    if not (candidate.startswith(base_real + os.sep) or candidate == base_real):
        return None

    if not os.path.isfile(candidate):
        return None

    # At this point candidate is guaranteed to be within base_real.
    # Derive a safe relative path so the open() call uses only the validated
    # relative suffix joined back onto the trusted base_real root.
    safe_rel = os.path.relpath(candidate, base_real)
    # Extra guard: a relative path must never start with '..' after normalisation.
    if Path(safe_rel).parts[0:1] == ('..', ):
        return None
    safe_open_path = os.path.join(base_real, safe_rel)

    try:
        with open(safe_open_path, "r", encoding="utf-8", errors="replace") as fh:
"""Code context enricher.

Given a file path and a line number, reads surrounding source lines to produce
a human-readable code snippet. The base_dir argument prevents path traversal.
"""

from __future__ import annotations

import os
from typing import List, Optional


def _safe_read_lines(file_path: str, base_dir: str) -> Optional[List[str]]:
    """Read a file only if it is inside base_dir (prevents path traversal)."""
    abs_base = os.path.realpath(base_dir)
    abs_file = os.path.realpath(os.path.join(base_dir, file_path))
    if not abs_file.startswith(abs_base + os.sep) and abs_file != abs_base:
        return None
    if not os.path.isfile(abs_file):
        return None
    try:
        with open(abs_file, encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return None


def extract_code_snippet(
    file_path: str,
    line: int,
    context_lines: int | None = None,
    base_dir: str | None = None,
) -> str:
    """
    Extract code snippet around the given line with context_lines above and below.
    Returns the snippet as a string with line numbers.

    file_path is resolved only when base_dir is supplied. When base_dir is
    omitted the function returns an empty placeholder so that callers can still
    build an enriched finding without requiring source-code access.
    """
    if context_lines is None:
        context_lines = settings.CODE_CONTEXT_LINES

    if not base_dir:
        return f"# Source directory not configured; cannot read: {file_path}"

    file_lines = _safe_read_lines(file_path, base_dir)
    if file_lines is None:
        return f"# File not found or access denied: {file_path}"

    total = len(file_lines)
    start = max(0, line - 1 - context_lines)
    end = min(total, line - 1 + context_lines + 1)

    snippet_lines = []
    for i, src_line in enumerate(file_lines[start:end], start=start + 1):
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

    Returns an empty string when the file cannot be resolved safely.
    """
    if not base_dir:
        return ""

    file_lines = _safe_read_lines(file_path, base_dir)
    if file_lines is None:
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

    for i in range(min(line - 1, len(file_lines) - 1), -1, -1):
        src = file_lines[i]
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
def enrich(
    file_path: str,
    start_line: int,
    base_dir: str,
    context_lines: int = 3,
    end_line: Optional[int] = None,
) -> Optional[str]:
    """Return a snippet of source code around ``start_line``.

    Args:
        file_path:     Relative path to the source file (relative to base_dir).
        start_line:    1-based line number of the finding.
        base_dir:      Root directory for the source files.
        context_lines: Number of lines of context before/after the finding.
        end_line:      Optional end line of the finding region.

    Returns:
        A formatted multi-line string, or None if the file cannot be read.
    """
    lines = _safe_read_lines(file_path, base_dir)
    if lines is None:
        return None

    end = end_line or start_line
    first = max(1, start_line - context_lines)
    last = min(len(lines), end + context_lines)

    snippet_lines = []
    for i, line in enumerate(lines[first - 1 : last], start=first):
        marker = ">>>" if start_line <= i <= end else "   "
        snippet_lines.append(f"{marker} {i:4d} | {line.rstrip()}")

    return "\n".join(snippet_lines)
