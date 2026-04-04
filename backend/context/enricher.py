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
