"""Tests for the context enricher."""

import os
import tempfile
import pytest
from backend.context.enricher import enrich, _safe_read_lines


def _make_temp_file(lines):
    td = tempfile.mkdtemp()
    fpath = os.path.join(td, "sample.py")
    with open(fpath, "w") as f:
        f.write("\n".join(lines) + "\n")
    return td, "sample.py"


def test_enrich_basic():
    source = [f"line_{i}" for i in range(1, 21)]
    base_dir, rel_path = _make_temp_file(source)
    snippet = enrich(rel_path, 10, base_dir, context_lines=2)
    assert snippet is not None
    assert ">>>" in snippet
    assert "line_10" in snippet
    assert "line_8" in snippet   # context before
    assert "line_12" in snippet  # context after


def test_enrich_start_of_file():
    source = [f"line_{i}" for i in range(1, 5)]
    base_dir, rel_path = _make_temp_file(source)
    snippet = enrich(rel_path, 1, base_dir, context_lines=3)
    assert snippet is not None
    assert "line_1" in snippet


def test_enrich_nonexistent_file():
    base_dir = tempfile.mkdtemp()
    result = enrich("does_not_exist.py", 5, base_dir)
    assert result is None


def test_safe_read_prevents_traversal():
    import tempfile
    base_dir = tempfile.mkdtemp()
    # Try to read /etc/passwd via path traversal
    result = _safe_read_lines("../../etc/passwd", base_dir)
    assert result is None


def test_enrich_with_range():
    source = [f"line_{i}" for i in range(1, 20)]
    base_dir, rel_path = _make_temp_file(source)
    snippet = enrich(rel_path, 5, base_dir, context_lines=1, end_line=7)
    assert snippet is not None
    lines = snippet.split("\n")
    marked = [l for l in lines if ">>>" in l]
    assert len(marked) == 3  # lines 5, 6, 7
