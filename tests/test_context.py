"""Tests for context enricher."""
import os
import tempfile
import pytest
from backend.context import extract_code_snippet, extract_function_name, build_execution_path, enrich_finding


SAMPLE_C_CODE = """\
#include <stdio.h>
#include <string.h>

int process_data(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // line 6: vulnerable
    return strlen(buffer);
}

void main() {
    char *ptr = NULL;
    process_data(ptr);  // line 12
}
"""


@pytest.fixture
def c_file(tmp_path):
    f = tmp_path / "test.c"
    f.write_text(SAMPLE_C_CODE)
    return str(f)


class TestExtractCodeSnippet:
    def test_basic_extraction(self, c_file):
        snippet = extract_code_snippet(c_file, 6, context_lines=2)
        assert "strcpy" in snippet
        assert "6" in snippet

    def test_highlights_target_line(self, c_file):
        snippet = extract_code_snippet(c_file, 6, context_lines=2)
        assert ">>>" in snippet

    def test_missing_file(self):
        snippet = extract_code_snippet("/nonexistent/file.c", 1)
        assert "not found" in snippet.lower() or "error" in snippet.lower()

    def test_context_lines_respected(self, c_file):
        snippet = extract_code_snippet(c_file, 6, context_lines=1)
        lines = snippet.strip().split("\n")
        assert len(lines) == 3  # 1 before + target + 1 after

    def test_base_dir_resolution(self, tmp_path):
        f = tmp_path / "src" / "test.c"
        f.parent.mkdir()
        f.write_text(SAMPLE_C_CODE)
        snippet = extract_code_snippet("src/test.c", 6, context_lines=2, base_dir=str(tmp_path))
        assert "strcpy" in snippet


class TestExtractFunctionName:
    def test_find_function(self, c_file):
        fn = extract_function_name(c_file, 6)
        assert fn == "process_data"

    def test_missing_file(self):
        fn = extract_function_name("/nonexistent/file.c", 1)
        assert fn == ""

    def test_python_function(self, tmp_path):
        py_file = tmp_path / "test.py"
        py_file.write_text("def my_func(x):\n    return x + 1\n")
        fn = extract_function_name(str(py_file), 2)
        assert fn == "my_func"


class TestBuildExecutionPath:
    def test_empty_trace(self):
        path = build_execution_path([])
        assert path == []

    def test_basic_trace(self):
        trace = [
            {"file": "src/main.c", "line": 10, "msg": "ptr assigned NULL"},
            {"file": "src/main.c", "line": 20, "msg": "ptr dereferenced"},
        ]
        path = build_execution_path(trace)
        assert len(path) == 2
        assert "Step 1" in path[0]
        assert "ptr assigned NULL" in path[0]

    def test_trace_without_msg(self):
        trace = [{"file": "src/a.c", "line": 5, "msg": ""}]
        path = build_execution_path(trace)
        assert len(path) == 1
        assert "a.c:5" in path[0]


class TestEnrichFinding:
    def test_enrichment_with_real_file(self, c_file):
        finding = {
            "tool": "cppcheck",
            "rule_id": "bufferOverflow",
            "file_path": c_file,
            "line_start": 6,
            "message": "Buffer overflow",
            "sast_severity": "high",
            "code_flows": [],
        }
        enriched = enrich_finding(finding)
        assert "strcpy" in enriched.get("code_snippet", "")
        assert enriched.get("function_name") == "process_data"
        assert enriched.get("execution_path") == []

    def test_enrichment_no_file(self):
        finding = {
            "tool": "cppcheck",
            "rule_id": "test",
            "file_path": "",
            "line_start": 0,
            "message": "test",
            "sast_severity": "low",
            "code_flows": [],
        }
        enriched = enrich_finding(finding)
        assert "code_snippet" in enriched
        assert "function_name" in enriched
        assert "execution_path" in enriched
