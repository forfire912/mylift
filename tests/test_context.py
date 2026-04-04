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


@pytest.fixture
def c_dir(tmp_path):
    """Fixture that returns both the file path and its parent directory."""
    f = tmp_path / "test.c"
    f.write_text(SAMPLE_C_CODE)
    return str(tmp_path), str(f)


class TestExtractCodeSnippet:
    def test_basic_extraction(self, c_dir):
        base_dir, c_file = c_dir
        snippet = extract_code_snippet(c_file, 6, context_lines=2, base_dir=base_dir)
        assert "strcpy" in snippet
        assert "6" in snippet

    def test_highlights_target_line(self, c_dir):
        base_dir, c_file = c_dir
        snippet = extract_code_snippet(c_file, 6, context_lines=2, base_dir=base_dir)
        assert ">>>" in snippet

    def test_missing_file(self, tmp_path):
        snippet = extract_code_snippet("/nonexistent/file.c", 1, base_dir=str(tmp_path))
        assert "not found" in snippet.lower() or "access denied" in snippet.lower()

    def test_no_base_dir_returns_placeholder(self):
        snippet = extract_code_snippet("src/main.c", 1)
        assert "not configured" in snippet.lower() or "cannot read" in snippet.lower()

    def test_context_lines_respected(self, c_dir):
        base_dir, c_file = c_dir
        snippet = extract_code_snippet(c_file, 6, context_lines=1, base_dir=base_dir)
        lines = snippet.strip().split("\n")
        assert len(lines) == 3  # 1 before + target + 1 after

    def test_base_dir_resolution(self, tmp_path):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        f = src_dir / "test.c"
        f.write_text(SAMPLE_C_CODE)
        snippet = extract_code_snippet("src/test.c", 6, context_lines=2, base_dir=str(tmp_path))
        assert "strcpy" in snippet


class TestExtractFunctionName:
    def test_find_function(self, c_dir):
        base_dir, c_file = c_dir
        fn = extract_function_name(c_file, 6, base_dir=base_dir)
        assert fn == "process_data"

    def test_no_base_dir_returns_empty(self):
        fn = extract_function_name("src/main.c", 1)
        assert fn == ""

    def test_missing_file(self, tmp_path):
        fn = extract_function_name("/nonexistent/file.c", 1, base_dir=str(tmp_path))
        assert fn == ""

    def test_python_function(self, tmp_path):
        py_file = tmp_path / "test.py"
        py_file.write_text("def my_func(x):\n    return x + 1\n")
        fn = extract_function_name(str(py_file), 2, base_dir=str(tmp_path))
        assert fn == "my_func"


class TestPathTraversalSecurity:
    def test_base_dir_traversal_blocked(self, tmp_path):
        # Create a sensitive file outside base_dir
        sensitive = tmp_path / "sensitive.txt"
        sensitive.write_text("secret")

        # Create sub-directory as base_dir
        sub_dir = tmp_path / "sub"
        sub_dir.mkdir()
        sub_file = sub_dir / "code.c"
        sub_file.write_text("int main() { return 0; }")

        # Attempt path traversal: ../sensitive.txt
        snippet = extract_code_snippet("../sensitive.txt", 1, base_dir=str(sub_dir))
        # Should NOT return content of sensitive.txt - path traversal blocked
        assert "secret" not in snippet

    def test_base_dir_valid_file_accessible(self, tmp_path):
        sub_dir = tmp_path / "src"
        sub_dir.mkdir()
        code_file = sub_dir / "main.c"
        code_file.write_text("int main() {\n    return 0;\n}\n")

        snippet = extract_code_snippet("main.c", 1, base_dir=str(sub_dir))
        assert "main" in snippet

    def test_absolute_path_outside_base_dir_blocked(self, tmp_path):
        # Create two separate directories
        dir_a = tmp_path / "proj_a"
        dir_a.mkdir()
        dir_b = tmp_path / "proj_b"
        dir_b.mkdir()
        secret_file = dir_b / "secret.c"
        secret_file.write_text("// top secret\n")

        # Try to access a file in dir_b using base_dir of dir_a
        snippet = extract_code_snippet(str(secret_file), 1, base_dir=str(dir_a))
        assert "top secret" not in snippet


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
    def test_enrichment_with_real_file(self, tmp_path):
        c_file = tmp_path / "test.c"
        c_file.write_text(SAMPLE_C_CODE)
        finding = {
            "tool": "cppcheck",
            "rule_id": "bufferOverflow",
            "file_path": str(c_file),
            "line_start": 6,
            "message": "Buffer overflow",
            "sast_severity": "high",
            "code_flows": [],
        }
        enriched = enrich_finding(finding, base_dir=str(tmp_path))
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

    def test_enrichment_without_base_dir(self):
        finding = {
            "tool": "cppcheck",
            "rule_id": "test",
            "file_path": "src/main.c",
            "line_start": 10,
            "message": "test",
            "sast_severity": "medium",
            "code_flows": [],
        }
        enriched = enrich_finding(finding)
        # Without base_dir, should still return a finding (with placeholder code_snippet)
        assert "code_snippet" in enriched
        assert enriched["function_name"] == ""
