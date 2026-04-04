"""Tests for LLM agents (mocked OpenAI calls)."""
import json
import pytest
from unittest.mock import MagicMock, patch
from backend.agents.llm_agents import (
    agent_code_understanding,
    agent_path_analysis,
    agent_vulnerability_judgment,
    agent_fix_suggestion,
    run_analysis_pipeline,
    _extract_json,
)


SAMPLE_FINDING = {
    "tool": "cppcheck",
    "rule_id": "nullPointer",
    "file_path": "src/main.c",
    "line_start": 42,
    "message": "Possible null pointer dereference: ptr",
    "sast_severity": "high",
    "code_snippet": "  42 >>>   *ptr = value;\n  43       return 0;",
    "function_name": "process_data",
    "execution_path": ["Step 1: [main.c:35] ptr assigned NULL", "Step 2: [main.c:42] ptr dereferenced"],
    "code_flows": [],
}


def make_mock_client(return_text: str):
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = return_text
    mock_client.chat.completions.create.return_value = mock_response
    return mock_client


class TestExtractJson:
    def test_direct_json(self):
        result = _extract_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_in_code_block(self):
        text = '```json\n{"is_vulnerable": true}\n```'
        result = _extract_json(text)
        assert result["is_vulnerable"] is True

    def test_json_embedded_in_text(self):
        text = 'The result is: {"confidence": 0.8} based on analysis.'
        result = _extract_json(text)
        assert result["confidence"] == 0.8

    def test_invalid_json(self):
        result = _extract_json("This is not JSON at all")
        assert result == {}


class TestAgent1CodeUnderstanding:
    def test_returns_string(self):
        client = make_mock_client("Variable ptr is assigned NULL at line 35.")
        result = agent_code_understanding(SAMPLE_FINDING, client)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_uses_finding_data(self):
        client = make_mock_client("analysis result")
        agent_code_understanding(SAMPLE_FINDING, client)
        call_args = client.chat.completions.create.call_args
        messages = call_args[1]["messages"]
        assert any("nullPointer" in str(m) or "src/main.c" in str(m) for m in messages)

    def test_handles_llm_error(self):
        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("API Error")
        result = agent_code_understanding(SAMPLE_FINDING, client)
        assert "Error" in result or "error" in result.lower()


class TestAgent2PathAnalysis:
    def test_returns_string(self):
        client = make_mock_client("The path is feasible. No guard condition found.")
        result = agent_path_analysis(SAMPLE_FINDING, "ptr is null", client)
        assert isinstance(result, str)

    def test_includes_execution_path(self):
        client = make_mock_client("path analysis")
        agent_path_analysis(SAMPLE_FINDING, "code understanding", client)
        call_args = client.chat.completions.create.call_args
        messages = call_args[1]["messages"]
        assert any("Step 1" in str(m) for m in messages)


class TestAgent3VulnerabilityJudgment:
    def test_returns_dict(self):
        response = '{"is_vulnerable": true, "confidence": 0.85, "reason": "No null check"}'
        client = make_mock_client(response)
        result = agent_vulnerability_judgment(SAMPLE_FINDING, "code", "path", client)
        assert isinstance(result, dict)
        assert "is_vulnerable" in result
        assert "confidence" in result
        assert "reason" in result

    def test_vulnerable_true(self):
        response = '{"is_vulnerable": true, "confidence": 0.9, "reason": "confirmed"}'
        client = make_mock_client(response)
        result = agent_vulnerability_judgment(SAMPLE_FINDING, "code", "path", client)
        assert result["is_vulnerable"] is True
        assert result["confidence"] == 0.9

    def test_false_positive(self):
        response = '{"is_vulnerable": false, "confidence": 0.7, "reason": "guard present"}'
        client = make_mock_client(response)
        result = agent_vulnerability_judgment(SAMPLE_FINDING, "code", "path", client)
        assert result["is_vulnerable"] is False

    def test_handles_malformed_json(self):
        client = make_mock_client("This is not valid JSON at all!")
        result = agent_vulnerability_judgment(SAMPLE_FINDING, "code", "path", client)
        assert isinstance(result, dict)
        assert "is_vulnerable" in result

    def test_handles_llm_error(self):
        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("Timeout")
        result = agent_vulnerability_judgment(SAMPLE_FINDING, "code", "path", client)
        assert result["confidence"] == 0.5


class TestAgent4FixSuggestion:
    JUDGMENT = {"is_vulnerable": True, "confidence": 0.9, "reason": "No null check before deref"}

    def test_returns_dict(self):
        fix_text = "Add null check: if (ptr != NULL) { *ptr = value; }"
        client = make_mock_client(fix_text)
        result = agent_fix_suggestion(SAMPLE_FINDING, self.JUDGMENT, client)
        assert isinstance(result, dict)
        assert "fix_suggestion" in result
        assert "patch_suggestion" in result

    def test_extracts_patch(self):
        fix_text = "Fix it:\n```c\nif (ptr) { *ptr = val; }\n```"
        client = make_mock_client(fix_text)
        result = agent_fix_suggestion(SAMPLE_FINDING, self.JUDGMENT, client)
        assert "ptr" in result["patch_suggestion"]

    def test_handles_error(self):
        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("API Error")
        result = agent_fix_suggestion(SAMPLE_FINDING, self.JUDGMENT, client)
        assert "unavailable" in result["fix_suggestion"].lower() or "error" in result["fix_suggestion"].lower()


class TestRunAnalysisPipeline:
    def test_pipeline_returns_enriched_finding(self):
        responses = [
            "Variable ptr is null.",
            "Path is feasible.",
            '{"is_vulnerable": true, "confidence": 0.85, "reason": "No guard"}',
            "Add null check: ```c\nif(ptr){}\n```",
        ]
        call_count = 0

        def mock_create(**kwargs):
            nonlocal call_count
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return mock_response

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = mock_create

        with patch("backend.agents.llm_agents._get_client", return_value=mock_client):
            result = run_analysis_pipeline(SAMPLE_FINDING)

        assert "llm_code_understanding" in result
        assert "llm_path_analysis" in result
        assert "is_vulnerable" in result
        assert "llm_confidence" in result
        assert "fix_suggestion" in result
        assert "patch_suggestion" in result
