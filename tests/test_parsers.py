"""Tests for SARIF and JSON parsers."""

import pytest
from backend.parsers import sarif as sarif_parser
from backend.parsers import json_parser


# ---------------------------------------------------------------------------
# SARIF parser
# ---------------------------------------------------------------------------

SARIF_SAMPLE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [
                        {
                            "id": "RULE001",
                            "defaultConfiguration": {"level": "error"},
                            "properties": {"tags": ["CWE-89", "injection"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "RULE001",
                    "level": "error",
                    "message": {"text": "SQL injection detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.py"},
                                "region": {
                                    "startLine": 42,
                                    "endLine": 42,
                                    "startColumn": 5,
                                },
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_sarif_tool_name():
    result = sarif_parser.parse(SARIF_SAMPLE)
    assert result["tool"] == "TestTool"


def test_sarif_vulnerability_count():
    result = sarif_parser.parse(SARIF_SAMPLE)
    assert len(result["vulnerabilities"]) == 1


def test_sarif_vuln_fields():
    vuln = sarif_parser.parse(SARIF_SAMPLE)["vulnerabilities"][0]
    assert vuln["rule_id"] == "RULE001"
    assert vuln["severity"] == "high"
    assert vuln["file_path"] == "src/db.py"
    assert vuln["start_line"] == 42
    assert vuln["cwe"] == "CWE-89"


def test_sarif_empty_runs():
    result = sarif_parser.parse({"version": "2.1.0", "runs": []})
    assert result["vulnerabilities"] == []


def test_sarif_no_runs_key():
    result = sarif_parser.parse({})
    assert result["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# Semgrep JSON parser
# ---------------------------------------------------------------------------

SEMGREP_SAMPLE = {
    "results": [
        {
            "check_id": "python.flask.security.xss",
            "path": "app.py",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 30},
            "extra": {
                "severity": "WARNING",
                "message": "Potential XSS vulnerability",
                "lines": "return render_template_string(user_input)",
            },
        }
    ],
    "errors": [],
}


def test_semgrep_detection():
    result = json_parser.parse(SEMGREP_SAMPLE)
    assert result["tool"] == "Semgrep"


def test_semgrep_fields():
    vuln = json_parser.parse(SEMGREP_SAMPLE)["vulnerabilities"][0]
    assert vuln["rule_id"] == "python.flask.security.xss"
    assert vuln["severity"] == "medium"
    assert vuln["file_path"] == "app.py"
    assert vuln["start_line"] == 10


# ---------------------------------------------------------------------------
# Bandit JSON parser
# ---------------------------------------------------------------------------

BANDIT_SAMPLE = {
    "errors": [],
    "generated_at": "2024-01-01T00:00:00Z",
    "metrics": {"_totals": {}},
    "results": [
        {
            "test_id": "B608",
            "test_name": "hardcoded_sql_expressions",
            "issue_severity": "MEDIUM",
            "issue_confidence": "MEDIUM",
            "issue_text": "Possible SQL injection via string-based query construction.",
            "filename": "src/models.py",
            "line_number": 55,
            "line_range": [55, 57],
            "code": "cursor.execute('SELECT * FROM users WHERE id = ' + uid)",
            "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
        }
    ],
}


def test_bandit_detection():
    result = json_parser.parse(BANDIT_SAMPLE)
    assert result["tool"] == "Bandit"


def test_bandit_fields():
    vuln = json_parser.parse(BANDIT_SAMPLE)["vulnerabilities"][0]
    assert vuln["rule_id"] == "B608"
    assert vuln["severity"] == "medium"
    assert vuln["cwe"] == "CWE-89"
    assert vuln["start_line"] == 55


# ---------------------------------------------------------------------------
# Generic JSON fallback
# ---------------------------------------------------------------------------

GENERIC_SAMPLE = {
    "findings": [
        {
            "id": "CUSTOM-01",
            "severity": "high",
            "message": "Hardcoded secret",
            "file_path": "config.py",
            "start_line": 3,
        }
    ]
}


def test_generic_fallback():
    result = json_parser.parse(GENERIC_SAMPLE)
    assert len(result["vulnerabilities"]) == 1
    vuln = result["vulnerabilities"][0]
    assert vuln["severity"] == "high"
    assert vuln["file_path"] == "config.py"
