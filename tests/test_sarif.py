"""Tests for SARIF normalization layer."""
import json
import pytest
from backend.adapters import CppcheckAdapter, RawFinding
from backend.sarif import findings_to_sarif, sarif_to_findings


CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.10"/>
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer" verbose="Detailed null pointer">
      <location file="src/main.c" line="42"/>
    </error>
    <error id="bufferOverflow" severity="warning" msg="Buffer overflow" verbose="Buffer overflow at index 10">
      <location file="src/io.c" line="100"/>
      <location file="src/io.c" line="90" msg="Buffer allocated here"/>
    </error>
  </errors>
</results>"""


def make_raw_findings():
    adapter = CppcheckAdapter()
    return adapter.parse(CPPCHECK_XML)


class TestFindingsToSarif:
    def test_structure(self):
        findings = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "cppcheck"
        assert len(run["results"]) == 2

    def test_result_fields(self):
        findings = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", findings)
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "nullPointer"
        assert result["level"] == "error"
        assert "text" in result["message"]

    def test_code_flows_included(self):
        findings = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", findings)
        # Second finding has trace
        result = sarif["runs"][0]["results"][1]
        assert "codeFlows" in result
        assert len(result["codeFlows"]) > 0

    def test_rules_deduplicated(self):
        findings = [
            RawFinding(tool="test", rule_id="RULE_A", file="a.c", line=1, message="msg1"),
            RawFinding(tool="test", rule_id="RULE_A", file="b.c", line=2, message="msg2"),
        ]
        sarif = findings_to_sarif("test", findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_empty_findings(self):
        sarif = findings_to_sarif("cppcheck", [])
        assert sarif["runs"][0]["results"] == []


class TestSarifToFindings:
    def test_round_trip(self):
        raw = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", raw)
        normalized = sarif_to_findings(sarif)
        assert len(normalized) == 2

    def test_normalized_fields(self):
        raw = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", raw)
        normalized = sarif_to_findings(sarif)
        f = normalized[0]
        assert f["tool"] == "cppcheck"
        assert f["rule_id"] == "nullPointer"
        assert f["file_path"] == "src/main.c"
        assert f["line_start"] == 42
        assert f["sast_severity"] == "high"

    def test_parse_from_string(self):
        raw = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", raw)
        normalized = sarif_to_findings(json.dumps(sarif))
        assert len(normalized) == 2

    def test_code_flows_in_trace(self):
        raw = make_raw_findings()
        sarif = findings_to_sarif("cppcheck", raw)
        normalized = sarif_to_findings(sarif)
        # Second finding has code flows
        f = normalized[1]
        assert len(f["code_flows"]) > 0
