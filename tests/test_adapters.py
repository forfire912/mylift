"""Tests for SAST adapters."""
import pytest
from backend.adapters import CppcheckAdapter, CoverityAdapter, KlocworkAdapter, get_adapter


CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.10"/>
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer dereference" verbose="Possible null pointer dereference: ptr">
      <location file="src/main.c" line="42" column="5"/>
      <location file="src/main.c" line="35" column="15" msg="Assignment of ptr"/>
    </error>
    <error id="memoryLeak" severity="warning" msg="Memory leak: buf" verbose="Memory leak: buf allocated but not freed">
      <location file="src/utils.c" line="100"/>
    </error>
  </errors>
</results>"""


COVERITY_JSON = """[
  {
    "cid": 12345,
    "checkerName": "NULL_RETURNS",
    "impact": "High",
    "events": [
      {
        "main": true,
        "strippedFilePathname": "src/foo.c",
        "lineNumber": 55,
        "eventDescription": "Null pointer dereference of returned value"
      },
      {
        "main": false,
        "strippedFilePathname": "src/foo.c",
        "lineNumber": 50,
        "eventDescription": "Function returns null"
      }
    ]
  }
]"""


KLOCWORK_JSON = """[
  {
    "id": "KW001",
    "code": "NPD.FUNC.MUST",
    "severity": 2,
    "file": "src/bar.cpp",
    "line": 78,
    "message": "Null pointer dereference"
  }
]"""


class TestCppcheckAdapter:
    def test_parse_basic(self):
        adapter = CppcheckAdapter()
        findings = adapter.parse(CPPCHECK_XML)
        assert len(findings) == 2

    def test_null_pointer_finding(self):
        adapter = CppcheckAdapter()
        findings = adapter.parse(CPPCHECK_XML)
        f = findings[0]
        assert f.rule_id == "nullPointer"
        assert f.file == "src/main.c"
        assert f.line == 42
        assert f.severity == "high"
        assert len(f.trace) == 1

    def test_warning_severity(self):
        adapter = CppcheckAdapter()
        findings = adapter.parse(CPPCHECK_XML)
        assert findings[1].severity == "medium"

    def test_invalid_xml(self):
        adapter = CppcheckAdapter()
        findings = adapter.parse("not xml")
        assert findings == []

    def test_tool_name(self):
        assert CppcheckAdapter.TOOL_NAME == "cppcheck"


class TestCoverityAdapter:
    def test_parse_basic(self):
        adapter = CoverityAdapter()
        findings = adapter.parse(COVERITY_JSON)
        assert len(findings) == 1

    def test_finding_details(self):
        adapter = CoverityAdapter()
        f = adapter.parse(COVERITY_JSON)[0]
        assert f.rule_id == "NULL_RETURNS"
        assert f.file == "src/foo.c"
        assert f.line == 55
        assert f.severity == "high"
        assert len(f.trace) == 1

    def test_parse_dict(self):
        import json
        adapter = CoverityAdapter()
        findings = adapter.parse(json.loads(COVERITY_JSON))
        assert len(findings) == 1

    def test_invalid_json(self):
        adapter = CoverityAdapter()
        findings = adapter.parse("not json")
        assert findings == []


class TestKlocworkAdapter:
    def test_parse_basic(self):
        adapter = KlocworkAdapter()
        findings = adapter.parse(KLOCWORK_JSON)
        assert len(findings) == 1

    def test_finding_details(self):
        adapter = KlocworkAdapter()
        f = adapter.parse(KLOCWORK_JSON)[0]
        assert f.rule_id == "NPD.FUNC.MUST"
        assert f.file == "src/bar.cpp"
        assert f.line == 78
        assert f.severity == "high"

    def test_tool_name(self):
        assert KlocworkAdapter.TOOL_NAME == "klocwork"


class TestGetAdapter:
    def test_valid_tools(self):
        for tool in ["cppcheck", "coverity", "klocwork"]:
            adapter = get_adapter(tool)
            assert adapter is not None

    def test_case_insensitive(self):
        adapter = get_adapter("Cppcheck")
        assert isinstance(adapter, CppcheckAdapter)

    def test_invalid_tool(self):
        with pytest.raises(ValueError, match="Unsupported tool"):
            get_adapter("unknown_tool")
