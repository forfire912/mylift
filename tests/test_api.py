"""Integration tests for the FastAPI application."""

import io
import json
import pytest
from fastapi.testclient import TestClient

# Use an in-memory SQLite DB for tests
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_mylift.db"

from backend.main import app
from backend.database import create_tables, engine, Base

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


SARIF_PAYLOAD = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "TestScanner", "rules": []}},
            "results": [
                {
                    "ruleId": "S001",
                    "level": "warning",
                    "message": {"text": "Test finding"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.py"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

SEMGREP_PAYLOAD = {
    "results": [
        {
            "check_id": "test.rule",
            "path": "app.py",
            "start": {"line": 5, "col": 1},
            "end": {"line": 5, "col": 20},
            "extra": {"severity": "ERROR", "message": "Test semgrep finding", "lines": "eval(x)"},
        }
    ],
    "errors": [],
}


def _upload(payload: dict, filename: str = "report.sarif") -> dict:
    content = json.dumps(payload).encode()
    response = client.post(
        "/api/upload",
        files={"file": (filename, io.BytesIO(content), "application/json")},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_upload_sarif():
    result = _upload(SARIF_PAYLOAD, "scan.sarif")
    assert result["format"] == "sarif"
    assert result["tool"] == "TestScanner"
    assert result["vulnerability_count"] == 1


def test_upload_semgrep():
    result = _upload(SEMGREP_PAYLOAD, "semgrep.json")
    assert result["tool"] == "Semgrep"
    assert result["vulnerability_count"] == 1


def test_list_reports_empty():
    resp = client.get("/api/reports")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_reports_after_upload():
    _upload(SARIF_PAYLOAD, "scan.sarif")
    resp = client.get("/api/reports")
    assert resp.status_code == 200
    reports = resp.json()
    assert len(reports) == 1
    assert reports[0]["tool"] == "TestScanner"
    assert reports[0]["vulnerability_count"] == 1


def test_get_report_detail():
    uploaded = _upload(SARIF_PAYLOAD, "scan.sarif")
    rid = uploaded["report_id"]
    resp = client.get(f"/api/reports/{rid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == rid
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["rule_id"] == "S001"


def test_get_report_not_found():
    resp = client.get("/api/reports/9999")
    assert resp.status_code == 404


def test_list_vulnerabilities():
    uploaded = _upload(SARIF_PAYLOAD, "scan.sarif")
    rid = uploaded["report_id"]
    resp = client.get(f"/api/reports/{rid}/vulnerabilities")
    assert resp.status_code == 200
    vulns = resp.json()
    assert len(vulns) == 1


def test_filter_vulnerabilities_by_severity():
    uploaded = _upload(SARIF_PAYLOAD, "scan.sarif")
    rid = uploaded["report_id"]

    resp = client.get(f"/api/reports/{rid}/vulnerabilities?severity=medium")
    assert resp.status_code == 200
    assert len(resp.json()) == 1  # "warning" maps to "medium"

    resp = client.get(f"/api/reports/{rid}/vulnerabilities?severity=high")
    assert resp.status_code == 200
    assert len(resp.json()) == 0


def test_delete_report():
    uploaded = _upload(SARIF_PAYLOAD, "scan.sarif")
    rid = uploaded["report_id"]
    resp = client.delete(f"/api/reports/{rid}")
    assert resp.status_code == 204
    # confirm gone
    assert client.get(f"/api/reports/{rid}").status_code == 404


def test_stats():
    _upload(SARIF_PAYLOAD, "scan.sarif")
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_reports"] == 1
    assert data["total_vulnerabilities"] == 1
    assert "medium" in data["by_severity"]


def test_upload_invalid_json():
    resp = client.post(
        "/api/upload",
        files={"file": ("bad.json", io.BytesIO(b"not json at all"), "application/json")},
    )
    assert resp.status_code == 400


def test_upload_unsupported_format():
    resp = client.post(
        "/api/upload",
        files={"file": ("report.xml", io.BytesIO(b"<xml/>"), "application/xml")},
    )
    assert resp.status_code == 400
