"""Integration tests for the FastAPI application."""
import pytest
import json
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import get_db
from backend.models import Base


# Test database
TEST_DB_URL = "sqlite:///./test_mylift.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c

    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.10"/>
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer dereference" verbose="Possible null pointer dereference: ptr">
      <location file="src/main.c" line="42" column="5"/>
    </error>
    <error id="memoryLeak" severity="warning" msg="Memory leak: buf" verbose="Memory leak">
      <location file="src/utils.c" line="100"/>
    </error>
  </errors>
</results>"""


class TestCreateTask:
    def test_create_task_success(self, client):
        resp = client.post("/api/v1/tasks", json={
            "name": "Test Cppcheck Scan",
            "tool": "cppcheck",
            "raw_input": CPPCHECK_XML,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Cppcheck Scan"
        assert data["tool"] == "cppcheck"
        assert data["finding_count"] == 2
        assert data["status"] == "parsed"

    def test_create_task_invalid_tool(self, client):
        resp = client.post("/api/v1/tasks", json={
            "name": "Bad Tool",
            "tool": "unknown_tool",
            "raw_input": "data",
        })
        assert resp.status_code == 422

    def test_create_task_invalid_input(self, client):
        resp = client.post("/api/v1/tasks", json={
            "name": "Empty input",
            "tool": "cppcheck",
            "raw_input": "<results><errors></errors></results>",
        })
        assert resp.status_code == 422


class TestListTasks:
    def test_list_tasks(self, client):
        resp = client.get("/api/v1/tasks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_task(self, client):
        # Create a task first
        create_resp = client.post("/api/v1/tasks", json={
            "name": "Task for get test",
            "tool": "cppcheck",
            "raw_input": CPPCHECK_XML,
        })
        task_id = create_resp.json()["id"]

        resp = client.get(f"/api/v1/tasks/{task_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == task_id

    def test_get_task_not_found(self, client):
        resp = client.get("/api/v1/tasks/99999")
        assert resp.status_code == 404


class TestFindings:
    @pytest.fixture(autouse=True)
    def create_task(self, client):
        resp = client.post("/api/v1/tasks", json={
            "name": "Findings test task",
            "tool": "cppcheck",
            "raw_input": CPPCHECK_XML,
        })
        self.task_id = resp.json()["id"]

    def test_list_findings(self, client):
        resp = client.get(f"/api/v1/findings?task_id={self.task_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_findings_pagination(self, client):
        resp = client.get(f"/api/v1/findings?task_id={self.task_id}&page=1&page_size=1")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["total"] == 2

    def test_get_finding(self, client):
        list_resp = client.get(f"/api/v1/findings?task_id={self.task_id}")
        finding_id = list_resp.json()["items"][0]["id"]

        resp = client.get(f"/api/v1/findings/{finding_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == finding_id

    def test_get_finding_not_found(self, client):
        resp = client.get("/api/v1/findings/99999")
        assert resp.status_code == 404

    def test_mark_false_positive(self, client):
        list_resp = client.get(f"/api/v1/findings?task_id={self.task_id}")
        finding_id = list_resp.json()["items"][0]["id"]

        resp = client.patch(f"/api/v1/findings/{finding_id}/false-positive?is_false_positive=true")
        assert resp.status_code == 200
        assert resp.json()["is_false_positive"] is True

        # Revert
        resp2 = client.patch(f"/api/v1/findings/{finding_id}/false-positive?is_false_positive=false")
        assert resp2.json()["is_false_positive"] is False

    def test_filter_by_tool(self, client):
        resp = client.get(f"/api/v1/findings?task_id={self.task_id}&tool=cppcheck")
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["tool"] == "cppcheck"


class TestStats:
    def test_get_stats(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_findings" in data
        assert "false_positive_rate" in data
        assert "severity_distribution" in data
        assert "tool_distribution" in data

    def test_get_stats_filtered(self, client):
        create_resp = client.post("/api/v1/tasks", json={
            "name": "Stats test",
            "tool": "cppcheck",
            "raw_input": CPPCHECK_XML,
        })
        task_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/stats?task_id={task_id}")
        assert resp.status_code == 200
        assert resp.json()["total_findings"] == 2


class TestCoverityIntegration:
    COVERITY_JSON = json.dumps([
        {
            "cid": 1,
            "checkerName": "NULL_RETURNS",
            "impact": "High",
            "events": [
                {"main": True, "strippedFilePathname": "src/a.c", "lineNumber": 10, "eventDescription": "Null deref"},
            ]
        }
    ])

    def test_coverity_task(self, client):
        resp = client.post("/api/v1/tasks", json={
            "name": "Coverity scan",
            "tool": "coverity",
            "raw_input": self.COVERITY_JSON,
        })
        assert resp.status_code == 201
        assert resp.json()["finding_count"] == 1


class TestKlocworkIntegration:
    KLOCWORK_JSON = json.dumps([
        {"id": "1", "code": "NPD.FUNC.MUST", "severity": 2, "file": "src/a.c", "line": 15, "message": "NPD"}
    ])

    def test_klocwork_task(self, client):
        resp = client.post("/api/v1/tasks", json={
            "name": "Klocwork scan",
            "tool": "klocwork",
            "raw_input": self.KLOCWORK_JSON,
        })
        assert resp.status_code == 201
        assert resp.json()["finding_count"] == 1


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
