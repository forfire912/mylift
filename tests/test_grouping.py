from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend.grouping as grouping
from backend.models import Base, Finding, IssueGroup, ScanTask


def _setup_grouping_db(tmp_path, monkeypatch):
    db_file = tmp_path / "grouping.db"
    test_engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    monkeypatch.setattr(grouping, "engine", test_engine)
    monkeypatch.setattr(grouping, "SessionLocal", TestingSessionLocal)
    return TestingSessionLocal


def test_sync_issue_group_flushes_pending_member_assignments(tmp_path, monkeypatch):
    session_factory = _setup_grouping_db(tmp_path, monkeypatch)
    db = session_factory()
    try:
        task = ScanTask(name="grouping-test", tool="cppcheck", status="parsed", raw_input="", sarif_output="{}")
        db.add(task)
        db.flush()

        finding1 = Finding(task_id=task.id, tool="cppcheck", rule_id="dup", file_path="a.cpp", line_start=10, message="dup")
        finding2 = Finding(task_id=task.id, tool="cppcheck", rule_id="dup", file_path="a.cpp", line_start=10, message="dup")
        db.add_all([finding1, finding2])
        db.flush()

        group = IssueGroup(
            task_id=task.id,
            merge_key="cppcheck|dup|a.cpp|10|dup",
            tool="cppcheck",
            rule_id="dup",
            file_path="a.cpp",
            line_start=10,
            message="dup",
            representative_finding_id=finding1.id,
            member_count=2,
        )
        db.add(group)
        db.flush()

        finding1.issue_group_id = group.id
        finding1.is_representative = True
        finding2.issue_group_id = group.id
        finding2.is_representative = False

        synced = grouping.sync_issue_group(group.id, db)

        assert synced is not None
        assert synced.member_count == 2
    finally:
        db.close()