from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.models import Base, Finding, ScanTask, TaskAnalysisProgress
import backend.progress as progress


def _setup_progress_db(tmp_path, monkeypatch):
    db_file = tmp_path / "progress.db"
    test_engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    monkeypatch.setattr(progress, "engine", test_engine)
    monkeypatch.setattr(progress, "SessionLocal", TestingSessionLocal)
    return TestingSessionLocal


def test_recover_interrupted_progress_marks_running_task_as_error(tmp_path, monkeypatch):
    session_factory = _setup_progress_db(tmp_path, monkeypatch)

    db = session_factory()
    try:
        task = ScanTask(name="stale task", tool="cppcheck", status="analyzing", raw_input="", sarif_output="{}")
        db.add(task)
        db.flush()

        db.add(Finding(task_id=task.id, tool="cppcheck", message="first"))
        db.add(Finding(task_id=task.id, tool="cppcheck", message="second"))
        db.add(TaskAnalysisProgress(
            task_id=task.id,
            status="running",
            finding_total=2,
            finding_current=1,
            current_agent=3,
            agents={
                "1": {"label": "代码理解", "status": "done", "output": "ok", "started_at": None, "finished_at": None},
                "2": {"label": "路径分析", "status": "done", "output": "ok", "started_at": None, "finished_at": None},
                "3": {"label": "漏洞判定", "status": "running", "output": "处理中", "started_at": None, "finished_at": None},
                "4": {"label": "修复建议", "status": "pending", "output": "", "started_at": None, "finished_at": None},
            },
        ))
        db.commit()
    finally:
        db.close()

    recovered = progress.recover_interrupted_progress()
    assert recovered == 1

    verify = session_factory()
    try:
        task = verify.query(ScanTask).first()
        record = verify.query(TaskAnalysisProgress).first()
        assert task.status == "error"
        assert record.status == "error"
        assert record.current_agent == 0
        assert record.agents["3"]["status"] == "error"
        assert "服务重启导致分析中断" in record.agents["3"]["output"]
    finally:
        verify.close()


def test_get_task_progress_snapshot_reconciles_stale_running_record(tmp_path, monkeypatch):
    session_factory = _setup_progress_db(tmp_path, monkeypatch)

    db = session_factory()
    try:
        task = ScanTask(name="finished task", tool="cppcheck", status="parsed", raw_input="", sarif_output="{}")
        db.add(task)
        db.flush()
        task_id = task.id

        finding = Finding(task_id=task_id, tool="cppcheck", message="only", analyzed_at=progress.utc_now())
        db.add(finding)
        db.add(TaskAnalysisProgress(
            task_id=task_id,
            status="running",
            finding_total=1,
            finding_current=0,
            current_agent=2,
            agents={
                "1": {"label": "代码理解", "status": "done", "output": "ok", "started_at": None, "finished_at": None},
                "2": {"label": "路径分析", "status": "running", "output": "处理中", "started_at": None, "finished_at": None},
            },
        ))
        db.commit()
    finally:
        db.close()

    snapshot = progress.get_task_progress_snapshot(task_id)
    assert snapshot["status"] == "error"
    assert snapshot["finding_current"] == 1
    assert snapshot["current_agent"] == 0
    assert snapshot["agents"]["2"]["status"] == "error"


def test_recover_interrupted_progress_fixes_terminal_record_with_running_agent(tmp_path, monkeypatch):
    session_factory = _setup_progress_db(tmp_path, monkeypatch)

    db = session_factory()
    try:
        task = ScanTask(name="inconsistent task", tool="cppcheck", status="analyzed", raw_input="", sarif_output="{}")
        db.add(task)
        db.flush()
        task_id = task.id

        db.add(Finding(task_id=task_id, tool="cppcheck", message="one", analyzed_at=progress.utc_now()))
        db.add(TaskAnalysisProgress(
            task_id=task_id,
            status="done",
            finding_total=1,
            finding_current=1,
            current_agent=0,
            agents={
                "1": {"label": "代码理解", "status": "done", "output": "ok", "started_at": None, "finished_at": None},
                "2": {"label": "路径分析", "status": "done", "output": "ok", "started_at": None, "finished_at": None},
                "3": {"label": "漏洞判定", "status": "running", "output": "处理中", "started_at": None, "finished_at": None},
                "4": {"label": "修复建议", "status": "pending", "output": "", "started_at": None, "finished_at": None},
            },
        ))
        db.commit()
    finally:
        db.close()

    recovered = progress.recover_interrupted_progress()
    assert recovered == 1

    verify = session_factory()
    try:
        task = verify.query(ScanTask).filter(ScanTask.id == task_id).first()
        record = verify.query(TaskAnalysisProgress).filter(TaskAnalysisProgress.task_id == task_id).first()
        assert task.status == "error"
        assert record.status == "error"
        assert record.agents["3"]["status"] == "error"
        assert "服务重启导致分析中断" in record.agents["3"]["output"]
    finally:
        verify.close()