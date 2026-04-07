from __future__ import annotations

import copy
import datetime

from sqlalchemy import func

from backend.database import engine, SessionLocal
from backend.models import Finding, ScanTask, TaskAnalysisProgress

AGENT_META = {
    1: "代码理解",
    2: "路径分析",
    3: "漏洞判定",
    4: "修复建议",
}


def _default_agents() -> dict[str, dict]:
    return {
        str(i): {
            "label": label,
            "status": "pending",
            "output": "",
            "started_at": None,
            "finished_at": None,
        }
        for i, label in AGENT_META.items()
    }


def _empty_progress(task_id: int, total: int = 0, status: str = "not_started") -> dict:
    return {
        "task_id": task_id,
        "status": status,
        "finding_total": total,
        "finding_current": 0,
        "current_agent": 0,
        "started_at": None,
        "finished_at": None,
        "agents": {},
    }


def _ensure_progress_table() -> None:
    TaskAnalysisProgress.__table__.create(bind=engine, checkfirst=True)


def init_task_progress(task_id: int, total: int) -> None:
    _ensure_progress_table()
    db = SessionLocal()
    try:
        record = db.query(TaskAnalysisProgress).filter(TaskAnalysisProgress.task_id == task_id).first()
        if record is None:
            record = TaskAnalysisProgress(task_id=task_id)
            db.add(record)
        record.status = "running"
        record.finding_total = total
        record.finding_current = 0
        record.current_agent = 0
        record.started_at = datetime.datetime.utcnow()
        record.finished_at = None
        record.agents = _default_agents()
        db.commit()
    finally:
        db.close()


def set_agent_status(
    task_id: int,
    agent_num: int,
    status: str,
    output: str | None = None,
    finding_current: int | None = None,
) -> None:
    _ensure_progress_table()
    db = SessionLocal()
    try:
        record = db.query(TaskAnalysisProgress).filter(TaskAnalysisProgress.task_id == task_id).first()
        if record is None:
            return
        agents = copy.deepcopy(record.agents or _default_agents())
        agent = agents.get(str(agent_num), {
            "label": AGENT_META.get(agent_num, f"Agent {agent_num}"),
            "status": "pending",
            "output": "",
            "started_at": None,
            "finished_at": None,
        })
        agent["status"] = status
        if output is not None:
            agent["output"] = output[:2000]
        now = datetime.datetime.utcnow().isoformat()
        if status == "running":
            agent["started_at"] = now
            agent["finished_at"] = None
            record.current_agent = agent_num
        elif status in ("done", "error"):
            agent["finished_at"] = now
        if finding_current is not None:
            record.finding_current = finding_current
        agents[str(agent_num)] = agent
        record.agents = agents
        db.commit()
    finally:
        db.close()


def finish_task_progress(task_id: int, status: str = "done") -> None:
    _ensure_progress_table()
    db = SessionLocal()
    try:
        record = db.query(TaskAnalysisProgress).filter(TaskAnalysisProgress.task_id == task_id).first()
        if record is None:
            return
        if status == "done":
            record.finding_current = record.finding_total
        record.status = status
        record.current_agent = 0
        record.finished_at = datetime.datetime.utcnow()
        db.commit()
    finally:
        db.close()


def clear_task_progress(task_id: int | None = None) -> None:
    _ensure_progress_table()
    db = SessionLocal()
    try:
        query = db.query(TaskAnalysisProgress)
        if task_id is not None:
            query = query.filter(TaskAnalysisProgress.task_id == task_id)
        query.delete()
        db.commit()
    finally:
        db.close()


def get_task_progress_snapshot(task_id: int) -> dict:
    _ensure_progress_table()
    db = SessionLocal()
    try:
        record = db.query(TaskAnalysisProgress).filter(TaskAnalysisProgress.task_id == task_id).first()
        if record is not None:
            return {
                "task_id": task_id,
                "status": record.status,
                "finding_total": record.finding_total,
                "finding_current": record.finding_current,
                "current_agent": record.current_agent,
                "started_at": record.started_at.isoformat() if record.started_at else None,
                "finished_at": record.finished_at.isoformat() if record.finished_at else None,
                "agents": copy.deepcopy(record.agents or {}),
            }

        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task is None:
            return _empty_progress(task_id)

        total = db.query(func.count(Finding.id)).filter(Finding.task_id == task_id).scalar() or 0
        analyzed = (
            db.query(func.count(Finding.id))
            .filter(Finding.task_id == task_id, Finding.analyzed_at.isnot(None))
            .scalar()
            or 0
        )
        if task.status == "analyzed":
            progress = _empty_progress(task_id, total, "done")
            progress["finding_current"] = total
            progress["finished_at"] = task.updated_at.isoformat() if task.updated_at else None
            return progress
        if task.status == "analyzing":
            progress = _empty_progress(task_id, total, "running")
            progress["finding_current"] = analyzed
            progress["started_at"] = task.updated_at.isoformat() if task.updated_at else None
            return progress
        return _empty_progress(task_id, total, "pending" if total > 0 else "not_started")
    finally:
        db.close()