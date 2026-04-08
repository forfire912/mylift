from __future__ import annotations

import copy

from sqlalchemy import func

from backend.database import engine, SessionLocal
from backend.models import Finding, ScanTask, TaskAnalysisProgress
from backend.timeutils import utc_now, utc_now_iso

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


def _mark_running_agents_interrupted(agents: dict[str, dict] | None) -> dict[str, dict]:
    normalized = copy.deepcopy(agents or _default_agents())
    now = utc_now_iso()
    for agent in normalized.values():
        status = agent.get("status")
        if status not in ("running", "pending"):
            continue
        agent["status"] = "error"
        agent["finished_at"] = now
        existing_output = (agent.get("output") or "").strip()
        interrupt_note = "服务重启导致分析中断，请重新发起分析。" if status == "running" else "服务重启导致分析未完成。"
        agent["output"] = f"{existing_output}\n{interrupt_note}".strip()
    return normalized


def _has_running_agent(agents: dict[str, dict] | None) -> bool:
    return any((agent or {}).get("status") == "running" for agent in (agents or {}).values())


def _has_unfinished_agent(agents: dict[str, dict] | None) -> bool:
    return any((agent or {}).get("status") in ("running", "pending") for agent in (agents or {}).values())


def _normalize_stale_progress_record(record: TaskAnalysisProgress, analyzed: int, total: int) -> None:
    record.status = "error"
    record.finding_total = total
    record.finding_current = analyzed
    record.current_agent = 0
    record.finished_at = utc_now()
    record.agents = _mark_running_agents_interrupted(record.agents)


def recover_interrupted_progress() -> int:
    _ensure_progress_table()
    db = SessionLocal()
    try:
        running_records = (
            db.query(TaskAnalysisProgress)
            .filter(TaskAnalysisProgress.status == "running")
            .all()
        )
        task_ids = {record.task_id for record in running_records}
        analyzing_tasks = (
            db.query(ScanTask)
            .filter(ScanTask.status == "analyzing")
            .all()
        )
        stale_agent_records = db.query(TaskAnalysisProgress).all()
        task_ids.update(task.id for task in analyzing_tasks)
        task_ids.update(record.task_id for record in stale_agent_records if _has_unfinished_agent(record.agents))

        if not task_ids:
            return 0

        now = utc_now()
        recovered = 0
        for task_id in task_ids:
            task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
            record = db.query(TaskAnalysisProgress).filter(TaskAnalysisProgress.task_id == task_id).first()
            analyzed = (
                db.query(func.count(Finding.id))
                .filter(Finding.task_id == task_id, Finding.analyzed_at.isnot(None))
                .scalar()
                or 0
            )
            total = db.query(func.count(Finding.id)).filter(Finding.task_id == task_id).scalar() or 0

            if record is None:
                record = TaskAnalysisProgress(task_id=task_id)
                db.add(record)

            had_unfinished_agent = _has_unfinished_agent(record.agents)
            _normalize_stale_progress_record(record, analyzed, total)

            if task is not None and task.status == "analyzing":
                task.status = "error"
            elif task is not None and had_unfinished_agent:
                task.status = "error"

            recovered += 1

        db.commit()
        return recovered
    finally:
        db.close()


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
        record.started_at = utc_now()
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
        now = utc_now_iso()
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
        record.finished_at = utc_now()
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
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()

        if record is not None and record.status == "running" and (task is None or task.status != "analyzing"):
            analyzed = (
                db.query(func.count(Finding.id))
                .filter(Finding.task_id == task_id, Finding.analyzed_at.isnot(None))
                .scalar()
                or 0
            )
            total = db.query(func.count(Finding.id)).filter(Finding.task_id == task_id).scalar() or record.finding_total or 0
            _normalize_stale_progress_record(record, analyzed, total)
            db.commit()

        if record is not None and record.status != "running" and _has_unfinished_agent(record.agents):
            analyzed = (
                db.query(func.count(Finding.id))
                .filter(Finding.task_id == task_id, Finding.analyzed_at.isnot(None))
                .scalar()
                or 0
            )
            total = db.query(func.count(Finding.id)).filter(Finding.task_id == task_id).scalar() or record.finding_total or 0
            _normalize_stale_progress_record(record, analyzed, total)
            if task is not None:
                task.status = "error"
            db.commit()

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