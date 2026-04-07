"""
API Routes for MyLift.
"""
from __future__ import annotations
import json
import logging
import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.config import get_settings
from backend.database import get_db
from backend.models import Finding, ScanTask, SeverityLevel
from backend.adapters import get_adapter
from backend.sarif import findings_to_sarif, sarif_to_findings
from backend.context import enrich_finding
from backend.scoring import compute_risk_score
from backend.progress import (
    clear_task_progress,
    finish_task_progress,
    get_task_progress_snapshot,
    init_task_progress,
    set_agent_status,
)
from backend.api.schemas import (
    ScanTaskCreate, ScanTaskResponse, FindingResponse,
    FindingListResponse, StatsResponse, AnalyzeRequest,
    BatchFalsePositiveUpdateRequest,
)
from backend.api.settings_routes import _get_all as _get_runtime_settings

settings = get_settings()

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────────────────────
# Scan Tasks
# ─────────────────────────────────────────────────────────────

@router.post("/tasks", response_model=ScanTaskResponse, status_code=201)
def create_scan_task(
    payload: ScanTaskCreate,
    db: Session = Depends(get_db),
):
    """
    上传 SAST 工具报告内容（Cppcheck XML / Coverity JSON / Klocwork JSON），
    系统自动解析、转换为 SARIF、上下文增强并持久化 Finding。
    """
    tool = payload.tool
    raw_input = payload.raw_input

    if tool not in ("cppcheck", "coverity", "klocwork"):
        raise HTTPException(status_code=422, detail="不支持的工具类型，仅支持 cppcheck / coverity / klocwork")

    adapter = get_adapter(tool)
    raw_findings = adapter.parse(raw_input)

    if not raw_findings:
        raise HTTPException(status_code=422, detail="未能从文件中解析出任何 Finding，请确认文件格式正确")

    sarif_doc = findings_to_sarif(tool, raw_findings)
    normalized = sarif_to_findings(sarif_doc)

    _cfg = _get_runtime_settings(db)
    source_code_dir = _cfg.get("source_code_dir") or settings.SOURCE_CODE_DIR or None

    task = ScanTask(
        name=payload.name,
        tool=tool,
        status="parsed",
        raw_input=raw_input,
        sarif_output=json.dumps(sarif_doc),
    )
    db.add(task)
    db.flush()

    for nd in normalized:
        enriched = enrich_finding(nd, base_dir=source_code_dir)
        finding = Finding(
            task_id=task.id,
            rule_id=enriched.get("rule_id"),
            tool=enriched.get("tool", tool),
            file_path=enriched.get("file_path"),
            line_start=enriched.get("line_start"),
            line_end=enriched.get("line_end"),
            message=enriched.get("message"),
            sast_severity=_map_severity(enriched.get("sast_severity", "medium")),
            code_flows=enriched.get("code_flows", []),
            raw_data=nd,
            code_snippet=enriched.get("code_snippet", ""),
            function_name=enriched.get("function_name", ""),
            execution_path=enriched.get("execution_path", []),
        )
        db.add(finding)

    db.commit()
    db.refresh(task)

    finding_count = db.query(func.count(Finding.id)).filter(Finding.task_id == task.id).scalar()
    resp = ScanTaskResponse(
        id=task.id,
        name=task.name,
        tool=task.tool,
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finding_count=finding_count,
    )
    return resp


@router.get("/tasks", response_model=list[ScanTaskResponse])
def list_tasks(db: Session = Depends(get_db)):
    tasks = db.query(ScanTask).order_by(ScanTask.created_at.desc()).all()
    result = []
    for t in tasks:
        count = db.query(func.count(Finding.id)).filter(Finding.task_id == t.id).scalar()
        result.append(ScanTaskResponse(
            id=t.id,
            name=t.name,
            tool=t.tool,
            status=t.status,
            created_at=t.created_at,
            updated_at=t.updated_at,
            finding_count=count,
        ))
    return result


@router.get("/tasks/{task_id}", response_model=ScanTaskResponse)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    count = db.query(func.count(Finding.id)).filter(Finding.task_id == task.id).scalar()
    return ScanTaskResponse(
        id=task.id,
        name=task.name,
        tool=task.tool,
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finding_count=count,
    )


@router.post("/tasks/{task_id}/analyze")
def trigger_analysis(
    task_id: int,
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger LLM analysis for findings in a task (runs in background via Celery)."""
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    task.status = "analyzing"
    db.commit()

    selected_ids = payload.finding_ids or None

    try:
        from backend.tasks import analyze_task_task
        analyze_task_task.delay(task_id, selected_ids)
        count_msg = len(selected_ids) if selected_ids else "all"
        return {"message": f"Queued {count_msg} findings for analysis", "task_id": task_id}
    except Exception as e:
        # Celery not available, run synchronously in background
        background_tasks.add_task(_analyze_task_sync, task_id, selected_ids)
        return {"message": "Analysis started (sync fallback - Celery unavailable)"}


def _analyze_task_sync(task_id: int, finding_ids: list[int] | None = None) -> None:
    """Step-by-step analysis with per-agent progress tracking."""
    from backend.agents import (
        agent_code_understanding, agent_path_analysis,
        agent_vulnerability_judgment, agent_fix_suggestion,
    )
    from backend.agents.llm_agents import _get_client, _get_runtime_cfg
    from backend.database import SessionLocal

    sync_db = SessionLocal()
    try:
        task = sync_db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task is None:
            return
        task.status = "analyzing"
        sync_db.commit()

        findings_query = sync_db.query(Finding).filter(Finding.task_id == task_id)
        if finding_ids:
            findings_query = findings_query.filter(Finding.id.in_(finding_ids))
        findings = findings_query.order_by(Finding.id.asc()).all()
        init_task_progress(task_id, len(findings))
        cfg = _get_runtime_cfg()
        client = _get_client(cfg)
        had_errors = False

        for idx, finding in enumerate(findings):
            finding_idx = idx + 1
            try:
                for agent_num in range(1, 5):
                    set_agent_status(task_id, agent_num, "pending", output="")
                fd = _finding_to_dict(finding)

                # Agent 1
                set_agent_status(task_id, 1, "running", finding_current=finding_idx)
                cu = agent_code_understanding(fd, client)
                set_agent_status(task_id, 1, "done", output=cu)

                # Agent 2
                set_agent_status(task_id, 2, "running")
                pa = agent_path_analysis(fd, cu, client)
                set_agent_status(task_id, 2, "done", output=pa)

                # Agent 3
                set_agent_status(task_id, 3, "running")
                judgment = agent_vulnerability_judgment(fd, cu, pa, client)
                set_agent_status(task_id, 3, "done",
                    output=f"is_vulnerable={judgment['is_vulnerable']}  "
                           f"confidence={judgment['confidence']:.2f}\n{judgment['reason']}")

                # Agent 4
                set_agent_status(task_id, 4, "running")
                fix = agent_fix_suggestion(fd, judgment, client)
                set_agent_status(task_id, 4, "done", output=fix["fix_suggestion"])

                result = {
                    "llm_code_understanding": cu,
                    "llm_path_analysis": pa,
                    "is_vulnerable": judgment["is_vulnerable"],
                    "llm_confidence": judgment["confidence"],
                    "llm_reason": judgment["reason"],
                    "fix_suggestion": fix["fix_suggestion"],
                    "patch_suggestion": fix["patch_suggestion"],
                }
                _update_finding_from_result(finding, result, sync_db)
                sync_db.commit()

            except Exception as e:
                logger.error("Analysis failed for finding %s: %s", finding.id, e)
                had_errors = True
                set_agent_status(task_id, 1, "error", output=str(e), finding_current=finding_idx)

        finish_task_progress(task_id, "error" if had_errors else "done")

        task.status = "error" if had_errors else "analyzed"
        sync_db.commit()

    except Exception as e:
        logger.error("Task analysis failed for task %s: %s", task_id, e)
        finish_task_progress(task_id, "error")
    finally:
        sync_db.close()


@router.get("/tasks/{task_id}/progress")
def get_task_progress(task_id: int):
    """Return analysis progress for a task."""
    return get_task_progress_snapshot(task_id)


@router.delete("/tasks", status_code=204)
def delete_all_tasks(db: Session = Depends(get_db)):
    """Delete ALL tasks and findings. Irreversible."""
    db.query(Finding).delete()
    db.query(ScanTask).delete()
    db.commit()
    clear_task_progress()


@router.post("/findings/analyze")
def analyze_findings_batch(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not payload.finding_ids:
        raise HTTPException(status_code=422, detail="finding_ids 不能为空")

    findings = db.query(Finding).filter(Finding.id.in_(payload.finding_ids)).all()
    if not findings:
        raise HTTPException(status_code=404, detail="Findings not found")

    grouped: dict[int, list[int]] = {}
    for finding in findings:
        grouped.setdefault(finding.task_id, []).append(finding.id)

    for task_id in grouped:
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status = "analyzing"
    db.commit()

    try:
        from backend.tasks import analyze_task_task
        for task_id, finding_ids in grouped.items():
            analyze_task_task.delay(task_id, finding_ids)
    except Exception:
        for task_id, finding_ids in grouped.items():
            background_tasks.add_task(_analyze_task_sync, task_id, finding_ids)

    return {
        "message": f"Queued {len(payload.finding_ids)} findings across {len(grouped)} tasks",
        "task_ids": list(grouped.keys()),
    }



# ─────────────────────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────────────────────

@router.get("/findings", response_model=FindingListResponse)
def list_findings(
    task_id: Optional[int] = Query(None),
    tool: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    is_vulnerable: Optional[bool] = Query(None),
    is_false_positive: Optional[bool] = Query(None),
    min_risk_score: Optional[float] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List findings with filtering and pagination, sorted by risk score."""
    q = db.query(Finding)
    if task_id:
        q = q.filter(Finding.task_id == task_id)
    if tool:
        q = q.filter(Finding.tool == tool)
    if severity:
        try:
            sev = SeverityLevel(severity)
            q = q.filter(Finding.final_severity == sev)
        except ValueError:
            pass
    if is_vulnerable is not None:
        q = q.filter(Finding.is_vulnerable == is_vulnerable)
    if is_false_positive is not None:
        q = q.filter(Finding.is_false_positive == is_false_positive)
    if min_risk_score is not None:
        q = q.filter(Finding.risk_score >= min_risk_score)

    total = q.count()
    items = (
        q.order_by(Finding.risk_score.desc().nullslast(), Finding.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return FindingListResponse(total=total, items=[_finding_to_response(f) for f in items])


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_to_response(finding)


@router.patch("/findings/{finding_id}/false-positive")
def mark_false_positive(
    finding_id: int,
    is_false_positive: bool = Query(...),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.is_false_positive = is_false_positive
    score_result = compute_risk_score(
        sast_severity=finding.sast_severity.value if finding.sast_severity else "medium",
        llm_confidence=finding.llm_confidence,
        is_vulnerable=finding.is_vulnerable,
        is_false_positive=finding.is_false_positive,
        code_snippet=finding.code_snippet,
        execution_path=finding.execution_path,
    )
    finding.risk_score = score_result["risk_score"]
    finding.final_severity = score_result["final_severity"]
    db.commit()
    return {"id": finding_id, "is_false_positive": is_false_positive}


@router.patch("/findings/false-positive")
def mark_false_positive_batch(
    payload: BatchFalsePositiveUpdateRequest,
    db: Session = Depends(get_db),
):
    findings = db.query(Finding).filter(Finding.id.in_(payload.finding_ids)).all()
    if not findings:
        raise HTTPException(status_code=404, detail="Findings not found")

    updated_ids: list[int] = []
    for finding in findings:
        finding.is_false_positive = payload.is_false_positive
        score_result = compute_risk_score(
            sast_severity=finding.sast_severity.value if finding.sast_severity else "medium",
            llm_confidence=finding.llm_confidence,
            is_vulnerable=finding.is_vulnerable,
            is_false_positive=finding.is_false_positive,
            code_snippet=finding.code_snippet,
            execution_path=finding.execution_path,
        )
        finding.risk_score = score_result["risk_score"]
        finding.final_severity = score_result["final_severity"]
        updated_ids.append(finding.id)

    db.commit()
    return {
        "updated_count": len(updated_ids),
        "updated_ids": updated_ids,
        "is_false_positive": payload.is_false_positive,
    }


@router.post("/findings/{finding_id}/analyze")
def analyze_finding(
    finding_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger single-finding LLM analysis."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    task = db.query(ScanTask).filter(ScanTask.id == finding.task_id).first()
    if task:
        task.status = "analyzing"
        db.commit()

    try:
        from backend.tasks import analyze_task_task
        analyze_task_task.delay(finding.task_id, [finding_id])
        return {"message": f"Finding {finding_id} queued for analysis"}
    except Exception:
        background_tasks.add_task(_analyze_task_sync, finding.task_id, [finding_id])
        return {"message": "Analysis started (sync fallback)"}


def _analyze_finding_sync(finding_id: int):
    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return
        _analyze_task_sync(finding.task_id, [finding_id])
    except Exception as e:
        logger.error("Sync analysis failed for finding %s: %s", finding_id, e)
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────

@router.get("/stats", response_model=StatsResponse)
def get_stats(task_id: Optional[int] = Query(None), db: Session = Depends(get_db)):
    q = db.query(Finding)
    if task_id:
        q = q.filter(Finding.task_id == task_id)

    total = q.count()
    analyzed = q.filter(Finding.analyzed_at.isnot(None)).count()
    vulnerable = q.filter(Finding.is_vulnerable == True).count()
    false_pos = q.filter(Finding.is_false_positive == True).count()
    fp_rate = round((false_pos / total * 100) if total > 0 else 0.0, 2)

    avg_risk = db.query(func.avg(Finding.risk_score)).filter(
        Finding.task_id == task_id if task_id else True
    ).scalar() or 0.0

    # Severity distribution
    sev_rows = (
        q.with_entities(Finding.final_severity, func.count(Finding.id))
        .group_by(Finding.final_severity)
        .all()
    )
    sev_dist = {(row[0].value if row[0] else "unknown"): row[1] for row in sev_rows}

    # Tool distribution
    tool_rows = (
        q.with_entities(Finding.tool, func.count(Finding.id))
        .group_by(Finding.tool)
        .all()
    )
    tool_dist = {row[0]: row[1] for row in tool_rows}

    return StatsResponse(
        total_findings=total,
        analyzed_findings=analyzed,
        vulnerable_findings=vulnerable,
        false_positive_findings=false_pos,
        false_positive_rate=fp_rate,
        severity_distribution=sev_dist,
        tool_distribution=tool_dist,
        avg_risk_score=round(float(avg_risk), 2),
    )


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _map_severity(sev: str) -> SeverityLevel:
    try:
        return SeverityLevel(sev.lower())
    except ValueError:
        return SeverityLevel.medium


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "tool": finding.tool,
        "rule_id": finding.rule_id or "",
        "file_path": finding.file_path or "",
        "line_start": finding.line_start or 0,
        "message": finding.message or "",
        "sast_severity": finding.sast_severity.value if finding.sast_severity else "medium",
        "code_snippet": finding.code_snippet or "",
        "function_name": finding.function_name or "",
        "execution_path": finding.execution_path or [],
        "code_flows": finding.code_flows or [],
    }


def _update_finding_from_result(finding: Finding, result: dict, db: Session):
    from backend.scoring import compute_risk_score
    finding.llm_code_understanding = result.get("llm_code_understanding", "")
    finding.llm_path_analysis = result.get("llm_path_analysis", "")
    finding.is_vulnerable = result.get("is_vulnerable")
    finding.llm_confidence = result.get("llm_confidence")
    finding.llm_reason = result.get("llm_reason", "")
    finding.fix_suggestion = result.get("fix_suggestion", "")
    finding.patch_suggestion = result.get("patch_suggestion", "")
    finding.analyzed_at = datetime.datetime.utcnow()

    score_result = compute_risk_score(
        sast_severity=finding.sast_severity.value if finding.sast_severity else "medium",
        llm_confidence=finding.llm_confidence,
        is_vulnerable=finding.is_vulnerable,
        is_false_positive=finding.is_false_positive,
        code_snippet=finding.code_snippet,
        execution_path=finding.execution_path,
    )
    finding.risk_score = score_result["risk_score"]
    finding.final_severity = score_result["final_severity"]


def _finding_to_response(f: Finding) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        task_id=f.task_id,
        rule_id=f.rule_id,
        tool=f.tool,
        file_path=f.file_path,
        line_start=f.line_start,
        line_end=f.line_end,
        message=f.message,
        sast_severity=f.sast_severity.value if f.sast_severity else None,
        code_snippet=f.code_snippet,
        function_name=f.function_name,
        execution_path=f.execution_path,
        llm_code_understanding=f.llm_code_understanding,
        llm_path_analysis=f.llm_path_analysis,
        is_vulnerable=f.is_vulnerable,
        llm_confidence=f.llm_confidence,
        llm_reason=f.llm_reason,
        fix_suggestion=f.fix_suggestion,
        patch_suggestion=f.patch_suggestion,
        risk_score=f.risk_score,
        final_severity=f.final_severity.value if f.final_severity else None,
        is_false_positive=f.is_false_positive,
        created_at=f.created_at,
        analyzed_at=f.analyzed_at,
    )
