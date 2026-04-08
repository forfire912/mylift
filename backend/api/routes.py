"""
API Routes for MyLift.
"""
from __future__ import annotations
import json
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.config import get_settings
from backend.database import get_db
from backend.models import Finding, IssueGroup, ScanTask, SeverityLevel
from backend.adapters import get_adapter
from backend.sarif import findings_to_sarif, sarif_to_findings
from backend.context import enrich_finding
from backend.scoring import compute_risk_score
from backend.grouping import (
    ensure_issue_group_schema,
    get_issue_group_member_ids,
    get_issue_group_representative,
    mark_issue_group_false_positive,
    propagate_group_analysis,
    rebuild_task_issue_groups,
    sync_issue_group,
    sync_issue_group_by_finding,
)
from backend.progress import (
    clear_task_progress,
    finish_task_progress,
    get_task_progress_snapshot,
    init_task_progress,
    set_agent_status,
)
from backend.api.schemas import (
    ScanTaskCreate, ScanTaskResponse, FindingResponse,
    FindingListResponse, IssueGroupListResponse, IssueGroupResponse,
    StatsResponse, AnalyzeRequest, BatchFalsePositiveUpdateRequest,
    BatchIssueGroupUpdateRequest,
)
from backend.api.settings_routes import _get_all as _get_runtime_settings
from backend.timeutils import utc_now

settings = get_settings()

logger = logging.getLogger(__name__)
router = APIRouter()

ensure_issue_group_schema()


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

    db.flush()
    rebuild_task_issue_groups(task.id, db)

    db.commit()
    db.refresh(task)

    finding_count = db.query(func.count(Finding.id)).filter(Finding.task_id == task.id).scalar()
    issue_group_count = db.query(func.count(IssueGroup.id)).filter(IssueGroup.task_id == task.id).scalar()
    resp = ScanTaskResponse(
        id=task.id,
        name=task.name,
        tool=task.tool,
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finding_count=finding_count,
        issue_group_count=issue_group_count,
    )
    return resp


@router.get("/tasks", response_model=list[ScanTaskResponse])
def list_tasks(db: Session = Depends(get_db)):
    tasks = db.query(ScanTask).order_by(ScanTask.created_at.desc()).all()
    result = []
    for t in tasks:
        count = db.query(func.count(Finding.id)).filter(Finding.task_id == t.id).scalar()
        issue_group_count = db.query(func.count(IssueGroup.id)).filter(IssueGroup.task_id == t.id).scalar()
        result.append(ScanTaskResponse(
            id=t.id,
            name=t.name,
            tool=t.tool,
            status=t.status,
            created_at=t.created_at,
            updated_at=t.updated_at,
            finding_count=count,
            issue_group_count=issue_group_count,
        ))
    return result


@router.get("/tasks/{task_id}", response_model=ScanTaskResponse)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    count = db.query(func.count(Finding.id)).filter(Finding.task_id == task.id).scalar()
    issue_group_count = db.query(func.count(IssueGroup.id)).filter(IssueGroup.task_id == task.id).scalar()
    return ScanTaskResponse(
        id=task.id,
        name=task.name,
        tool=task.tool,
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finding_count=count,
        issue_group_count=issue_group_count,
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

    selected_finding_ids = payload.finding_ids or None
    selected_issue_group_ids = payload.issue_group_ids or None

    try:
        from backend.tasks import analyze_task_task
        if payload.target_type == "issue_group":
            analyze_task_task.delay(task_id, None, selected_issue_group_ids, "issue_group")
            count_msg = len(selected_issue_group_ids) if selected_issue_group_ids else "all"
            return {"message": f"Queued {count_msg} issue groups for analysis", "task_id": task_id}
        analyze_task_task.delay(task_id, selected_finding_ids, None, "finding")
        count_msg = len(selected_finding_ids) if selected_finding_ids else "all"
        return {"message": f"Queued {count_msg} findings for analysis", "task_id": task_id}
    except Exception as e:
        # Celery not available, run synchronously in background
        if payload.target_type == "issue_group":
            background_tasks.add_task(_analyze_issue_groups_sync, task_id, selected_issue_group_ids)
        else:
            background_tasks.add_task(_analyze_task_sync, task_id, selected_finding_ids)
        return {"message": "Analysis started (sync fallback - Celery unavailable)"}


def _analyze_single_finding(
    sync_db: Session,
    task_id: int,
    finding: Finding,
    item_index: int,
    client,
) -> None:
    for agent_num in range(1, 5):
        set_agent_status(task_id, agent_num, "pending", output="")

    from backend.agents import (
        agent_code_understanding, agent_path_analysis,
        agent_vulnerability_judgment, agent_fix_suggestion,
    )

    fd = _finding_to_dict(finding)
    set_agent_status(task_id, 1, "running", finding_current=item_index)
    cu = agent_code_understanding(fd, client)
    set_agent_status(task_id, 1, "done", output=cu)

    set_agent_status(task_id, 2, "running")
    pa = agent_path_analysis(fd, cu, client)
    set_agent_status(task_id, 2, "done", output=pa)

    set_agent_status(task_id, 3, "running")
    judgment = agent_vulnerability_judgment(fd, cu, pa, client)
    verdict = "真实漏洞" if judgment["is_vulnerable"] else "误报"
    set_agent_status(task_id, 3, "done", output=f"结论={verdict}  置信度={judgment['confidence']:.2f}\n{judgment['reason']}")

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
    sync_issue_group_by_finding(finding, sync_db)


def _analyze_task_sync(task_id: int, finding_ids: list[int] | None = None) -> None:
    """Step-by-step analysis with per-agent progress tracking."""
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
                _analyze_single_finding(sync_db, task_id, finding, finding_idx, client)
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


def _analyze_issue_groups_sync(task_id: int, issue_group_ids: list[int] | None = None) -> None:
    from backend.agents.llm_agents import _get_client, _get_runtime_cfg
    from backend.database import SessionLocal

    sync_db = SessionLocal()
    try:
        task = sync_db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task is None:
            return
        task.status = "analyzing"
        sync_db.commit()

        groups_query = sync_db.query(IssueGroup).filter(IssueGroup.task_id == task_id)
        if issue_group_ids:
            groups_query = groups_query.filter(IssueGroup.id.in_(issue_group_ids))
        groups = groups_query.order_by(IssueGroup.id.asc()).all()
        init_task_progress(task_id, len(groups))
        cfg = _get_runtime_cfg()
        client = _get_client(cfg)
        had_errors = False

        for idx, issue_group in enumerate(groups):
            try:
                representative = get_issue_group_representative(issue_group.id, sync_db)
                if representative is None:
                    continue
                _analyze_single_finding(sync_db, task_id, representative, idx + 1, client)
                propagate_group_analysis(issue_group.id, representative.id, sync_db)
                sync_issue_group(issue_group.id, sync_db)
                sync_db.commit()
            except Exception as e:
                logger.error("Analysis failed for issue group %s: %s", issue_group.id, e)
                had_errors = True
                set_agent_status(task_id, 1, "error", output=str(e), finding_current=idx + 1)

        finish_task_progress(task_id, "error" if had_errors else "done")
        task.status = "error" if had_errors else "analyzed"
        sync_db.commit()
    except Exception as e:
        logger.error("Issue group analysis failed for task %s: %s", task_id, e)
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
    db.query(IssueGroup).delete()
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


@router.post("/issue-groups/analyze")
def analyze_issue_groups_batch(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not payload.issue_group_ids:
        raise HTTPException(status_code=422, detail="issue_group_ids 不能为空")

    issue_groups = db.query(IssueGroup).filter(IssueGroup.id.in_(payload.issue_group_ids)).all()
    if not issue_groups:
        raise HTTPException(status_code=404, detail="Issue groups not found")

    grouped: dict[int, list[int]] = {}
    for issue_group in issue_groups:
        grouped.setdefault(issue_group.task_id, []).append(issue_group.id)

    for task_id in grouped:
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status = "analyzing"
    db.commit()

    try:
        from backend.tasks import analyze_task_task
        for task_id, issue_group_ids in grouped.items():
            analyze_task_task.delay(task_id, None, issue_group_ids, "issue_group")
    except Exception:
        for task_id, issue_group_ids in grouped.items():
            background_tasks.add_task(_analyze_issue_groups_sync, task_id, issue_group_ids)

    return {
        "message": f"Queued {len(payload.issue_group_ids)} issue groups across {len(grouped)} tasks",
        "task_ids": list(grouped.keys()),
    }



# ─────────────────────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────────────────────

@router.get("/issue-groups", response_model=IssueGroupListResponse)
def list_issue_groups(
    task_id: Optional[int] = Query(None),
    tool: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    analyzed: Optional[bool] = Query(None),
    is_vulnerable: Optional[bool] = Query(None),
    is_false_positive: Optional[bool] = Query(None),
    min_risk_score: Optional[float] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    q = db.query(IssueGroup)
    if task_id:
        q = q.filter(IssueGroup.task_id == task_id)
    if tool:
        q = q.filter(IssueGroup.tool == tool)
    if severity:
        try:
            sev = SeverityLevel(severity)
            q = q.filter(IssueGroup.final_severity == sev)
        except ValueError:
            pass
    if analyzed is not None:
        q = q.filter(IssueGroup.analyzed_at.isnot(None) if analyzed else IssueGroup.analyzed_at.is_(None))
    if is_vulnerable is not None:
        q = q.filter(IssueGroup.is_vulnerable == is_vulnerable)
    if is_false_positive is not None:
        q = q.filter(IssueGroup.is_false_positive == is_false_positive)
    if min_risk_score is not None:
        q = q.filter(IssueGroup.risk_score >= min_risk_score)

    total = q.count()
    items = (
        q.order_by(IssueGroup.risk_score.desc().nullslast(), IssueGroup.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return IssueGroupListResponse(total=total, items=[_issue_group_to_response(group, db) for group in items])


@router.get("/issue-groups/{issue_group_id}", response_model=IssueGroupResponse)
def get_issue_group(issue_group_id: int, db: Session = Depends(get_db)):
    issue_group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if not issue_group:
        raise HTTPException(status_code=404, detail="Issue group not found")
    return _issue_group_to_response(issue_group, db)

@router.get("/findings", response_model=FindingListResponse)
def list_findings(
    task_id: Optional[int] = Query(None),
    tool: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    analyzed: Optional[bool] = Query(None),
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
    if analyzed is not None:
        q = q.filter(Finding.analyzed_at.isnot(None) if analyzed else Finding.analyzed_at.is_(None))
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
    sync_issue_group_by_finding(finding, db)
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
        sync_issue_group_by_finding(finding, db)
        updated_ids.append(finding.id)

    db.commit()
    return {
        "updated_count": len(updated_ids),
        "updated_ids": updated_ids,
        "is_false_positive": payload.is_false_positive,
    }


@router.patch("/issue-groups/{issue_group_id}/false-positive")
def mark_issue_group_false_positive_single(
    issue_group_id: int,
    is_false_positive: bool = Query(...),
    db: Session = Depends(get_db),
):
    issue_group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if not issue_group:
        raise HTTPException(status_code=404, detail="Issue group not found")
    updated_ids = mark_issue_group_false_positive(issue_group_id, is_false_positive, db)
    db.commit()
    return {"id": issue_group_id, "updated_ids": updated_ids, "is_false_positive": is_false_positive}


@router.patch("/issue-groups/false-positive")
def mark_issue_group_false_positive_batch(
    payload: BatchIssueGroupUpdateRequest,
    db: Session = Depends(get_db),
):
    issue_groups = db.query(IssueGroup).filter(IssueGroup.id.in_(payload.issue_group_ids)).all()
    if not issue_groups:
        raise HTTPException(status_code=404, detail="Issue groups not found")

    updated_group_ids: list[int] = []
    updated_finding_ids: list[int] = []
    for issue_group in issue_groups:
        updated_group_ids.append(issue_group.id)
        updated_finding_ids.extend(mark_issue_group_false_positive(issue_group.id, payload.is_false_positive, db))
    db.commit()
    return {
        "updated_count": len(updated_group_ids),
        "updated_ids": updated_group_ids,
        "updated_finding_ids": updated_finding_ids,
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


@router.post("/issue-groups/{issue_group_id}/analyze")
def analyze_issue_group(
    issue_group_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    issue_group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if not issue_group:
        raise HTTPException(status_code=404, detail="Issue group not found")
    task = db.query(ScanTask).filter(ScanTask.id == issue_group.task_id).first()
    if task:
        task.status = "analyzing"
        db.commit()

    try:
        from backend.tasks import analyze_task_task
        analyze_task_task.delay(issue_group.task_id, None, [issue_group_id], "issue_group")
        return {"message": f"Issue group {issue_group_id} queued for analysis"}
    except Exception:
        background_tasks.add_task(_analyze_issue_groups_sync, issue_group.task_id, [issue_group_id])
        return {"message": "Analysis started (sync fallback)"}


def _analyze_finding_sync(finding_id: int):
    from backend.database import SessionLocal
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
def get_stats(
    task_id: Optional[int] = Query(None),
    scope: str = Query("finding"),
    db: Session = Depends(get_db),
):
    if scope == "issue_group":
        q = db.query(IssueGroup)
        if task_id:
            q = q.filter(IssueGroup.task_id == task_id)
        total = q.count()
        analyzed = q.filter(IssueGroup.analyzed_at.isnot(None)).count()
        vulnerable = q.filter(IssueGroup.is_vulnerable == True).count()
        false_pos = q.filter(IssueGroup.is_false_positive == True).count()
        avg_risk = db.query(func.avg(IssueGroup.risk_score)).filter(
            IssueGroup.task_id == task_id if task_id else True
        ).scalar() or 0.0
        sev_rows = q.with_entities(IssueGroup.final_severity, func.count(IssueGroup.id)).group_by(IssueGroup.final_severity).all()
        tool_rows = q.with_entities(IssueGroup.tool, func.count(IssueGroup.id)).group_by(IssueGroup.tool).all()
    else:
        q = db.query(Finding)
        if task_id:
            q = q.filter(Finding.task_id == task_id)
        total = q.count()
        analyzed = q.filter(Finding.analyzed_at.isnot(None)).count()
        vulnerable = q.filter(Finding.is_vulnerable == True).count()
        false_pos = q.filter(Finding.is_false_positive == True).count()
        avg_risk = db.query(func.avg(Finding.risk_score)).filter(
            Finding.task_id == task_id if task_id else True
        ).scalar() or 0.0
        sev_rows = q.with_entities(Finding.final_severity, func.count(Finding.id)).group_by(Finding.final_severity).all()
        tool_rows = q.with_entities(Finding.tool, func.count(Finding.id)).group_by(Finding.tool).all()

    fp_rate = round((false_pos / total * 100) if total > 0 else 0.0, 2)
    sev_dist = {(row[0].value if row[0] else "unknown"): row[1] for row in sev_rows}
    tool_dist = {row[0]: row[1] for row in tool_rows}

    return StatsResponse(
        scope=scope,
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
    finding.analyzed_at = utc_now()

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
        issue_group_id=f.issue_group_id,
        is_representative=bool(f.is_representative),
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


def _issue_group_to_response(group: IssueGroup, db: Session) -> IssueGroupResponse:
    members = (
        db.query(Finding)
        .filter(Finding.issue_group_id == group.id)
        .order_by(Finding.id.asc())
        .all()
    )
    return IssueGroupResponse(
        id=group.id,
        task_id=group.task_id,
        representative_finding_id=group.representative_finding_id,
        tool=group.tool,
        rule_id=group.rule_id,
        file_path=group.file_path,
        line_start=group.line_start,
        line_end=group.line_end,
        message=group.message,
        function_name=group.function_name,
        member_count=group.member_count,
        llm_code_understanding=group.llm_code_understanding,
        llm_path_analysis=group.llm_path_analysis,
        is_vulnerable=group.is_vulnerable,
        llm_confidence=group.llm_confidence,
        llm_reason=group.llm_reason,
        fix_suggestion=group.fix_suggestion,
        patch_suggestion=group.patch_suggestion,
        risk_score=group.risk_score,
        final_severity=group.final_severity.value if group.final_severity else None,
        is_false_positive=group.is_false_positive,
        analyzed_at=group.analyzed_at,
        created_at=group.created_at,
        updated_at=group.updated_at,
        member_ids=[member.id for member in members],
        member_findings=[_finding_to_response(member) for member in members],
    )
