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

from backend.database import get_db
from backend.models import Finding, ScanTask, SeverityLevel
from backend.adapters import get_adapter
from backend.sarif import findings_to_sarif, sarif_to_findings
from backend.context import enrich_finding
from backend.scoring import compute_risk_score
from backend.api.schemas import (
    ScanTaskCreate, ScanTaskResponse, FindingResponse,
    FindingListResponse, StatsResponse, AnalyzeRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────────────────────
# Scan Tasks
# ─────────────────────────────────────────────────────────────

@router.post("/tasks", response_model=ScanTaskResponse, status_code=201)
def create_scan_task(
    payload: ScanTaskCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Upload raw SAST output. The system parses it, converts to SARIF,
    enriches with code context, and persists findings.
    """
    adapter = get_adapter(payload.tool)
    raw_findings = adapter.parse(payload.raw_input)

    if not raw_findings:
        raise HTTPException(status_code=422, detail="No findings parsed from input.")

    sarif_doc = findings_to_sarif(payload.tool, raw_findings)
    normalized = sarif_to_findings(sarif_doc)

    task = ScanTask(
        name=payload.name,
        tool=payload.tool,
        status="parsed",
        raw_input=payload.raw_input,
        sarif_output=json.dumps(sarif_doc),
    )
    db.add(task)
    db.flush()

    for nd in normalized:
        enriched = enrich_finding(nd)
        finding = Finding(
            task_id=task.id,
            rule_id=enriched.get("rule_id"),
            tool=enriched.get("tool", payload.tool),
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

    try:
        from backend.tasks import analyze_finding_task, analyze_task_task
        if payload.finding_ids:
            for fid in payload.finding_ids:
                analyze_finding_task.delay(fid)
            return {"message": f"Queued {len(payload.finding_ids)} findings for analysis"}
        else:
            analyze_task_task.delay(task_id)
            return {"message": f"Queued all findings in task {task_id} for analysis"}
    except Exception as e:
        # Celery not available, run synchronously in background
        background_tasks.add_task(_analyze_task_sync, task_id, db)
        return {"message": "Analysis started (sync fallback - Celery unavailable)"}


def _analyze_task_sync(task_id: int, db: Session):
    """Synchronous fallback analysis when Celery is not available."""
    from backend.agents import run_analysis_pipeline
    from backend.scoring import compute_risk_score
    from backend.database import SessionLocal

    sync_db = SessionLocal()
    try:
        findings = sync_db.query(Finding).filter(Finding.task_id == task_id).all()
        for finding in findings:
            try:
                finding_dict = _finding_to_dict(finding)
                result = run_analysis_pipeline(finding_dict)
                _update_finding_from_result(finding, result, sync_db)
                sync_db.commit()
            except Exception as e:
                logger.error("Analysis failed for finding %s: %s", finding.id, e)
    finally:
        sync_db.close()


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
    db.commit()
    return {"id": finding_id, "is_false_positive": is_false_positive}


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

    try:
        from backend.tasks import analyze_finding_task
        analyze_finding_task.delay(finding_id)
        return {"message": f"Finding {finding_id} queued for analysis"}
    except Exception:
        background_tasks.add_task(_analyze_finding_sync, finding_id)
        return {"message": "Analysis started (sync fallback)"}


def _analyze_finding_sync(finding_id: int):
    from backend.agents import run_analysis_pipeline
    from backend.database import SessionLocal

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return
        finding_dict = _finding_to_dict(finding)
        result = run_analysis_pipeline(finding_dict)
        _update_finding_from_result(finding, result, db)
        db.commit()
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
"""API routes for the MyLift SAST analysis backend."""

from __future__ import annotations

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import Report, Vulnerability, get_db
from backend.models import (
    ReportDetail,
    ReportOut,
    StatsOut,
    UploadResult,
    VulnerabilityOut,
)
from backend.parsers import sarif as sarif_parser
from backend.parsers import json_parser

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------


def _detect_format(filename: str, raw: str) -> str:
    if filename.endswith(".sarif") or filename.endswith(".sarif.json"):
        return "sarif"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return "unknown"
    if "runs" in data and "version" in data:
        return "sarif"
    return "json"


@router.post("/upload", response_model=UploadResult, status_code=201)
async def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    content = await file.read()
    try:
        raw = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text.")

    fmt = _detect_format(file.filename or "", raw)
    if fmt == "unknown":
        raise HTTPException(status_code=400, detail="Unsupported file format. Upload SARIF or JSON.")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}")

    if fmt == "sarif":
        parsed = sarif_parser.parse(data)
    else:
        parsed = json_parser.parse(data)

    report = Report(
        name=file.filename or "unnamed",
        tool=parsed.get("tool"),
        format=fmt,
        raw_json=raw[:1_000_000],  # cap stored raw to 1 MB
    )
    db.add(report)
    db.flush()

    for v in parsed.get("vulnerabilities", []):
        db.add(
            Vulnerability(
                report_id=report.id,
                rule_id=v.get("rule_id"),
                severity=v.get("severity"),
                message=v.get("message"),
                file_path=v.get("file_path"),
                start_line=v.get("start_line"),
                end_line=v.get("end_line"),
                start_column=v.get("start_column"),
                code_snippet=v.get("code_snippet"),
                cwe=v.get("cwe"),
                tags=str(v.get("tags")) if v.get("tags") else None,
            )
        )

    db.commit()
    db.refresh(report)

    count = db.query(Vulnerability).filter(Vulnerability.report_id == report.id).count()

    return UploadResult(
        report_id=report.id,
        name=report.name,
        tool=report.tool,
        format=report.format,
        vulnerability_count=count,
        message=f"Successfully imported {count} finding(s).",
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@router.get("/reports", response_model=List[ReportOut])
def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    reports = (
        db.query(Report).order_by(Report.created_at.desc()).offset(skip).limit(limit).all()
    )
    result = []
    for r in reports:
        count = db.query(Vulnerability).filter(Vulnerability.report_id == r.id).count()
        out = ReportOut.model_validate(r)
        out.vulnerability_count = count
        result.append(out)
    return result


@router.get("/reports/{report_id}", response_model=ReportDetail)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    vulns = (
        db.query(Vulnerability).filter(Vulnerability.report_id == report_id).all()
    )
    out = ReportDetail.model_validate(report)
    out.vulnerability_count = len(vulns)
    out.vulnerabilities = [VulnerabilityOut.model_validate(v) for v in vulns]
    return out


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.delete(report)
    db.commit()


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


@router.get("/reports/{report_id}/vulnerabilities", response_model=List[VulnerabilityOut])
def list_vulnerabilities(
    report_id: int,
    severity: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    q = db.query(Vulnerability).filter(Vulnerability.report_id == report_id)
    if severity:
        q = q.filter(Vulnerability.severity == severity.lower())
    if rule_id:
        q = q.filter(Vulnerability.rule_id == rule_id)
    vulns = q.offset(skip).limit(limit).all()
    return [VulnerabilityOut.model_validate(v) for v in vulns]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=StatsOut)
def get_stats(db: Session = Depends(get_db)):
    total_reports = db.query(Report).count()
    total_vulns = db.query(Vulnerability).count()

    sev_rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    by_severity = {row[0] or "unknown": row[1] for row in sev_rows}

    tool_rows = (
        db.query(Report.tool, func.count(Report.id))
        .group_by(Report.tool)
        .all()
    )
    by_tool = {row[0] or "unknown": row[1] for row in tool_rows}

    return StatsOut(
        total_reports=total_reports,
        total_vulnerabilities=total_vulns,
        by_severity=by_severity,
        by_tool=by_tool,
    )
