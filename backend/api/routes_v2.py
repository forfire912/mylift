"""API routes for the MyLift SAST analysis backend (upload/report API)."""

from __future__ import annotations

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import Report, Vulnerability, get_db
from backend.report_schemas import (
    ReportDetail,
    ReportOut,
    StatsOut,
    UploadResult,
    VulnerabilityOut,
)
from backend.parsers import sarif as sarif_parser
from backend.parsers import json_parser

router_v2 = APIRouter(prefix="/api")


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


@router_v2.post("/upload", response_model=UploadResult, status_code=201)
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
        raw_json=raw[:1_000_000],
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


@router_v2.get("/reports", response_model=List[ReportOut])
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


@router_v2.get("/reports/{report_id}", response_model=ReportDetail)
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


@router_v2.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.delete(report)
    db.commit()


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


@router_v2.get("/reports/{report_id}/vulnerabilities", response_model=List[VulnerabilityOut])
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


@router_v2.get("/stats", response_model=StatsOut)
def get_stats_v2(db: Session = Depends(get_db)):
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
