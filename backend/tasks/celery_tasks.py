"""
Celery task definitions for async SAST analysis pipeline.
"""
from __future__ import annotations
import json
import logging
import datetime
from celery import Celery
from backend.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

celery_app = Celery(
    "mylift",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(bind=True, name="tasks.analyze_finding")
def analyze_finding_task(self, finding_id: int):
    """Async task: Run the 4-agent LLM pipeline on a single finding."""
    from backend.database import SessionLocal
    from backend.models import Finding
    from backend.agents import run_analysis_pipeline
    from backend.scoring import compute_risk_score

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error("Finding %s not found", finding_id)
            return

        # Build finding dict for agents
        finding_dict = {
            "tool": finding.tool,
            "rule_id": finding.rule_id,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "message": finding.message,
            "sast_severity": finding.sast_severity.value if finding.sast_severity else "medium",
            "code_snippet": finding.code_snippet or "",
            "function_name": finding.function_name or "",
            "execution_path": finding.execution_path or [],
            "code_flows": finding.code_flows or [],
        }

        # Run pipeline
        result = run_analysis_pipeline(finding_dict)

        # Update finding
        finding.llm_code_understanding = result.get("llm_code_understanding", "")
        finding.llm_path_analysis = result.get("llm_path_analysis", "")
        finding.is_vulnerable = result.get("is_vulnerable")
        finding.llm_confidence = result.get("llm_confidence")
        finding.llm_reason = result.get("llm_reason", "")
        finding.fix_suggestion = result.get("fix_suggestion", "")
        finding.patch_suggestion = result.get("patch_suggestion", "")
        finding.analyzed_at = datetime.datetime.utcnow()

        # Compute risk score
        score_result = compute_risk_score(
            sast_severity=finding_dict["sast_severity"],
            llm_confidence=finding.llm_confidence,
            is_vulnerable=finding.is_vulnerable,
            code_snippet=finding.code_snippet,
            execution_path=finding.execution_path,
        )
        finding.risk_score = score_result["risk_score"]
        finding.final_severity = score_result["final_severity"]

        db.commit()
        logger.info("Analysis complete for finding %s, risk_score=%s", finding_id, finding.risk_score)
        return {"finding_id": finding_id, "risk_score": finding.risk_score}

    except Exception as e:
        logger.error("Task failed for finding %s: %s", finding_id, e)
        raise self.retry(exc=e, countdown=30, max_retries=2)
    finally:
        db.close()


@celery_app.task(bind=True, name="tasks.analyze_task")
def analyze_task_task(self, task_id: int):
    """Async task: Analyze all findings for a scan task."""
    from backend.database import SessionLocal
    from backend.models import Finding, ScanTask

    db = SessionLocal()
    try:
        scan_task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not scan_task:
            return

        scan_task.status = "analyzing"
        db.commit()

        finding_ids = [f.id for f in db.query(Finding).filter(Finding.task_id == task_id).all()]
        db.close()

        for fid in finding_ids:
            analyze_finding_task.delay(fid)

        return {"task_id": task_id, "finding_count": len(finding_ids)}
    except Exception as e:
        logger.error("Task analyze_task failed for task %s: %s", task_id, e)
        raise
    finally:
        if db.is_active:
            db.close()
