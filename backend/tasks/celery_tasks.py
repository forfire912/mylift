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
    from backend.api.routes import _analyze_task_sync

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error("Finding %s not found", finding_id)
            return
        _analyze_task_sync(finding.task_id, [finding_id])
        db.refresh(finding)
        return {"finding_id": finding_id, "risk_score": finding.risk_score}

    except Exception as e:
        logger.error("Task failed for finding %s: %s", finding_id, e)
        # 指数退避：第1次30s、第2次60s、第3次120s，最多重试3次
        countdown = 30 * (2 ** self.request.retries)
        raise self.retry(exc=e, countdown=countdown, max_retries=3)
    finally:
        db.close()


@celery_app.task(bind=True, name="tasks.analyze_task")
def analyze_task_task(self, task_id: int, finding_ids: list[int] | None = None):
    """Async task: Analyze all findings for a scan task."""
    from backend.api.routes import _analyze_task_sync
    try:
        _analyze_task_sync(task_id, finding_ids)
        return {"task_id": task_id, "finding_count": len(finding_ids or [])}
    except Exception as e:
        logger.error("Task analyze_task failed for task %s: %s", task_id, e)
        raise
