from __future__ import annotations

import re

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from backend.database import SessionLocal, engine
from backend.models import Finding, IssueGroup


def ensure_issue_group_schema() -> None:
    IssueGroup.__table__.create(bind=engine, checkfirst=True)

    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("findings")}
    statements: list[str] = []
    if "issue_group_id" not in columns:
        statements.append("ALTER TABLE findings ADD COLUMN issue_group_id INTEGER")
    if "is_representative" not in columns:
        statements.append("ALTER TABLE findings ADD COLUMN is_representative BOOLEAN DEFAULT 0")

    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


def normalize_file_path(file_path: str | None) -> str:
    return (file_path or "").replace("\\", "/").strip().lower()


def normalize_message(message: str | None) -> str:
    normalized = re.sub(r"\s+", " ", (message or "").strip().lower())
    return normalized[:512]


def build_merge_key(finding: Finding) -> str:
    line_anchor = finding.line_start or 0
    return "|".join([
        finding.tool or "",
        (finding.rule_id or "").strip().lower(),
        normalize_file_path(finding.file_path),
        str(line_anchor),
        normalize_message(finding.message),
    ])


def rebuild_task_issue_groups(task_id: int, db: Session) -> int:
    ensure_issue_group_schema()

    findings = (
        db.query(Finding)
        .filter(Finding.task_id == task_id)
        .order_by(Finding.id.asc())
        .all()
    )
    if not findings:
        db.query(IssueGroup).filter(IssueGroup.task_id == task_id).delete()
        return 0

    for finding in findings:
        finding.issue_group_id = None
        finding.is_representative = False

    db.query(IssueGroup).filter(IssueGroup.task_id == task_id).delete()
    db.flush()

    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(build_merge_key(finding), []).append(finding)

    created_count = 0
    for merge_key, members in grouped.items():
        representative = members[0]
        group = IssueGroup(
            task_id=task_id,
            merge_key=merge_key,
            tool=representative.tool,
            rule_id=representative.rule_id,
            file_path=representative.file_path,
            line_start=representative.line_start,
            line_end=representative.line_end,
            message=representative.message,
            function_name=representative.function_name,
            representative_finding_id=representative.id,
            member_count=len(members),
        )
        db.add(group)
        db.flush()

        for member in members:
            member.issue_group_id = group.id
            member.is_representative = member.id == representative.id

        sync_issue_group(group.id, db)
        created_count += 1

    db.flush()
    return created_count


def sync_issue_group(issue_group_id: int, db: Session) -> IssueGroup | None:
    ensure_issue_group_schema()
    db.flush()

    group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if group is None:
        return None

    members = (
        db.query(Finding)
        .filter(Finding.issue_group_id == issue_group_id, Finding.task_id == group.task_id)
        .order_by(Finding.id.asc())
        .all()
    )
    if not members:
        db.delete(group)
        db.flush()
        return None

    representative = next((member for member in members if member.is_representative), members[0])
    preferred = representative if representative.analyzed_at else next((member for member in members if member.analyzed_at), representative)

    group.tool = representative.tool
    group.rule_id = representative.rule_id
    group.file_path = representative.file_path
    group.line_start = representative.line_start
    group.line_end = representative.line_end
    group.message = representative.message
    group.function_name = representative.function_name
    group.representative_finding_id = representative.id
    group.member_count = len(members)

    group.llm_code_understanding = preferred.llm_code_understanding
    group.llm_path_analysis = preferred.llm_path_analysis
    group.is_vulnerable = preferred.is_vulnerable
    group.llm_confidence = preferred.llm_confidence
    group.llm_reason = preferred.llm_reason
    group.fix_suggestion = preferred.fix_suggestion
    group.patch_suggestion = preferred.patch_suggestion
    group.risk_score = preferred.risk_score
    group.final_severity = preferred.final_severity
    group.analyzed_at = preferred.analyzed_at
    group.is_false_positive = all(member.is_false_positive for member in members)

    db.flush()
    return group


def sync_issue_group_by_finding(finding: Finding, db: Session) -> IssueGroup | None:
    if not finding.issue_group_id:
        return None
    return sync_issue_group(finding.issue_group_id, db)


def propagate_group_analysis(issue_group_id: int, source_finding_id: int, db: Session) -> None:
    source = db.query(Finding).filter(Finding.id == source_finding_id).first()
    if source is None or source.issue_group_id != issue_group_id:
        return

    members = (
        db.query(Finding)
        .filter(
            Finding.issue_group_id == issue_group_id,
            Finding.task_id == source.task_id,
            Finding.id != source_finding_id,
        )
        .all()
    )
    for member in members:
        member.llm_code_understanding = source.llm_code_understanding
        member.llm_path_analysis = source.llm_path_analysis
        member.is_vulnerable = source.is_vulnerable
        member.llm_confidence = source.llm_confidence
        member.llm_reason = source.llm_reason
        member.fix_suggestion = source.fix_suggestion
        member.patch_suggestion = source.patch_suggestion
        member.risk_score = source.risk_score
        member.final_severity = source.final_severity
        member.analyzed_at = source.analyzed_at
    db.flush()


def mark_issue_group_false_positive(issue_group_id: int, is_false_positive: bool, db: Session) -> list[int]:
    group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if group is None:
        return []
    members = db.query(Finding).filter(Finding.issue_group_id == issue_group_id, Finding.task_id == group.task_id).all()
    updated_ids: list[int] = []
    for member in members:
        member.is_false_positive = is_false_positive
        updated_ids.append(member.id)
    db.flush()
    sync_issue_group(issue_group_id, db)
    return updated_ids


def get_issue_group_member_ids(issue_group_id: int, db: Session) -> list[int]:
    group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if group is None:
        return []
    return [
        row[0]
        for row in (
            db.query(Finding.id)
            .filter(Finding.issue_group_id == issue_group_id, Finding.task_id == group.task_id)
            .order_by(Finding.id.asc())
            .all()
        )
    ]


def get_issue_group_representative(issue_group_id: int, db: Session) -> Finding | None:
    group = db.query(IssueGroup).filter(IssueGroup.id == issue_group_id).first()
    if group is None:
        return None
    return (
        db.query(Finding)
        .filter(Finding.issue_group_id == issue_group_id, Finding.task_id == group.task_id, Finding.is_representative == True)
        .first()
        or db.query(Finding).filter(Finding.issue_group_id == issue_group_id, Finding.task_id == group.task_id).order_by(Finding.id.asc()).first()
    )


def rebuild_task_issue_groups_with_new_session(task_id: int) -> int:
    db = SessionLocal()
    try:
        count = rebuild_task_issue_groups(task_id, db)
        db.commit()
        return count
    finally:
        db.close()