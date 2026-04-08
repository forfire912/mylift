import enum
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean,
    DateTime, Enum, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from backend.database import Base
from backend.timeutils import utc_now


class SeverityLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    tool = Column(String(50), nullable=False)
    status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    raw_input = Column(Text, nullable=True)
    sarif_output = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="task", cascade="all, delete-orphan")
    issue_groups = relationship("IssueGroup", back_populates="task", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    issue_group_id = Column(Integer, ForeignKey("issue_groups.id"), nullable=True, index=True)
    is_representative = Column(Boolean, default=False)

    # SARIF fields
    rule_id = Column(String(255), nullable=True)
    tool = Column(String(50), nullable=False)
    file_path = Column(String(1024), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    message = Column(Text, nullable=True)
    sast_severity = Column(Enum(SeverityLevel), default=SeverityLevel.medium)
    code_flows = Column(JSON, default=list)
    raw_data = Column(JSON, default=dict)

    # Context enrichment
    code_snippet = Column(Text, nullable=True)
    function_name = Column(String(255), nullable=True)
    execution_path = Column(JSON, default=list)

    # LLM Analysis
    llm_code_understanding = Column(Text, nullable=True)
    llm_path_analysis = Column(Text, nullable=True)
    is_vulnerable = Column(Boolean, nullable=True)
    llm_confidence = Column(Float, nullable=True)
    llm_reason = Column(Text, nullable=True)
    fix_suggestion = Column(Text, nullable=True)
    patch_suggestion = Column(Text, nullable=True)

    # Risk score
    risk_score = Column(Float, nullable=True)
    final_severity = Column(Enum(SeverityLevel), nullable=True)
    is_false_positive = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=utc_now)
    analyzed_at = Column(DateTime, nullable=True)

    task = relationship("ScanTask", back_populates="findings")
    issue_group = relationship("IssueGroup", back_populates="findings", foreign_keys=[issue_group_id])


class IssueGroup(Base):
    __tablename__ = "issue_groups"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False, index=True)
    merge_key = Column(String(2048), nullable=False, index=True)
    tool = Column(String(50), nullable=False)
    rule_id = Column(String(255), nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    message = Column(Text, nullable=True)
    function_name = Column(String(255), nullable=True)
    representative_finding_id = Column(
        Integer,
        ForeignKey(
            "findings.id",
            use_alter=True,
            name="fk_issue_groups_representative_finding_id",
        ),
        nullable=True,
    )
    member_count = Column(Integer, nullable=False, default=1)

    llm_code_understanding = Column(Text, nullable=True)
    llm_path_analysis = Column(Text, nullable=True)
    is_vulnerable = Column(Boolean, nullable=True)
    llm_confidence = Column(Float, nullable=True)
    llm_reason = Column(Text, nullable=True)
    fix_suggestion = Column(Text, nullable=True)
    patch_suggestion = Column(Text, nullable=True)

    risk_score = Column(Float, nullable=True)
    final_severity = Column(Enum(SeverityLevel), nullable=True)
    is_false_positive = Column(Boolean, default=False)
    analyzed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    task = relationship("ScanTask", back_populates="issue_groups")
    findings = relationship("Finding", back_populates="issue_group", foreign_keys=[Finding.issue_group_id])
    representative_finding = relationship("Finding", foreign_keys=[representative_finding_id], post_update=True)


class SystemConfig(Base):
    """Key-value store for runtime-configurable system settings (LLM config, agent prompts, etc.)."""
    __tablename__ = "system_config"

    key = Column(String(128), primary_key=True, index=True)
    value = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class TaskAnalysisProgress(Base):
    __tablename__ = "task_analysis_progress"

    task_id = Column(Integer, ForeignKey("scan_tasks.id"), primary_key=True)
    status = Column(String(32), nullable=False, default="not_started")
    finding_total = Column(Integer, nullable=False, default=0)
    finding_current = Column(Integer, nullable=False, default=0)
    current_agent = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    agents = Column(JSON, default=dict)
