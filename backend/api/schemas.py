"""
Pydantic schemas for API request/response validation.
"""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any
import datetime


class ScanTaskResponse(BaseModel):
    id: int
    name: str
    tool: str
    status: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    finding_count: int = 0
    issue_group_count: int = 0

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: int
    task_id: int
    issue_group_id: int | None
    is_representative: bool
    rule_id: str | None
    tool: str
    file_path: str | None
    line_start: int | None
    line_end: int | None
    message: str | None
    sast_severity: str | None
    code_snippet: str | None
    function_name: str | None
    execution_path: list | None
    llm_code_understanding: str | None
    llm_path_analysis: str | None
    is_vulnerable: bool | None
    llm_confidence: float | None
    llm_reason: str | None
    fix_suggestion: str | None
    patch_suggestion: str | None
    risk_score: float | None
    final_severity: str | None
    is_false_positive: bool
    created_at: datetime.datetime
    analyzed_at: datetime.datetime | None

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    total: int
    items: list[FindingResponse]


class IssueGroupResponse(BaseModel):
    id: int
    task_id: int
    representative_finding_id: int | None
    tool: str
    rule_id: str | None
    file_path: str | None
    line_start: int | None
    line_end: int | None
    message: str | None
    function_name: str | None
    member_count: int
    llm_code_understanding: str | None
    llm_path_analysis: str | None
    is_vulnerable: bool | None
    llm_confidence: float | None
    llm_reason: str | None
    fix_suggestion: str | None
    patch_suggestion: str | None
    risk_score: float | None
    final_severity: str | None
    is_false_positive: bool
    analyzed_at: datetime.datetime | None
    created_at: datetime.datetime
    updated_at: datetime.datetime
    member_ids: list[int] = Field(default_factory=list)
    member_findings: list[FindingResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IssueGroupListResponse(BaseModel):
    total: int
    items: list[IssueGroupResponse]


class StatsResponse(BaseModel):
    scope: str = "finding"
    total_findings: int
    analyzed_findings: int
    vulnerable_findings: int
    false_positive_findings: int
    false_positive_rate: float
    severity_distribution: dict[str, int]
    tool_distribution: dict[str, int]
    avg_risk_score: float


class ScanTaskCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    tool: str = Field(..., description="cppcheck | coverity | klocwork")
    raw_input: str = Field(..., min_length=1, description="Raw tool output text (XML or JSON)")


class AnalyzeRequest(BaseModel):
    finding_ids: list[int] = Field(default_factory=list, description="IDs to analyze; empty = all in task")
    issue_group_ids: list[int] = Field(default_factory=list, description="Issue group IDs to analyze")
    target_type: str = Field(default="finding", description="finding | issue_group")


class BatchIssueGroupUpdateRequest(BaseModel):
    issue_group_ids: list[int] = Field(default_factory=list, min_length=1, description="Issue group IDs to update")
    is_false_positive: bool = Field(..., description="Whether to mark issue groups as false positives")


class BatchFalsePositiveUpdateRequest(BaseModel):
    finding_ids: list[int] = Field(default_factory=list, min_length=1, description="IDs to update")
    is_false_positive: bool = Field(..., description="Whether to mark findings as false positives")
