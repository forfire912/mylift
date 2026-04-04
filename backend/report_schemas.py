"""Pydantic schemas for request/response validation."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_id: int
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe: Optional[str] = None
    tags: Optional[str] = None


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    tool: Optional[str] = None
    format: str
    created_at: datetime
    vulnerability_count: int = 0


class ReportDetail(ReportOut):
    vulnerabilities: List[VulnerabilityOut] = []


class StatsOut(BaseModel):
    total_reports: int
    total_vulnerabilities: int
    by_severity: dict
    by_tool: dict


class UploadResult(BaseModel):
    report_id: int
    name: str
    tool: Optional[str] = None
    format: str
    vulnerability_count: int
    message: str
