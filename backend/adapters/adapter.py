"""
SAST Adapter Layer - Adapter Pattern
Converts tool-specific output to unified internal format.
"""
from __future__ import annotations
import json
import xml.etree.ElementTree as ET
from typing import Any
from dataclasses import dataclass, field


@dataclass
class RawFinding:
    """Unified internal finding format from SAST tools."""
    tool: str
    rule_id: str
    file: str
    line: int
    message: str
    severity: str = "medium"
    trace: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "severity": self.severity,
            "trace": self.trace,
            "extra": self.extra,
        }


class BaseAdapter:
    """Abstract base adapter."""
    TOOL_NAME: str = "unknown"

    def parse(self, raw: str | dict | Any) -> list[RawFinding]:
        raise NotImplementedError


class CppcheckAdapter(BaseAdapter):
    """Adapter for Cppcheck XML output."""
    TOOL_NAME = "cppcheck"

    SEVERITY_MAP = {
        "error": "high",
        "warning": "medium",
        "style": "low",
        "performance": "low",
        "portability": "low",
        "information": "info",
    }

    def parse(self, raw: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return findings

        for error in root.iter("error"):
            rule_id = error.get("id", "unknown")
            severity = self.SEVERITY_MAP.get(error.get("severity", "warning"), "medium")
            message = error.get("msg", "")
            verbose = error.get("verbose", message)

            # Get location(s)
            locations = list(error.iter("location"))
            if not locations:
                continue

            primary = locations[0]
            file_path = primary.get("file", "")
            line = int(primary.get("line", 0))

            trace = [
                {"file": loc.get("file", ""), "line": int(loc.get("line", 0)), "msg": loc.get("msg", "")}
                for loc in locations[1:]
            ]

            findings.append(RawFinding(
                tool=self.TOOL_NAME,
                rule_id=rule_id,
                file=file_path,
                line=line,
                message=verbose or message,
                severity=severity,
                trace=trace,
            ))

        return findings


class CoverityAdapter(BaseAdapter):
    """Adapter for Coverity JSON output."""
    TOOL_NAME = "coverity"

    SEVERITY_MAP = {
        "High": "high",
        "Medium": "medium",
        "Low": "low",
    }

    def parse(self, raw: str | dict) -> list[RawFinding]:
        findings: list[RawFinding] = []
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return findings
        else:
            data = raw

        issues = data if isinstance(data, list) else data.get("issues", [])

        for issue in issues:
            checker = issue.get("checkerName", issue.get("checker", "unknown"))
            impact = issue.get("impact", issue.get("severity", "Medium"))
            severity = self.SEVERITY_MAP.get(impact, "medium")

            events = issue.get("events", [])
            main_event = next((e for e in events if e.get("main", False)), events[0] if events else {})

            file_path = main_event.get("strippedFilePathname", issue.get("file", ""))
            line = int(main_event.get("lineNumber", issue.get("line", 0)))
            message = main_event.get("eventDescription", issue.get("message", ""))

            trace = [
                {
                    "file": e.get("strippedFilePathname", ""),
                    "line": int(e.get("lineNumber", 0)),
                    "msg": e.get("eventDescription", ""),
                }
                for e in events
                if not e.get("main", False)
            ]

            findings.append(RawFinding(
                tool=self.TOOL_NAME,
                rule_id=checker,
                file=file_path,
                line=line,
                message=message,
                severity=severity,
                trace=trace,
                extra={"cid": issue.get("cid", "")},
            ))

        return findings


class KlocworkAdapter(BaseAdapter):
    """Adapter for Klocwork JSON output."""
    TOOL_NAME = "klocwork"

    SEVERITY_MAP = {
        "1": "critical",
        "2": "high",
        "3": "high",
        "4": "medium",
        "5": "medium",
        "6": "low",
        "7": "low",
        "8": "info",
        "9": "info",
        "10": "info",
    }

    def parse(self, raw: str | dict) -> list[RawFinding]:
        findings: list[RawFinding] = []
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return findings
        else:
            data = raw

        issues = data if isinstance(data, list) else data.get("response", [])

        for issue in issues:
            rule_id = issue.get("code", "unknown")
            sev_str = str(issue.get("severity", issue.get("severityCode", "5")))
            severity = self.SEVERITY_MAP.get(sev_str, "medium")

            file_path = issue.get("file", "")
            line = int(issue.get("line", 0))
            message = issue.get("message", "")

            trace_raw = issue.get("trace", [])
            trace = [
                {
                    "file": t.get("file", ""),
                    "line": int(t.get("line", 0)),
                    "msg": t.get("message", ""),
                }
                for t in trace_raw
            ]

            findings.append(RawFinding(
                tool=self.TOOL_NAME,
                rule_id=rule_id,
                file=file_path,
                line=line,
                message=message,
                severity=severity,
                trace=trace,
                extra={"id": issue.get("id", "")},
            ))

        return findings


ADAPTERS: dict[str, BaseAdapter] = {
    "cppcheck": CppcheckAdapter(),
    "coverity": CoverityAdapter(),
    "klocwork": KlocworkAdapter(),
}


def get_adapter(tool: str) -> BaseAdapter:
    adapter = ADAPTERS.get(tool.lower())
    if adapter is None:
        raise ValueError(f"Unsupported tool: {tool}. Supported: {list(ADAPTERS.keys())}")
    return adapter
