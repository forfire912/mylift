"""SARIF (Static Analysis Results Interchange Format) v2.1.0 parser."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def _severity_from_level(level: Optional[str]) -> str:
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get((level or "").lower(), "info")


def _extract_cwe(tags: List[str]) -> Optional[str]:
    for tag in tags:
        if tag.lower().startswith("cwe-") or tag.lower().startswith("cwe/"):
            return tag.upper().replace("CWE/", "CWE-")
    return None


def parse(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a SARIF document and return normalized result."""
    runs = data.get("runs", [])
    if not runs:
        return {"tool": None, "vulnerabilities": []}

    run = runs[0]
    tool_info = run.get("tool", {}).get("driver", {})
    tool_name = tool_info.get("name")

    # Build rule index for fast lookup
    rules: Dict[str, Any] = {}
    for rule in tool_info.get("rules", []):
        rules[rule.get("id", "")] = rule

    vulnerabilities: List[Dict[str, Any]] = []
    for result in run.get("results", []):
        rule_id = result.get("ruleId") or result.get("rule", {}).get("id")
        level = result.get("level")
        message_text = (
            result.get("message", {}).get("text")
            or result.get("message", {}).get("markdown")
            or ""
        )

        # Location
        locations = result.get("locations", [])
        file_path: Optional[str] = None
        start_line: Optional[int] = None
        end_line: Optional[int] = None
        start_column: Optional[int] = None

        if locations:
            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            file_path = artifact.get("uri")
            region = phys.get("region", {})
            start_line = region.get("startLine")
            end_line = region.get("endLine")
            start_column = region.get("startColumn")

        # Tags / CWE from rule
        rule_meta = rules.get(rule_id or "", {})
        rule_tags: List[str] = (
            rule_meta.get("properties", {}).get("tags", [])
            or rule_meta.get("defaultConfiguration", {}).get("level", [])
        )
        if isinstance(rule_tags, str):
            rule_tags = [rule_tags]

        # Severity: prefer rule's default level over result level
        rule_level = (
            rule_meta.get("defaultConfiguration", {}).get("level") or level
        )
        severity = _severity_from_level(rule_level)

        cwe = _extract_cwe(rule_tags)

        vulnerabilities.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message_text,
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "start_column": start_column,
                "code_snippet": None,
                "cwe": cwe,
                "tags": ",".join(rule_tags) if rule_tags else None,
            }
        )

    return {"tool": tool_name, "vulnerabilities": vulnerabilities}
