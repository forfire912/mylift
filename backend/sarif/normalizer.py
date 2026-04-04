"""
SARIF Normalization Layer
Converts RawFinding list to SARIF 2.1.0 format and provides utilities to work with it.
"""
from __future__ import annotations
import json
from typing import Any
from backend.adapters.adapter import RawFinding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def findings_to_sarif(tool_name: str, findings: list[RawFinding]) -> dict:
    """Convert a list of RawFindings into a SARIF 2.1.0 document."""
    results = []
    rules: dict[str, dict] = {}

    for f in findings:
        level = SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")

        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "defaultConfiguration": {"level": level},
                "shortDescription": {"text": f.rule_id},
            }

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": f.line},
            }
        }

        code_flows = []
        if f.trace:
            thread_flow_locations = [
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": step.get("file", ""), "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": step.get("line", 0)},
                        },
                        "message": {"text": step.get("msg", "")},
                    }
                }
                for step in f.trace
            ]
            code_flows.append({
                "threadFlows": [{"locations": thread_flow_locations}]
            })

        result = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [location],
        }
        if code_flows:
            result["codeFlows"] = code_flows

        results.append(result)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif_doc


def sarif_to_findings(sarif_doc: dict | str) -> list[dict]:
    """
    Parse SARIF document back into a list of normalized finding dicts.
    Returns a list compatible with the Finding model.
    """
    if isinstance(sarif_doc, str):
        sarif_doc = json.loads(sarif_doc)

    normalized: list[dict] = []
    for run in sarif_doc.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "warning")
            message = result.get("message", {}).get("text", "")

            locations = result.get("locations", [])
            file_path = ""
            line_start = 0
            line_end = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line_start = region.get("startLine", 0)
                line_end = region.get("endLine", None)

            code_flows = result.get("codeFlows", [])
            trace = []
            for cf in code_flows:
                for tf in cf.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        phys = loc.get("location", {}).get("physicalLocation", {})
                        trace.append({
                            "file": phys.get("artifactLocation", {}).get("uri", ""),
                            "line": phys.get("region", {}).get("startLine", 0),
                            "msg": loc.get("location", {}).get("message", {}).get("text", ""),
                        })

            normalized.append({
                "tool": tool_name,
                "rule_id": rule_id,
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "message": message,
                "sast_severity": _level_to_severity(level),
                "code_flows": code_flows,
            })

    return normalized


def _level_to_severity(level: str) -> str:
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get(level, "medium")
