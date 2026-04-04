"""Generic JSON parser for common SAST tool output formats.

Supported tools/formats (auto-detected):
- Semgrep JSON output
- Bandit JSON output
- Checkov JSON output (single check result)
- Trivy JSON output (vulnerability scan)
- Generic flat list of findings
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _semgrep(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    results = data.get("results")
    # Semgrep results always have check_id in their items
    if not isinstance(results, list) or not results or "check_id" not in results[0]:
        return None
    vulns: List[Dict[str, Any]] = []
    for r in results:
        extra = r.get("extra", {})
        severity_raw = (extra.get("severity") or r.get("severity") or "").lower()
        severity_map = {
            "error": "high",
            "warning": "medium",
            "info": "low",
        }
        severity = severity_map.get(severity_raw, severity_raw or "info")
        start = r.get("start", {})
        end = r.get("end", {})
        vulns.append(
            {
                "rule_id": r.get("check_id"),
                "severity": severity,
                "message": extra.get("message") or extra.get("lines", ""),
                "file_path": r.get("path"),
                "start_line": start.get("line"),
                "end_line": end.get("line"),
                "start_column": start.get("col"),
                "code_snippet": extra.get("lines"),
                "cwe": None,
                "tags": None,
            }
        )
    return {"tool": "Semgrep", "vulnerabilities": vulns}


def _bandit(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    results = data.get("results")
    if results is None or "metrics" not in data:
        return None
    vulns: List[Dict[str, Any]] = []
    for r in results:
        sev = (r.get("issue_severity") or "").lower()
        sev_map = {"high": "high", "medium": "medium", "low": "low"}
        severity = sev_map.get(sev, "info")
        cwe_data = r.get("issue_cwe", {})
        cwe = f"CWE-{cwe_data.get('id')}" if cwe_data and cwe_data.get("id") else None
        vulns.append(
            {
                "rule_id": r.get("test_id"),
                "severity": severity,
                "message": r.get("issue_text"),
                "file_path": r.get("filename"),
                "start_line": r.get("line_number"),
                "end_line": r.get("line_range", [None])[-1] if r.get("line_range") else None,
                "start_column": None,
                "code_snippet": r.get("code"),
                "cwe": cwe,
                "tags": r.get("test_name"),
            }
        )
    return {"tool": "Bandit", "vulnerabilities": vulns}


def _checkov(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Checkov wraps results in check_type / results dict
    results = data.get("results", {})
    failed = results.get("failed_checks", [])
    if not failed and "check_type" not in data:
        return None
    vulns: List[Dict[str, Any]] = []
    for r in failed:
        bc_id = r.get("check_id", "")
        vulns.append(
            {
                "rule_id": bc_id,
                "severity": "medium",
                "message": r.get("check_result", {}).get("result", "") + " – " + r.get("resource", ""),
                "file_path": r.get("file_path"),
                "start_line": r.get("file_line_range", [None])[0],
                "end_line": r.get("file_line_range", [None, None])[-1],
                "start_column": None,
                "code_snippet": None,
                "cwe": None,
                "tags": data.get("check_type"),
            }
        )
    return {"tool": "Checkov", "vulnerabilities": vulns}


def _trivy(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    schema_ver = data.get("SchemaVersion")
    if schema_ver is None:
        return None
    vulns: List[Dict[str, Any]] = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "").lower()
            sev_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "unknown": "info",
            }
            severity = sev_map.get(sev, "info")
            cwes = v.get("CweIDs", [])
            cwe = cwes[0] if cwes else None
            vulns.append(
                {
                    "rule_id": v.get("VulnerabilityID"),
                    "severity": severity,
                    "message": v.get("Title") or v.get("Description", ""),
                    "file_path": target,
                    "start_line": None,
                    "end_line": None,
                    "start_column": None,
                    "code_snippet": None,
                    "cwe": cwe,
                    "tags": v.get("PkgName"),
                }
            )
    return {"tool": "Trivy", "vulnerabilities": vulns}


def _generic(data: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt to extract a flat list of findings from unknown JSON."""
    # Look for a list at the top level or inside common keys
    findings_list: Optional[List[Any]] = None
    if isinstance(data, list):
        findings_list = data
    else:
        for key in ("findings", "issues", "vulnerabilities", "alerts", "results"):
            if isinstance(data.get(key), list):
                findings_list = data[key]
                break

    if not findings_list:
        return {"tool": None, "vulnerabilities": []}

    vulns = []
    for item in findings_list:
        if not isinstance(item, dict):
            continue
        sev = (
            item.get("severity")
            or item.get("level")
            or item.get("priority")
            or "info"
        )
        vulns.append(
            {
                "rule_id": item.get("rule_id") or item.get("id") or item.get("check_id"),
                "severity": str(sev).lower(),
                "message": item.get("message") or item.get("description") or item.get("title"),
                "file_path": item.get("file") or item.get("file_path") or item.get("filename"),
                "start_line": item.get("line") or item.get("start_line") or item.get("line_number"),
                "end_line": item.get("end_line"),
                "start_column": item.get("column") or item.get("start_column"),
                "code_snippet": item.get("code") or item.get("snippet"),
                "cwe": item.get("cwe"),
                "tags": item.get("tags"),
            }
        )
    return {"tool": None, "vulnerabilities": vulns}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_PARSERS = [_semgrep, _bandit, _checkov, _trivy]


def parse(data: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-detect format and parse into normalized dict."""
    for parser in _PARSERS:
        result = parser(data)
        if result is not None:
            return result
    return _generic(data)
