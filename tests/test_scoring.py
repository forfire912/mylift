"""Tests for risk scoring engine."""
import pytest
from backend.scoring import compute_risk_score


class TestComputeRiskScore:
    def test_basic_high_severity(self):
        result = compute_risk_score(
            sast_severity="high",
            llm_confidence=0.9,
            is_vulnerable=True,
            code_snippet="ptr = NULL; *ptr = 1;",
            execution_path=["step1", "step2"],
        )
        assert result["risk_score"] > 50
        assert result["final_severity"] in ("critical", "high", "medium", "low", "info")
        assert "breakdown" in result

    def test_false_positive_reduces_score(self):
        result_tp = compute_risk_score("high", 0.9, True, "strcpy(buf, src);", [])
        result_fp = compute_risk_score("high", 0.9, False, "strcpy(buf, src);", [])
        assert result_tp["risk_score"] > result_fp["risk_score"]

    def test_no_llm_analysis(self):
        result = compute_risk_score("medium", None, None, None, None)
        assert 0 <= result["risk_score"] <= 100
        assert result["final_severity"] is not None

    def test_score_bounds(self):
        # Should never exceed 100
        result = compute_risk_score(
            "critical", 1.0, True,
            " ".join(["strcpy malloc free NULL system exec"] * 10),
            ["s"] * 20
        )
        assert result["risk_score"] <= 100.0
        assert result["risk_score"] >= 0.0

    def test_critical_severity_high_base(self):
        result = compute_risk_score("critical", None, None, "", [])
        assert result["breakdown"]["severity_score"] == 40

    def test_info_severity_low_base(self):
        result = compute_risk_score("info", None, None, "", [])
        assert result["breakdown"]["severity_score"] == 5

    def test_code_context_risk_detected(self):
        result = compute_risk_score("medium", None, None, "strcpy malloc free NULL", [])
        assert result["breakdown"]["context_score"] > 0

    def test_trace_depth_contributes(self):
        result_no_trace = compute_risk_score("medium", None, None, "", [])
        result_with_trace = compute_risk_score("medium", None, None, "", ["s1", "s2", "s3", "s4", "s5"])
        assert result_with_trace["risk_score"] > result_no_trace["risk_score"]

    def test_severity_thresholds(self):
        critical_result = compute_risk_score("critical", 1.0, True, "strcpy", ["s"] * 5)
        assert critical_result["final_severity"] in ("critical", "high")

        info_result = compute_risk_score("info", 0.0, False, "", [])
        assert info_result["final_severity"] in ("info", "low")
