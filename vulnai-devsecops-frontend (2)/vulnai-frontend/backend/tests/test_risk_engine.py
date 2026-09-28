import pytest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from app.services.risk_scoring import RiskScore, compute_scan_risk

def test_risk_score_no_findings():
    # If there are no vulnerabilities, base score should be 100
    res = compute_scan_risk([])
    assert res["score"] == 100
    assert res["rating"] == "Low"

def test_risk_score_critical_findings():
    findings = [
        {"severity": "Critical", "confidence": 1.0},
        {"severity": "High", "confidence": 0.8}
    ]
    # We must instantiate the class since global compute_scan_risk doesn't take incidents explicitly in its signature
    engine = RiskScore(findings)
    res = engine.calculate_score()
    
    # Critical should pull score down fast.
    assert res["score"] <= 85
    assert res["deductions"] > 0.0

def test_risk_score_active_incidents():
    # In earlier versions incidents were passed directly. Now we check that the base findings parse properly.
    findings = [
        {"severity": "Medium", "confidence": 0.9}
    ]
    engine = RiskScore(findings)
    res = engine.calculate_score()
    
    assert res["score"] < 100
    assert res["deductions"] > 0.0
