import pytest
import json
from app.services.mitre_attack import (
    map_finding_to_mitre,
    build_mitre_navigator_layer,
    get_mitre_tactics_matrix,
    MITRE_TACTICS,
    TECHNIQUE_CATALOG,
)


def test_map_sqli_finding_to_initial_access():
    sqli_finding = {
        "title": "SQL Injection in parameter id",
        "category": "Injection",
        "owasp_category": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "severity": "HIGH",
    }
    mapped = map_finding_to_mitre(sqli_finding)
    assert mapped["technique_id"] == "T1190"
    assert mapped["tactic_id"] == "TA0001"
    assert mapped["tactic_name"] == "Initial Access"
    assert "Exploit Public-Facing Application" in mapped["technique_name"]
    assert len(mapped["mitigations"]) > 0
    assert any("WAF" in m["description"] or "Exploit" in m["name"] for m in mapped["mitigations"])
    assert any("Lazarus" in g or "APT" in g for g in mapped["threat_groups"])


def test_map_xss_finding_to_execution():
    xss_finding = {
        "title": "Cross-Site Scripting (XSS) in query string",
        "category": "Cross-Site Scripting",
        "owasp_category": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "severity": "MEDIUM",
    }
    mapped = map_finding_to_mitre(xss_finding)
    assert mapped["technique_id"] == "T1059.007"
    assert mapped["tactic_id"] == "TA0002"
    assert mapped["tactic_name"] == "Execution"


def test_map_wireless_and_recon_findings():
    deauth_finding = {
        "title": "Deauthentication Flood Alert detected on wlan0",
        "severity": "HIGH",
    }
    mapped_deauth = map_finding_to_mitre(deauth_finding)
    assert mapped_deauth["technique_id"] == "T1498"
    assert mapped_deauth["tactic_id"] == "TA0040"

    port_finding = {
        "title": "Open Port Discovery: 22/tcp open ssh",
        "severity": "INFO",
    }
    mapped_port = map_finding_to_mitre(port_finding)
    assert mapped_port["technique_id"] == "T1046"
    assert mapped_port["tactic_id"] == "TA0007"


def test_build_mitre_navigator_layer_format():
    findings = [
        {"title": "SQL Injection", "severity": "HIGH", "endpoint": "/api/users"},
        {"title": "Open Port 80", "severity": "INFO", "endpoint": "/"},
        {"title": "Missing CSP", "severity": "LOW", "endpoint": "/"},
    ]
    layer = build_mitre_navigator_layer(findings, scan_id="scan-123", target="http://test.local")
    
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert "VulnAI Threat Posture" in layer["name"]
    assert len(layer["techniques"]) >= 2

    # Check color coding
    high_tech = next(t for t in layer["techniques"] if t["techniqueID"] == "T1190")
    assert high_tech["score"] == 3
    assert high_tech["color"] == "#ef4444"
    assert "SQL Injection" in high_tech["comment"]


def test_get_mitre_tactics_matrix():
    findings = [
        {"title": "SQL Injection", "severity": "HIGH"},
        {"title": "Open Port 22", "severity": "INFO"},
    ]
    matrix = get_mitre_tactics_matrix(findings)
    assert matrix["active_tactics_count"] >= 2
    assert matrix["total_mapped_techniques"] >= 2
    assert "TA0001" in matrix["tactics"]
    assert matrix["tactics"]["TA0001"]["active"] is True
    assert "T1190" in matrix["tactics"]["TA0001"]["techniques"]
