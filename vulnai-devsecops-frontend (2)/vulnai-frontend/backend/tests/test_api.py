import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.kali_scanner import validate_wapiti_target, normalize_wapiti_findings

client = TestClient(app)


def test_health_check():
    """Verify the health endpoint works"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "vulnai-backend"}


def test_monitoring_metrics():
    """Verify monitoring subsystem returns valid structural telemetry"""
    response = client.get("/api/monitoring/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data
    assert "infrastructure" in data
    assert "cpu_usage_percent" in data["infrastructure"]


def test_validate_wapiti_target_accepts_https_urls():
    """Wapiti should only accept valid HTTP(S) targets."""
    assert validate_wapiti_target("https://example.com") == "https://example.com"

    with pytest.raises(ValueError):
        validate_wapiti_target("ftp://example.com")


def test_normalize_wapiti_findings_handles_json_payloads():
    """Primitive Wapiti JSON payloads should normalize into VulnAI findings."""
    payload = {
        "vulnerabilities": [
            {
                "level": "high",
                "name": "Cross Site Scripting",
                "description": "A reflected XSS issue was found on the search query.",
                "url": "https://example.com/search",
                "parameter": "q",
                "module": "xss"
            }
        ]
    }

    findings = normalize_wapiti_findings(payload, "scan-1", "https://example.com", "user-1", "asset-1")
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["source"] == "wapiti"
    assert findings[0]["target_url"] == "https://example.com/search"
