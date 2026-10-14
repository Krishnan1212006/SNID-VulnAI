import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.dependencies import get_current_user
from app.services.domain_assessment import (
    normalize_target_input,
    is_private_ip,
    detect_technologies_and_architecture,
    assess_sql_injection,
    ACTIVE_DOMAIN_JOBS,
)

client = TestClient(app)


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "test-user-domain"})
    return client


def test_target_input_normalization():
    """Verify target URL and domain parsing."""
    dom, base, target = normalize_target_input("example.com")
    assert dom == "example.com"
    assert base == "https://example.com"
    assert target == "https://example.com"

    dom2, base2, target2 = normalize_target_input("http://api.target.org:8080/v1/users?id=1")
    assert dom2 == "api.target.org"
    assert base2 == "http://api.target.org:8080"
    assert target2 == "http://api.target.org:8080/v1/users?id=1"


def test_private_ip_ssrf_detection():
    """Verify SSRF defense identifies loopback, private, and link-local IPs."""
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.5.10") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("169.254.1.1") is True
    assert is_private_ip("::1") is True

    # Public IPs are not private
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("93.184.216.34") is False


@pytest.mark.asyncio
async def test_architecture_classification():
    """Verify Static vs Dynamic architecture indicators and rationales."""
    # Dynamic indicators: Set-Cookie, dynamic session, server framework
    dynamic_http = {
        "headers": {
            "server": "nginx/1.18.0",
            "set-cookie": "PHPSESSID=abc123456; path=/",
            "x-powered-by": "PHP/7.4",
            "cache-control": "no-store, no-cache, must-revalidate",
        },
        "cookies": ["PHPSESSID"],
        "body_sample": "<html><body>Dashboard</body></html>",
    }
    dyn_res = await detect_technologies_and_architecture("dyn.test", "https://dyn.test", dynamic_http)
    assert dyn_res["architecture_label"] == "Dynamic indicators"
    assert any("Dynamic state management" in r for r in dyn_res["architecture_evidence"])

    # Static indicators: ETag, public cache, no cookies
    static_http = {
        "headers": {
            "server": "GitHubNet",
            "etag": '"5d-5c8e3"',
            "cache-control": "max-age=600, public",
        },
        "cookies": [],
        "body_sample": "<html><body>Static Docs</body></html>",
    }
    stat_res = await detect_technologies_and_architecture("docs.test", "https://docs.test", static_http)
    assert stat_res["architecture_label"] == "Static indicators"
    assert any("ETag" in r for r in stat_res["architecture_evidence"])


@pytest.mark.asyncio
async def test_sqli_passive_assessment_structure():
    """Verify safe passive SQLi evaluation identifies parameters without destructive testing."""
    url_with_params = "https://example.com/search?q=test&page=1"
    res = await assess_sql_injection(url_with_params, active_testing_authorized=False)
    assert res["passive_status"] == "Parameters Identified"
    assert res["active_status"] == "Not tested (Active testing requires explicit authorization)"
    assert len(res["limitations"]) > 0


def test_api_domain_assess_unauthorized_rejected(auth_client):
    """Verify that launching domain assessment without explicit authorization is rejected."""
    resp = auth_client.post(
        "/api/domain/assess",
        json={"target": "example.com", "authorized": False},
    )
    assert resp.status_code == 400
    assert "authorization" in resp.json()["detail"].lower()


def test_api_domain_history_endpoint(auth_client, monkeypatch):
    """Verify listing assessment history."""
    class FakeCursor:
        def sort(self, *args, **kwargs):
            return self
        async def to_list(self, limit):
            return [{
                "_id": "507f1f77bcf86cd799439011",
                "job_id": "dom-test12345",
                "domain": "test.org",
                "target_url": "https://test.org",
                "status": "COMPLETED",
                "start_time": "2026-10-14T06:00:00Z",
                "duration_seconds": 2.5,
                "technology": {"architecture_label": "Static indicators"},
                "resolved_ips": ["93.184.216.34"],
                "nmap": {"open_ports": [{"port": 80}, {"port": 443}]},
            }]

    class FakeDB:
        domain_assessments = type("Col", (), {"find": lambda self, q: FakeCursor()})()

    monkeypatch.setattr("app.routers.domain.get_database", lambda: FakeDB())

    resp = auth_client.get("/api/domain/history")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["domain"] == "test.org"
    assert data[0]["open_ports_count"] == 2


def test_api_domain_cancel(auth_client):
    """Verify cancelling an active domain assessment."""
    job_id = "dom-canceltarget"
    ACTIVE_DOMAIN_JOBS[job_id] = {"status": "RUNNING", "cancelled": False}

    resp = auth_client.post(f"/api/domain/assess/{job_id}/cancel")
    assert resp.status_code == 200
    assert ACTIVE_DOMAIN_JOBS[job_id]["cancelled"] is True
    assert ACTIVE_DOMAIN_JOBS[job_id]["status"] == "CANCELLED"
