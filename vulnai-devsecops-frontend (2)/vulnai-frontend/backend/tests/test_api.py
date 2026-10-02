import pytest
from app.core.ids import ObjectId
from fastapi.testclient import TestClient
from jose import jwt
from app.main import app
from app.dependencies import get_current_user
from app.core.config import settings
import app.dependencies as dependencies
from app.parsers.gobuster_parser import parse_gobuster_observations
from app.routers import scans
from app.services.kali_scanner import validate_wapiti_target, normalize_wapiti_findings

client = TestClient(app)
GOBUSTER_OUTPUT = """favicon.svg          (Status: 200) [Size: 9522]
icons.svg            (Status: 200) [Size: 5031]
"""


@pytest.fixture
def authenticated_client(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "test-user"})
    return client


def test_health_check():
    """Verify the health endpoint works"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "vulnai-backend"}


def test_latest_unified_observations_is_owner_scoped(authenticated_client, monkeypatch):
    class Scans:
        async def find_one(self, query, sort=None):
            assert query["owner_id"] == "test-user"
            assert query["unified_mode"] is True
            return {
                "_id": ObjectId(), "target_url": "http://127.0.0.1:5173/", "status": "incomplete",
                "combined_results": {
                    "status": "incomplete", "confirmed": [], "potential": [], "informational": [],
                    "incomplete": [{"scanner": "nikto", "classification": "incomplete"}],
                },
            }

    class Database:
        scans = Scans()

    from app.routers import vulnerabilities
    monkeypatch.setattr(vulnerabilities, "get_database", lambda: Database())
    response = authenticated_client.get("/api/vulnerabilities/unified-observations")

    assert response.status_code == 200
    assert response.json()["status"] == "incomplete"
    assert response.json()["target"] == "http://127.0.0.1:5173/"
    assert response.json()["incomplete"][0]["scanner"] == "nikto"


def test_runtime_status_exposes_the_scanner_matrix(authenticated_client, monkeypatch):
    async def matrix_preflight(_scanners):
        return {
            "status": "partial",
            "runtime": "matrix",
            "scanners": {
                "nmap": {"runtime": "wsl", "status": "available", "available": True},
                "nikto": {"runtime": "docker", "status": "unavailable", "available": False},
            },
        }

    from app.routers import scans
    monkeypatch.setattr(scans.scanner_runtime, "preflight_matrix", matrix_preflight)
    response = authenticated_client.get("/api/scans/runtime-status")

    assert response.status_code == 200
    assert response.json()["runtime"] == "matrix"
    assert response.json()["scanners"]["nmap"]["runtime"] == "wsl"
    assert response.json()["scanners"]["nikto"]["runtime"] == "docker"


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


def test_parse_gobuster_observations_preserves_current_findings():
    observations = parse_gobuster_observations(GOBUSTER_OUTPUT)

    assert [(item["path"], item["status_code"], item["response_size"]) for item in observations] == [
        ("/favicon.svg", 200, 9522),
        ("/icons.svg", 200, 5031),
    ]
    assert all(item["verification_status"] == "unverified" for item in observations)
    assert all(item["classification"] == "informational" for item in observations)
    assert [item["raw_line"] for item in observations] == GOBUSTER_OUTPUT.splitlines()[:2]


def test_parse_gobuster_observations_ignores_malformed_lines():
    output = "banner text\n/favicon.svg (Status: nope) [Size: 9522]\n/icons.svg (Status: 200) [Size: 5031] trailing garbage"

    assert parse_gobuster_observations(output) == []


def test_get_gobuster_results_requires_authentication(monkeypatch, tmp_path):
    monkeypatch.setattr(scans, "GOBUSTER_RESULT", tmp_path / "gobuster.txt")

    response = client.get("/api/scans/gobuster")

    assert response.status_code in (401, 403)


def test_get_gobuster_results_returns_informational_observations_without_database_access(
    authenticated_client, monkeypatch, tmp_path
):
    result_file = tmp_path / "gobuster.txt"
    result_file.write_text(GOBUSTER_OUTPUT, encoding="utf-8")
    monkeypatch.setattr(scans, "GOBUSTER_RESULT", result_file)
    monkeypatch.setattr(scans, "get_database", lambda: pytest.fail("Gobuster observations must not query or update vulnerabilities"))

    response = authenticated_client.get("/api/scans/gobuster")

    assert response.status_code == 200
    data = response.json()
    assert data["scanner"] == "gobuster"
    assert data["source"] == "scan-results/gobuster.txt"
    assert data["status"] == "completed"
    assert data["raw_output"] == GOBUSTER_OUTPUT
    assert len(data["observations"]) == 2
    assert "vulnerabilities" not in data
    assert [item["path"] for item in data["observations"]] == ["/favicon.svg", "/icons.svg"]
    assert all(item["status"] == "unverified" for item in data["observations"])
    assert all(item["severity"] == "informational" for item in data["observations"])
    assert all(item["message"] in GOBUSTER_OUTPUT for item in data["observations"])


def test_get_gobuster_results_accepts_application_jwt(monkeypatch, tmp_path):
    result_file = tmp_path / "gobuster.txt"
    result_file.write_text(GOBUSTER_OUTPUT, encoding="utf-8")
    monkeypatch.setattr(scans, "GOBUSTER_RESULT", result_file)

    class Users:
        async def find_one(self, query):
            return {"_id": query["_id"]}

    class Database:
        users = Users()

    user_id = ObjectId()
    token = jwt.encode(
        {"sub": str(user_id)},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    monkeypatch.setattr(dependencies, "get_database", lambda: Database())

    response = client.get(
        "/api/scans/gobuster",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert len(response.json()["observations"]) == 2


def test_get_gobuster_results_handles_empty_file(authenticated_client, monkeypatch, tmp_path):
    result_file = tmp_path / "gobuster.txt"
    result_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(scans, "GOBUSTER_RESULT", result_file)

    response = authenticated_client.get("/api/scans/gobuster")

    assert response.status_code == 200
    assert response.json()["raw_output"] == ""
    assert response.json()["observations"] == []


def test_get_gobuster_results_handles_missing_file(authenticated_client, monkeypatch, tmp_path):
    monkeypatch.setattr(scans, "GOBUSTER_RESULT", tmp_path / "missing.txt")

    response = authenticated_client.get("/api/scans/gobuster")

    assert response.status_code == 404
    assert response.json()["detail"] == "Gobuster result not found"


def test_get_gobuster_results_preserves_malformed_output_without_crashing(
    authenticated_client, monkeypatch, tmp_path
):
    malformed_output = "Gobuster banner\n/favicon.svg (Status: nope) [Size: 9522]\n"
    result_file = tmp_path / "gobuster.txt"
    result_file.write_text(malformed_output, encoding="utf-8")
    monkeypatch.setattr(scans, "GOBUSTER_RESULT", result_file)

    response = authenticated_client.get("/api/scans/gobuster")

    assert response.status_code == 200
    assert response.json()["raw_output"] == malformed_output
    assert response.json()["observations"] == []
