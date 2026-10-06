import asyncio
import json
import sys
from types import SimpleNamespace
from pathlib import Path

from app.core.ids import ObjectId
from fastapi.testclient import TestClient

from app.dependencies import get_current_user
from app.main import app
from app.routers import scans
from app.services import unified_scan

client = TestClient(app)


def test_aggregate_scanner_status_distinguishes_completed_failed_incomplete_and_running():
    assert unified_scan.aggregate_scanner_status({name: "completed" for name in unified_scan.SCANNERS}) == "completed"
    assert unified_scan.aggregate_scanner_status({
        "nmap": "completed", "nikto": "failed", "wapiti": "timed_out",
    }) == "failed"
    assert unified_scan.aggregate_scanner_status({"nmap": "completed", "nikto": "unavailable"}) == "incomplete"
    assert unified_scan.aggregate_scanner_status({name: "failed" for name in unified_scan.SCANNERS}) == "failed"
    assert unified_scan.aggregate_scanner_status({"nmap": "completed", "nikto": "running"}) == "running"


def test_validate_assessment_target_normalizes_host_and_rejects_credentials(monkeypatch):
    monkeypatch.setattr(unified_scan, "validate_url_for_ssrf", lambda target, lab_mode=False: target)

    assert unified_scan.validate_assessment_target(" Example.COM ") == "https://example.com/"

    try:
        unified_scan.validate_assessment_target("https://user:pass@example.com/")
    except unified_scan.AssessmentTargetError:
        pass
    else:
        raise AssertionError("Target credentials must be rejected")


def test_timed_process_command_kills_overdue_child_and_preserves_partial_output():
    async def run():
        return await unified_scan._timed_process_command(
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"],
            timeout_seconds=0.05,
            grace_seconds=0.05,
        )

    result = asyncio.run(run())

    assert result["status"] == "timed_out"
    assert b"started" in result["stdout"]
    assert result["completed_at"]


def test_capture_command_preserves_helper_stdout_stderr_and_exit_code():
    async def run():
        return await unified_scan._capture_command([
            sys.executable,
            "-c",
            "import sys; print('helper stdout'); print('helper stderr', file=sys.stderr); sys.exit(7)",
        ])

    exit_code, stdout, stderr = asyncio.run(run())

    assert exit_code == 7
    assert b"helper stdout" in stdout
    assert b"helper stderr" in stderr


def test_orchestration_keeps_running_after_timeout_and_process_failure(monkeypatch, tmp_path):
    scan_id = str(ObjectId())
    record = {
        "_id": ObjectId(scan_id),
        "owner_id": "user-1",
        "asset_id": "asset-1",
        "target_url": "http://127.0.0.1:5173/",
        "lab_mode": False,
        "status": "queued",
    }

    class ScansCollection:
        async def find_one(self, query):
            return record

        async def update_one(self, query, update):
            record.update(update["$set"])

    class Database:
        scans = ScansCollection()

    monkeypatch.setattr(unified_scan, "SCAN_RESULTS_ROOT", tmp_path)
    monkeypatch.setattr(unified_scan, "WORDLIST_PATH", tmp_path / "wordlist.txt")
    monkeypatch.setattr(unified_scan, "validate_assessment_target", lambda target, lab_mode=False: target)

    async def available_preflight(scanners):
        return {
            "status": "available", "runtime": "wsl", "distribution": "Ubuntu",
            "wsl_available": True, "distribution_installed": True,
            "distribution_state_before_command": "stopped", "command_executable": True,
            "stdout": "", "stderr": "", "error": None,
            "scanners": {
                name: {"scanner": name, "available": True, "status": "available",
                       "binary": name, "path": f"/usr/bin/{name}", "stdout": "",
                       "stderr": "", "exit_code": 0, "error": None}
                for name in scanners
            },
        }

    monkeypatch.setattr(unified_scan.scanner_runtime, "preflight_matrix", available_preflight)

    async def fixed_gateway():
        return "172.30.32.1"

    async def no_wildcard(target, host_header=None):
        return 1444

    async def build_command(scanner, target, output_dir, timeout, wordlist, wildcard, gateway):
        return [scanner], output_dir / f"{scanner}.txt"

    output_by_scanner = {
        "nmap": b"80/tcp open http\n",
        "nikto": b"partial Nikto output\n",
        "wapiti": b"Vulnerability SQL Injection:\nUrl: http://127.0.0.1:5173/\nParameter: id\n",
        "sqlmap": b"",
        "gobuster": b"favicon.svg          (Status: 200) [Size: 9522]\nicons.svg            (Status: 200) [Size: 5031]\n",
    }
    completed_status = {
        "nmap": "completed",
        "nikto": "timed_out",
        "wapiti": "completed",
        "sqlmap": "failed",
        "gobuster": "completed",
    }
    started = []
    all_started = asyncio.Event()

    async def run_process(command, timeout):
        scanner = command[0]
        started.append(scanner)
        if len(started) == len(unified_scan.SCANNERS):
            all_started.set()
        await asyncio.wait_for(all_started.wait(), timeout=1)
        status = completed_status[scanner]
        return {
            "status": status,
            "exit_code": 124 if status == "timed_out" else (2 if status == "failed" else 0),
            "started_at": "started",
            "completed_at": "completed",
            "stdout": output_by_scanner[scanner],
            "stderr": b"simulated SQLMap error" if status == "failed" else b"",
            "error": "simulated timeout" if status == "timed_out" else ("simulated failure" if status == "failed" else None),
        }

    monkeypatch.setattr(unified_scan, "_wsl_host_gateway", fixed_gateway)
    monkeypatch.setattr(unified_scan, "_wildcard_response_size", no_wildcard)
    monkeypatch.setattr(unified_scan, "_build_scanner_command", build_command)
    monkeypatch.setattr(unified_scan, "_timed_process_command", run_process)
    async def technology_detection(target):
        return {"tool": "Technology Fingerprinting", "status": "completed", "technologies": [], "classification": "informational"}

    monkeypatch.setattr(unified_scan, "_run_wappalyzer", technology_detection)

    asyncio.run(unified_scan.run_unified_assessment(scan_id, Database()))

    scan_dir = tmp_path / scan_id
    status_data = json.loads((scan_dir / "scan-status.json").read_text(encoding="utf-8"))
    assert record["status"] == "failed", record.get("error_message")
    assert record["security_score"] is None
    combined = record["combined_results"]
    assert combined["status"] == "failed"
    assert status_data["status"] == "failed"
    assert set(started) == set(unified_scan.SCANNERS)
    assert all(combined["scanner_details"][name]["execution_seconds"] >= 0 for name in unified_scan.SCANNERS)
    assert status_data["scanners"] == completed_status
    assert combined["scanner_status"] == completed_status
    assert len(combined["incomplete"]) == 2
    assert {item["scanner"] for item in combined["incomplete"]} == {"nikto", "sqlmap"}
    assert [item["path"] for item in combined["informational"] if item["scanner"] == "gobuster"] == [
        "/favicon.svg", "/icons.svg"
    ]
    assert all(item["verification_status"] == "unverified" for item in combined["informational"] if item["scanner"] == "gobuster")
    assert all((scan_dir / f"{scanner}.txt").exists() for scanner in unified_scan.SCANNERS)
    assert (scan_dir / "security_assessment_report.md").exists()
    assert record["total_findings"] == 0
    assert not hasattr(Database(), "vulnerabilities")


def test_all_scanner_failure_aggregates_to_failed():
    states = {name: "failed" for name in unified_scan.SCANNERS}
    assert unified_scan.aggregate_scanner_status(states) == "failed"


def test_runtime_matrix_routes_nikto_through_wsl_on_windows(monkeypatch, tmp_path):
    async def wsl_target(_target, _gateway=None):
        return "http://172.30.32.1:5173/"

    async def wsl_path(path):
        return f"/mnt/e/{Path(path).name}"

    monkeypatch.setattr(unified_scan, "_target_for_wsl", wsl_target)
    monkeypatch.setattr(unified_scan, "_wsl_path", wsl_path)
    monkeypatch.setattr(unified_scan.os, "name", "nt", raising=False)

    async def build_all():
        return {
            scanner: await unified_scan._build_scanner_command(
                scanner, "http://127.0.0.1:5173/", tmp_path, 30,
                tmp_path / "wordlist.txt", None, "172.30.32.1",
            )
            for scanner in unified_scan.SCANNERS
        }

    commands = asyncio.run(build_all())
    nikto_command = commands["nikto"][0]
    assert nikto_command[:5] == ["wsl.exe", "-d", "Ubuntu", "--", "nikto"]
    assert "http://172.30.32.1:5173/" in nikto_command
    assert "nikto" in nikto_command
    assert "-output" in nikto_command
    assert "-vhost" in nikto_command
    assert "127.0.0.1:5173" in nikto_command
    assert unified_scan._scanner_runtime_specs()["nikto"]["runtime"] == "wsl"
    assert unified_scan._scanner_runtime_specs()["nikto"]["binary"] == "nikto"
    for scanner in ("nmap", "wapiti", "sqlmap", "gobuster"):
        assert "http://172.30.32.1:5173/" in commands[scanner][0] or scanner == "nmap"
    assert "--store-session" in commands["wapiti"][0]
    assert "Host: 127.0.0.1:5173" in commands["wapiti"][0]
    assert "--host" in commands["sqlmap"][0]
    assert "Host: 127.0.0.1:5173" in commands["gobuster"][0]


def test_wsl_gateway_is_parsed_dynamically_from_default_route(monkeypatch):
    from app.services.scanner_runtime import CommandResult

    async def route_probe(command, timeout=10):
        assert command == ["ip", "route", "show", "default"]
        return CommandResult("completed", 0, b"default via 10.42.0.1 dev eth0\n", b"", None, 0.01)

    monkeypatch.setattr(unified_scan.os, "name", "nt", raising=False)
    monkeypatch.setattr(unified_scan.scanner_runtime, "capture_runtime", route_probe)

    assert asyncio.run(unified_scan._wsl_host_gateway()) == "10.42.0.1"


def test_wsl_loopback_target_uses_dynamic_gateway_and_external_target_is_unchanged(monkeypatch):
    monkeypatch.setattr(unified_scan, "_is_wsl_host", lambda: True)

    async def gateway():
        return "10.42.0.1"

    monkeypatch.setattr(unified_scan, "_wsl_host_gateway", gateway)

    local_target = "http://127.0.0.1:5173/vulnerabilities"
    external_target = "https://example.com/scan"

    assert asyncio.run(unified_scan._target_for_scanner_runtime(local_target)) == (
        "http://10.42.0.1:5173/vulnerabilities"
    )
    assert asyncio.run(unified_scan._target_for_scanner_runtime(external_target)) == external_target


def test_scanner_runtime_target_rewrites_local_docker_target_only(monkeypatch):
    monkeypatch.setattr(unified_scan, "_is_docker_container", lambda: True)

    local_target = "http://127.0.0.1:5173/vulnerabilities"
    external_target = "https://example.com/scan"

    assert asyncio.run(unified_scan._target_for_scanner_runtime(local_target)) == (
        "http://host.docker.internal:5173/vulnerabilities"
    )
    assert asyncio.run(unified_scan._target_for_scanner_runtime(external_target)) == external_target
    assert unified_scan._runtime_host_header(local_target) == "127.0.0.1:5173"


def test_all_scanner_commands_use_resolved_container_target_and_preserve_original(monkeypatch, tmp_path):
    monkeypatch.setattr(unified_scan, "_is_docker_container", lambda: True)

    async def local_path(path):
        return str(path)

    monkeypatch.setattr(unified_scan, "_wsl_path", local_path)
    monkeypatch.setattr(unified_scan.scanner_runtime, "wrap_runtime_command", lambda command: list(command))
    original_target = "http://127.0.0.1:5173/"

    async def build_all():
        return {
            scanner: (await unified_scan._build_scanner_command(
                scanner, original_target, tmp_path, 30,
                tmp_path / "wordlist.txt", 1428, None,
            ))[0]
            for scanner in unified_scan.SCANNERS
        }

    commands = asyncio.run(build_all())

    assert original_target == "http://127.0.0.1:5173/"
    assert "host.docker.internal" in commands["nmap"]
    for scanner in ("nikto", "wapiti", "sqlmap", "gobuster"):
        assert any("host.docker.internal" in argument for argument in commands[scanner])
    assert "Host: 127.0.0.1:5173" in commands["wapiti"]
    assert "127.0.0.1:5173" in commands["sqlmap"]
    assert "Host: 127.0.0.1:5173" in commands["gobuster"]
    assert "-vhost" not in commands["nikto"]


def test_successful_exit_without_scanner_output_is_not_marked_completed(monkeypatch, tmp_path):
    scan_id = str(ObjectId())
    record = {
        "_id": ObjectId(scan_id), "owner_id": "user", "asset_id": "asset",
        "target_url": "https://example.com/", "lab_mode": False, "status": "queued",
    }

    class ScansCollection:
        async def find_one(self, query):
            return record

        async def update_one(self, query, update):
            record.update(update["$set"])

    class Database:
        scans = ScansCollection()

    async def preflight(scanners):
        return {"status": "available", "command_executable": True,
                "scanners": {name: {"available": True} for name in scanners}}

    async def no_wildcard(target, host_header=None):
        return None

    async def build(scanner, target, output_dir, timeout, wordlist, wildcard, gateway):
        return [scanner], output_dir / f"{scanner}.txt"

    async def empty_success(command, timeout):
        return {"status": "completed", "exit_code": 0, "stdout": b"", "stderr": b"",
                "error": None, "started_at": "start", "completed_at": "end"}

    async def no_technology(_target):
        return {"status": "completed", "technologies": [], "classification": "informational"}

    monkeypatch.setattr(unified_scan, "SCAN_RESULTS_ROOT", tmp_path)
    monkeypatch.setattr(unified_scan, "validate_assessment_target", lambda target, lab_mode=False: target)
    monkeypatch.setattr(unified_scan.scanner_runtime, "preflight_matrix", preflight)
    monkeypatch.setattr(unified_scan, "_wildcard_response_size", no_wildcard)
    monkeypatch.setattr(unified_scan, "_build_scanner_command", build)
    monkeypatch.setattr(unified_scan, "_timed_process_command", empty_success)
    monkeypatch.setattr(unified_scan, "_run_wappalyzer", no_technology)

    asyncio.run(unified_scan.run_unified_assessment(scan_id, Database()))

    assert record["scanner_status"]["nmap"] == "failed"
    assert record["scanner_details"]["nmap"]["failure_stage"] == "result_validation"
    assert "no usable output" in record["scanner_details"]["nmap"]["error"]


def test_nikto_connection_error_output_is_not_usable(tmp_path):
    report = tmp_path / "nikto.txt"
    report.write_text("+ [FAIL] Unable to connect to host.docker.internal:5173.\n", encoding="utf-8")

    assert "could not connect" in unified_scan._scanner_output_error("nikto", b"", report)
    assert unified_scan._scanner_output_error("sqlmap", b"no parameters found", report) is None


def test_runtime_matrix_routes_nikto_to_local_binary_in_docker(monkeypatch):
    monkeypatch.setattr(unified_scan, "_is_docker_container", lambda: True)

    specs = unified_scan._scanner_runtime_specs()

    assert specs["nikto"]["runtime"] == "wsl"
    assert specs["nikto"]["binary"] == "nikto"


def test_existing_scan_workflow_schedules_unified_mode(monkeypatch):
    asset_id = ObjectId()
    inserted_scan = {}
    scheduled = []

    class Assets:
        async def find_one(self, query):
            return {"_id": asset_id, "owner_id": "user-1", "target_urls": ["http://127.0.0.1:5173/"]}

    class Scans:
        async def insert_one(self, scan):
            inserted_scan.update(scan)
            return SimpleNamespace(inserted_id=ObjectId())

    class Database:
        assets = Assets()
        scans = Scans()

    async def no_op_scan(scan_id, db):
        scheduled.append((scan_id, db))

    async def no_op_audit(*args, **kwargs):
        return None

    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "user-1"})
    monkeypatch.setattr(scans, "get_database", lambda: Database())
    monkeypatch.setattr(scans, "validate_assessment_target", lambda target, lab_mode=False: target)
    monkeypatch.setattr(scans, "run_unified_assessment", no_op_scan)
    monkeypatch.setattr(scans, "log_audit_action", no_op_audit)

    response = client.post("/api/scans/", json={
        "asset_id": str(asset_id),
        "target_urls": ["http://127.0.0.1:5173/"],
        "authorized": True,
        "lab_mode": False,
        "kali_mode": False,
        "unified_mode": True,
    })

    assert response.status_code == 201, response.text
    assert response.json()["unified_mode"] is True
    assert len(scheduled) == 1
    assert inserted_scan["unified_mode"] is True


def test_assessment_status_and_results_require_authentication():
    scan_id = str(ObjectId())

    status_response = client.get(f"/api/scans/{scan_id}/assessment-status")
    results_response = client.get(f"/api/scans/{scan_id}/assessment-results")

    assert status_response.status_code in (401, 403)
    assert results_response.status_code in (401, 403)


def test_assessment_status_and_results_are_owner_scoped(monkeypatch):
    scan_id = ObjectId()
    record = {
        "_id": scan_id,
        "owner_id": "user-1",
        "target_url": "http://127.0.0.1:5173/",
        "unified_mode": True,
        "status": "failed",
        "progress": 100,
        "scanner_status": {name: "failed" for name in unified_scan.SCANNERS},
        "combined_results": {"scan_id": str(scan_id), "status": "failed", "confirmed": [], "potential": [], "informational": [], "incomplete": []},
    }

    class Scans:
        async def find_one(self, query):
            if query.get("owner_id") != "user-1" or query.get("_id") != scan_id:
                return None
            return record

    class Database:
        scans = Scans()

    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "user-1"})
    monkeypatch.setattr(scans, "get_database", lambda: Database())

    status_response = client.get(f"/api/scans/{scan_id}/assessment-status")
    results_response = client.get(f"/api/scans/{scan_id}/assessment-results")

    assert status_response.status_code == 200
    assert status_response.json()["status"] == "failed"
    assert status_response.json()["scanners"]["gobuster"] == "failed"
    assert results_response.status_code == 200
    assert results_response.json()["scan_id"] == str(scan_id)
    assert results_response.json()["status"] == "failed"


def test_unified_scan_requires_authorization(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "user-1"})
    response = client.post("/api/scans/", json={
        "asset_id": str(ObjectId()),
        "authorized": False,
        "unified_mode": True,
    })

    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot create scan without confirmed authorization."


def test_local_demo_target_runs_all_five_scanner_jobs_and_serializes(monkeypatch, tmp_path):
    scan_id = str(ObjectId())
    local_target = "http://127.0.0.1:5173"
    record = {"_id": ObjectId(scan_id), "owner_id": "local-user", "asset_id": "local-asset",
              "target_url": local_target, "lab_mode": True, "status": "queued"}

    class ScansCollection:
        async def find_one(self, query):
            return record

        async def update_one(self, query, update):
            record.update(update["$set"])

    class Database:
        scans = ScansCollection()

    async def preflight(scanners):
        return {"status": "available", "runtime": "wsl", "distribution": "Ubuntu",
                "wsl_available": True, "distribution_installed": True,
                "distribution_state_before_command": "stopped", "command_executable": True,
                "stdout": "", "stderr": "", "error": None,
                "scanners": {name: {"scanner": name, "available": True, "status": "available",
                                    "binary": name, "path": f"/usr/bin/{name}", "stdout": "",
                                    "stderr": "", "exit_code": 0, "error": None}
                             for name in scanners}}

    async def build(scanner, target, output_dir, timeout, wordlist, wildcard, gateway):
        assert target == local_target + "/"
        return [scanner], output_dir / f"{scanner}.txt"

    async def execute(command, timeout):
        return {"status": "completed", "exit_code": 0, "stdout": b"scanner completed\n", "stderr": b"",
                "error": None, "started_at": "start", "completed_at": "end"}

    async def gateway():
        return "172.20.0.1"

    async def no_wildcard(_target, host_header=None):
        return None

    async def no_technology(_target):
        return {"status": "completed", "tool": "Technology Fingerprinting", "technologies": [],
                "classification": "informational"}

    monkeypatch.setattr(unified_scan, "SCAN_RESULTS_ROOT", tmp_path)
    monkeypatch.setattr(unified_scan, "validate_assessment_target", lambda target, lab_mode=False: target.rstrip("/") + "/")
    monkeypatch.setattr(unified_scan.scanner_runtime, "preflight_matrix", preflight)
    monkeypatch.setattr(unified_scan, "_wsl_host_gateway", gateway)
    monkeypatch.setattr(unified_scan, "_wildcard_response_size", no_wildcard)
    monkeypatch.setattr(unified_scan, "_build_scanner_command", build)
    monkeypatch.setattr(unified_scan, "_timed_process_command", execute)
    monkeypatch.setattr(unified_scan, "_run_wappalyzer", no_technology)

    asyncio.run(unified_scan.run_unified_assessment(scan_id, Database()))

    assert record["status"] == "completed"
    assert record["combined_results"]["target"] == local_target + "/"
    assert set(record["scanner_status"]) == set(unified_scan.SCANNERS)
    assert all(record["scanner_status"][name] == "completed" for name in unified_scan.SCANNERS)
    json.dumps(record["combined_results"])
    saved_results = json.loads((tmp_path / scan_id / "unified-results.json").read_text(encoding="utf-8"))
    assert saved_results["status"] == "completed"
    assert saved_results["target"] == local_target + "/"
