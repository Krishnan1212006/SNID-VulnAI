import asyncio
import pytest
from app.services.redaction import redact_command, redact_text
from app.services.scanner_runtime import scanner_runtime, CommandResult
from app.services.scan_job_manager import scan_job_manager


def test_redaction_secrets_in_commands_and_text():
    raw_cmd = [
        "sqlmap", "-u", "http://target.com/?token=secret1234567890abcdef",
        "--header", "Authorization: Bearer my-super-secret-jwt-token-12345",
        "--password", "MySecretP@ssw0rd!"
    ]
    redacted = redact_command(raw_cmd)
    redacted_joined = " ".join(redacted)
    assert "secret1234567890abcdef" not in redacted_joined
    assert "my-super-secret-jwt-token-12345" not in redacted_joined
    assert "MySecretP@ssw0rd!" not in redacted_joined
    assert "[REDACTED]" in redacted_joined

    raw_text = "Database error: connection to postgresql://user:super_secret_pw@host/db failed with token=secret12345"
    redacted_str = redact_text(raw_text)
    assert "super_secret_pw" not in redacted_str
    assert "secret12345" not in redacted_str
    assert "[REDACTED]" in redacted_str


def test_scan_job_manager_lifecycle():
    scan_id = "test-reliability-scan-01"
    tools = ["nmap", "nikto", "wapiti", "sqlmap", "gobuster", "wappalyzer"]
    scan_job_manager.register_scan(scan_id, "http://test.local", tools)

    job = scan_job_manager.get_scan(scan_id)
    assert job is not None
    assert job.status == "queued"
    assert job.overall_progress == 0
    assert len(job.tools) == 6

    # Start and complete one tool
    scan_job_manager.start_tool(scan_id, "nmap")
    assert job.tools["nmap"].status == "running"
    scan_job_manager.complete_tool(scan_id, "nmap", exit_code=0, status="completed")
    assert job.tools["nmap"].status == "completed"
    assert job.overall_progress == 16  # 1/6 = 16%

    # Complete remaining tools
    for tool in ["nikto", "wapiti", "sqlmap", "gobuster", "wappalyzer"]:
        scan_job_manager.start_tool(scan_id, tool)
        scan_job_manager.complete_tool(scan_id, tool, exit_code=0, status="completed")

    assert job.overall_progress == 100
    assert job.status == "completed"


def test_scan_job_manager_cancellation():
    scan_id = "test-cancellation-scan-02"
    tools = ["nmap", "nikto", "wapiti"]
    scan_job_manager.register_scan(scan_id, "http://test.local", tools)

    scan_job_manager.start_tool(scan_id, "nmap")
    scan_job_manager.cancel_scan(scan_id)

    job = scan_job_manager.get_scan(scan_id)
    assert scan_job_manager.is_cancelled(scan_id) is True
    assert job.status == "cancelled"
    assert job.overall_progress == 100
    assert job.tools["nmap"].status == "cancelled"


@pytest.mark.asyncio
async def test_scanner_runtime_process_streaming():
    stdout_chunks = []
    stderr_chunks = []

    res = await scanner_runtime.run_streaming_command(
        ["python", "-c", "import sys; sys.stdout.write('hello stdout\\n'); sys.stderr.write('hello stderr\\n')"],
        timeout=5,
        on_stdout=lambda c: stdout_chunks.append(c),
        on_stderr=lambda c: stderr_chunks.append(c),
    )

    assert res.exit_code == 0
    assert res.status == "completed"
    assert b"hello stdout" in res.stdout
    assert b"hello stderr" in res.stderr
    assert any("hello stdout" in c for c in stdout_chunks)
    assert any("hello stderr" in c for c in stderr_chunks)


@pytest.mark.asyncio
async def test_scanner_runtime_timeout_handling():
    res = await scanner_runtime.run_streaming_command(
        ["python", "-c", "import time; time.sleep(10)"],
        timeout=1,
    )
    assert res.status == "timed_out"
    assert res.exit_code in (1, 15, 124)
    assert res.error is not None
    assert "safety limit" in res.error.lower() or "timed out" in res.error.lower()


@pytest.mark.asyncio
async def test_scanner_runtime_cancellation():
    cancel_evt = asyncio.Event()

    async def trigger_cancel():
        await asyncio.sleep(0.5)
        cancel_evt.set()

    asyncio.create_task(trigger_cancel())

    res = await scanner_runtime.run_streaming_command(
        ["python", "-c", "import time; time.sleep(10)"],
        cancel_event=cancel_evt,
        timeout=5,
    )
    assert res.status == "cancelled"
    assert "cancelled" in (res.error or "").lower()
