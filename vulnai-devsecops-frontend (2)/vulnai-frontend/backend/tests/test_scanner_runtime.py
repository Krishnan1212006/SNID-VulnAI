import asyncio
import sys
import pytest

from app.services.scanner_runtime import CommandResult, ScannerRuntime

SCANNERS = {name: {"binary": name} for name in ("nmap", "nikto", "wapiti", "sqlmap", "gobuster")}


class FakeWslRuntime(ScannerRuntime):
    @property
    def uses_wsl(self):
        return True

    def __init__(self, probes, distribution="Ubuntu"):
        super().__init__(distribution)
        self.probes = probes
        self.calls = []

    async def capture_host(self, command, timeout=10):
        self.calls.append(list(command))
        key = tuple(command)
        return self.probes.get(key, CommandResult("failed", 127, b"", b"unexpected probe", "unexpected probe", 0))

    async def capture_runtime(self, command, timeout=10):
        return await self.capture_host(self.wrap_runtime_command(command), timeout)


def result(stdout=b"", stderr=b"", exit_code=0):
    return CommandResult("completed" if exit_code == 0 else "failed", exit_code, stdout, stderr,
                         None if exit_code == 0 else f"exit {exit_code}", 0.01)


def make_probes(*, distributions=b"Ubuntu\n", missing_scanner=None):
    probes = {
        ("wsl.exe", "--status"): result(),
        ("wsl.exe", "-l", "-q"): result(distributions),
        ("wsl.exe", "-l", "-v"): result(b"  NAME      STATE    VERSION\n* Ubuntu    Stopped  2\n"),
        ("wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc", "printf VULNAI_WSL_READY"): result(b"VULNAI_WSL_READY"),
    }
    for name in SCANNERS:
        probes[("wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc", f"command -v {name}")] = (
            result(b"", exit_code=1) if name == missing_scanner else result(f"/usr/bin/{name}\n".encode())
        )
    return probes


def test_detects_ubuntu_stopped_and_command_executable():
    runtime = FakeWslRuntime(make_probes())
    status = asyncio.run(runtime.preflight(SCANNERS))
    assert status["status"] == "available"
    assert status["distribution_installed"] is True
    assert status["distribution_state_before_command"] == "stopped"
    assert status["command_executable"] is True
    assert all(item["available"] for item in status["scanners"].values())


def test_detects_ubuntu_missing_without_misclassifying_wsl():
    probes = make_probes(distributions=b"Windows Subsystem for Linux has no installed distributions.\n")
    probes[("wsl.exe", "-l", "-q")] = result(
        b"Windows Subsystem for Linux has no installed distributions.\n", exit_code=1
    )
    status = asyncio.run(FakeWslRuntime(probes).preflight(SCANNERS))
    assert status["wsl_available"] is True
    assert status["distribution_installed"] is False
    assert status["status"] == "unavailable"
    assert all(item["reason"] == "distribution_missing" for item in status["scanners"].values())


def test_detects_configured_distribution_missing_while_other_distros_exist():
    runtime = FakeWslRuntime(make_probes(distributions=b"Ubuntu-22.04\nKali-Linux\n"), "Ubuntu")

    status = asyncio.run(runtime.preflight(SCANNERS))

    assert status["wsl_available"] is True
    assert status["distribution_installed"] is False
    assert status["status"] == "unavailable"
    assert all(item["reason"] == "distribution_missing" for item in status["scanners"].values())


@pytest.mark.parametrize("missing_scanner", SCANNERS)
def test_detects_each_missing_scanner_binary_independently(missing_scanner):
    status = asyncio.run(FakeWslRuntime(make_probes(missing_scanner=missing_scanner)).preflight(SCANNERS))
    assert status["status"] == "partial"
    assert status["scanners"][missing_scanner]["available"] is False
    assert status["scanners"][missing_scanner]["reason"] == "binary_missing"
    assert all(status["scanners"][name]["available"] for name in SCANNERS if name != missing_scanner)


def test_wsl_command_adapter_uses_configured_ubuntu_distribution():
    assert FakeWslRuntime({}).wrap_runtime_command(["nmap", "-Pn", "127.0.0.1"]) == [
        "wsl.exe", "-d", "Ubuntu", "--", "nmap", "-Pn", "127.0.0.1"
    ]


def test_wsl_command_adapter_rejects_blank_distribution_name_and_falls_back_to_default():
    runtime = ScannerRuntime("   ")
    assert runtime.distribution == "Ubuntu"
    assert runtime.wrap_runtime_command(["nmap", "-Pn", "127.0.0.1"]) == [
        "wsl.exe", "-d", "Ubuntu", "--", "nmap", "-Pn", "127.0.0.1"
    ]


def test_runtime_matrix_keeps_nikto_docker_failure_independent(monkeypatch):
    runtime = ScannerRuntime("Ubuntu")

    async def wsl_preflight(_scanners):
        return {"status": "available", "runtime": "wsl", "scanners": {
            name: {"scanner": name, "available": True, "status": "available"}
            for name in ("nmap", "wapiti", "sqlmap", "gobuster")
        }}

    async def docker_preflight(_scanners):
        return {"status": "unavailable", "runtime": "docker", "scanners": {
            "nikto": {"scanner": "nikto", "available": False, "status": "unavailable",
                      "reason": "docker_image_missing", "error": "Nikto image unavailable"}
        }}

    monkeypatch.setattr(runtime, "preflight", wsl_preflight)
    monkeypatch.setattr(runtime, "_preflight_docker", docker_preflight)
    status = asyncio.run(runtime.preflight_matrix({
        "nmap": {"runtime": "wsl", "binary": "nmap"},
        "nikto": {"runtime": "docker", "image": "sullo/nikto:latest"},
        "wapiti": {"runtime": "wsl", "binary": "wapiti"},
        "sqlmap": {"runtime": "wsl", "binary": "sqlmap"},
        "gobuster": {"runtime": "wsl", "binary": "gobuster"},
    }))
    assert status["status"] == "partial"
    assert status["scanners"]["nikto"]["status"] == "unavailable"
    assert all(status["scanners"][name]["available"] for name in ("nmap", "wapiti", "sqlmap", "gobuster"))


def test_command_results_preserve_success_failure_and_timeout():
    runtime = ScannerRuntime("Ubuntu")

    async def run():
        success = await runtime.run_command([sys.executable, "-c", "print('ok')"], 3)
        failure = await runtime.run_command([sys.executable, "-c", "import sys; print('bad', file=sys.stderr); sys.exit(9)"], 3)
        timeout = await runtime.run_command([sys.executable, "-c", "import time; print('started', flush=True); time.sleep(2)"], 0.05)
        return success, failure, timeout

    success, failure, timeout = asyncio.run(run())
    assert success.status == "completed" and success.exit_code == 0 and b"ok" in success.stdout
    assert failure.status == "failed" and failure.exit_code == 9 and b"bad" in failure.stderr
    assert timeout.status == "timed_out" and b"started" in timeout.stdout
