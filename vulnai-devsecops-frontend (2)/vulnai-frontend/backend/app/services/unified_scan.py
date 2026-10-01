"""Run the authorized scanners independently and preserve their evidence."""

import asyncio
import ipaddress
import json
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx
from bson import ObjectId

from app.parsers import parse_nmap, parse_nikto, parse_sqlmap, parse_wapiti
from app.parsers.gobuster_parser import parse_gobuster_observations
from app.core.paths import SCAN_RESULTS_ROOT, WORDLIST_PATH
from app.services.risk_scoring import compute_scan_risk
from app.services.scanner import SSRFProtectionError, validate_url_for_ssrf
from app.services.scanner_runtime import decode_output, scanner_runtime
from app.core.config import settings
SCANNERS = ("nmap", "nikto", "wapiti", "sqlmap", "gobuster")


def _is_docker_container() -> bool:
    return Path("/.dockerenv").is_file()


def _is_wsl_host() -> bool:
    return os.name == "nt" and not _is_docker_container()


def _preferred_runtime(scanner: str) -> str:
    if scanner == "nikto" and (_is_wsl_host() or _is_docker_container()):
        return "wsl"
    return SCANNER_BINARIES[scanner]["runtime"]


SCANNER_BINARIES = {
    "nmap": {"runtime": "wsl", "binary": "nmap"},
    "nikto": {"runtime": "docker", "image": settings.nikto_docker_image},
    "wapiti": {"runtime": "wsl", "binary": "wapiti"},
    "sqlmap": {"runtime": "wsl", "binary": "sqlmap"},
    "gobuster": {"runtime": "wsl", "binary": "gobuster"},
}


def _scanner_runtime_specs() -> Dict[str, Dict[str, Any]]:
    resolved = {}
    for name, spec in SCANNER_BINARIES.items():
        runtime = _preferred_runtime(name)
        resolved[name] = {**spec, "runtime": runtime}
        if name == "nikto" and runtime == "wsl":
            resolved[name]["binary"] = "nikto"
    return resolved


SCANNER_CONCURRENCY_LIMIT = 5
SCANNER_TIMEOUTS = {
    "nmap": 180,
    "nikto": 240,
    "wapiti": 300,
    "sqlmap": 120,
    "gobuster": 180,
}
SCANNER_WSL_DISTRIBUTION = settings.scanner_wsl_distribution
class AssessmentTargetError(ValueError):
    """Raised when an assessment target is invalid or blocked by SSRF rules."""


async def _run_wappalyzer(target: str) -> Dict[str, Any]:
    """Run the existing passive technology detector as supplemental metadata."""
    try:
        from app.scanners.wappalyzer_scanner import WappalyzerScanner

        result = await asyncio.wait_for(
            asyncio.to_thread(WappalyzerScanner(target, timeout=10).scan),
            timeout=12,
        )
        result["classification"] = "informational"
        return result
    except asyncio.TimeoutError:
        return {
            "tool": "Technology Fingerprinting",
            "type": "technology_detection",
            "target": target,
            "status": "timed_out",
            "technologies": [],
            "error": "Technology fingerprinting exceeded its 12-second timeout.",
            "classification": "informational",
        }
    except Exception as exc:
        return {
            "tool": "Technology Fingerprinting",
            "type": "technology_detection",
            "target": target,
            "status": "failed",
            "technologies": [],
            "error": str(exc),
            "classification": "informational",
        }


def validate_assessment_target(target: str, lab_mode: bool = False) -> str:
    candidate = (target or "").strip()
    if not candidate or any(char in candidate for char in ("\r", "\n", "\x00")):
        raise AssessmentTargetError("A valid authorized HTTP(S) target is required")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise AssessmentTargetError("Target must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise AssessmentTargetError("Target must not contain credentials or a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AssessmentTargetError("Target contains an invalid port") from exc

    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))

    try:
        validate_url_for_ssrf(normalized, lab_mode=lab_mode)
    except SSRFProtectionError as exc:
        raise AssessmentTargetError(str(exc)) from exc
    return normalized


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _wsl_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    result = await scanner_runtime.capture_runtime(["wslpath", "-a", str(path.resolve())])
    if result.status != "completed":
        detail = _decode_command_output(result.stderr) or _decode_command_output(result.stdout)
        raise RuntimeError(detail or result.error or f"wslpath exited with {result.exit_code}")
    return _decode_command_output(result.stdout)


async def _capture_command(command: Sequence[str]) -> Tuple[int, bytes, bytes]:
    """Capture short helper-command output without depending on a Windows loop policy."""
    result = await scanner_runtime.capture_host(command)
    return result.exit_code if result.exit_code is not None else -1, result.stdout, result.stderr


def _decode_command_output(output: bytes) -> str:
    return decode_output(output)


async def _wsl_host_gateway() -> str:
    if os.name != "nt":
        return ""
    result = await scanner_runtime.capture_runtime(["ip", "route", "show", "default"])
    if result.status != "completed":
        detail = _decode_command_output(result.stderr) or _decode_command_output(result.stdout)
        raise RuntimeError(
            f"WSL gateway command exited with code {result.exit_code}: "
            f"{detail or result.error or 'no stdout or stderr was returned'}"
        )
    match = re.search(rb"\bdefault\s+via\s+(\S+)", result.stdout)
    if not match:
        output = _decode_command_output(result.stdout) or _decode_command_output(result.stderr)
        raise RuntimeError(
            "The WSL default route did not include a host gateway"
            + (f": {output}" if output else "; command returned no output")
        )
    return match.group(1).decode("ascii")


def _replace_local_host(url: str, host: str) -> str:
    parsed = urlsplit(url)
    port = parsed.port
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))


async def _target_for_wsl(target: str, gateway: Optional[str] = None) -> str:
    parsed = urlsplit(target)
    try:
        is_loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        is_loopback = (parsed.hostname or "").lower() == "localhost"
    if os.name == "nt" and is_loopback:
        return _replace_local_host(target, gateway or await _wsl_host_gateway())
    return target


async def _target_for_scanner_runtime(target: str, gateway: Optional[str] = None) -> str:
    if _is_wsl_host():
        return await _target_for_wsl(target, gateway)
    if _is_docker_container():
        return _target_for_docker(target)
    return target


def _target_for_docker(target: str) -> str:
    """Use Docker's host gateway alias only when the submitted target is local."""
    parsed = urlsplit(target)
    try:
        is_loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        is_loopback = (parsed.hostname or "").lower() == "localhost"
    return _replace_local_host(target, "host.docker.internal") if is_loopback else target


def _target_requires_wsl_gateway(target: str) -> bool:
    hostname = urlsplit(target).hostname or ""
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return hostname.lower() == "localhost"


def _runtime_host_header(target: str) -> Optional[str]:
    if not (_is_wsl_host() or _is_docker_container()) or not _target_requires_wsl_gateway(target):
        return None
    return urlsplit(target).netloc


async def _wildcard_response_size(target: str, host_header: Optional[str] = None) -> Optional[int]:
    probe_url = f"{target.rstrip('/')}/.vulnai-missing-{secrets.token_hex(8)}"
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            headers = {"Host": host_header} if host_header else None
            response = await client.get(probe_url, headers=headers)
        if response.status_code != 404:
            return len(response.content)
    except httpx.HTTPError:
        return None
    return None


async def _timed_process_command(
    command: Sequence[str],
    timeout_seconds: float,
    grace_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    started_at = _utc_now()
    result = await scanner_runtime.run_command(command, timeout_seconds + (grace_seconds or 0))
    return {
        "status": result.status,
        "exit_code": result.exit_code,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
    }


def aggregate_scanner_status(scanner_states: Dict[str, str]) -> str:
    """Return an overall terminal state that reflects every required scanner."""
    if not scanner_states or any(state in {"queued", "running"} for state in scanner_states.values()):
        return "running"
    terminal_states = {"completed", "failed", "timed_out", "unavailable", "skipped"}
    if any(state not in terminal_states for state in scanner_states.values()):
        return "running"
    if all(state == "completed" for state in scanner_states.values()):
        return "completed"
    if any(state in {"failed", "timed_out"} for state in scanner_states.values()):
        return "failed"
    return "incomplete"


async def _build_scanner_command(
    scanner: str,
    target: str,
    output_dir: Path,
    timeout_seconds: int,
    wordlist_path: Path,
    wildcard_size: Optional[int],
    gateway: Optional[str],
) -> Tuple[List[str], Path]:
    output_path = output_dir / f"{scanner}.txt"
    if scanner == "nikto" and _preferred_runtime(scanner) == "wsl":
        wsl_target = await _target_for_scanner_runtime(target, gateway)
        wsl_output_path = await _wsl_path(output_path)
        scanner_args = [
            "nikto", "-h", wsl_target, "-nointeractive", "-Tuning", "12349",
            "-timeout", "5", "-maxtime", f"{timeout_seconds}s", "-output", wsl_output_path, "-Format", "txt",
        ]
        host_header = _runtime_host_header(target) if _is_wsl_host() else None
        if host_header:
            scanner_args.extend(["-vhost", host_header])
        command = scanner_runtime.wrap_runtime_command([
            "timeout", "--signal=TERM", "--kill-after=5s", f"{timeout_seconds}s", *scanner_args,
        ])
        return command, output_path
    if scanner == "nikto":
        docker_target = _target_for_docker(target)
        command = [
            settings.scanner_docker_command, "run", "--rm",
            "--add-host", "host.docker.internal:host-gateway",
            settings.nikto_docker_image,
            "-h", docker_target, "-nointeractive", "-Tuning", "12349",
            "-timeout", "5", "-maxtime", f"{timeout_seconds}s", "-Format", "txt",
        ]
        return command, output_path

    wsl_target = await _target_for_scanner_runtime(target, gateway)
    wsl_output_path = await _wsl_path(output_path)
    parsed_target = urlsplit(wsl_target)
    hostname = parsed_target.hostname or ""
    port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

    if scanner == "nmap":
        scanner_args = ["nmap", "-Pn", "-sV", "--version-light", "--open", "-p", str(port), hostname]
    elif scanner == "wapiti":
        scanner_args = [
            "wapiti", "-u", wsl_target, "--scope", "page", "-d", "1", "--tasks", "1",
            "--max-scan-time", str(timeout_seconds), "--max-attack-time", "15",
            "--store-session", await _wsl_path(output_dir / "wapiti-session"),
            "--no-bugreport", "-f", "txt", "-o", wsl_output_path,
        ]
        host_header = _runtime_host_header(target)
        if host_header:
            scanner_args.extend(["-H", f"Host: {host_header}"])
    elif scanner == "sqlmap":
        scanner_args = [
            "sqlmap", "-u", wsl_target, "--batch", "--risk=1", "--level=1",
            "--technique=BEU", "--threads=1", "--timeout=5", "--retries=0",
            f"--output-dir={await _wsl_path(output_dir / 'sqlmap-data')}",
        ]
        host_header = _runtime_host_header(target)
        if host_header:
            scanner_args.extend(["--host", host_header])
    elif scanner == "gobuster":
        wsl_wordlist = await _wsl_path(wordlist_path)
        scanner_args = [
            "gobuster", "dir", "-u", wsl_target, "-w", wsl_wordlist,
            "-o", wsl_output_path, "--threads", "4", "--no-progress", "--no-color",
        ]
        host_header = _runtime_host_header(target)
        if host_header:
            scanner_args.extend(["-H", f"Host: {host_header}"])
        if wildcard_size is not None:
            scanner_args.extend(["--exclude-length", str(wildcard_size)])
    else:
        raise ValueError(f"Unsupported scanner: {scanner}")

    command = scanner_runtime.wrap_runtime_command([
        "timeout", "--signal=TERM", "--kill-after=5s", f"{timeout_seconds}s", *scanner_args,
    ])
    return command, output_path

async def _write_status_file(output_dir: Path, status_data: Dict[str, Any]) -> None:
    status_path = output_dir / "scan-status.json"
    temporary_path = status_path.with_suffix(".json.tmp")
    serialized = json.dumps(status_data, indent=2)
    temporary_path.write_text(serialized, encoding="utf-8")
    try:
        os.replace(temporary_path, status_path)
    except PermissionError:
        status_path.write_text(serialized, encoding="utf-8")
        temporary_path.unlink(missing_ok=True)


def _classify_finding(finding: Dict[str, Any]) -> str:
    explicit = str(finding.get("classification", "")).lower()
    confidence = str(finding.get("confidence", "")).lower()
    if explicit == "confirmed" or confidence == "confirmed":
        return "confirmed"
    if explicit == "informational" or confidence == "informational" or str(finding.get("severity", "")).lower() == "info":
        return "informational"
    return "potential"


def _scanner_output_error(scanner: str, stdout: bytes, output_path: Path) -> Optional[str]:
    report = output_path.read_bytes() if output_path.is_file() else b""
    output = (stdout + b"\n" + report).decode("utf-8", errors="replace").casefold()
    if not output.strip():
        return "Scanner exited successfully but produced no usable output"
    if scanner == "nikto" and "unable to connect to" in output:
        return "Nikto reported that it could not connect to the target"
    return None


def _normalise_parser_finding(
    scanner: str,
    finding: Dict[str, Any],
    index: int,
    output_name: str,
) -> Dict[str, Any]:
    normalized = dict(finding)
    parser_confidence = finding.get("confidence")
    classification = _classify_finding(finding)
    numeric_confidence = (
        float(parser_confidence)
        if isinstance(parser_confidence, (int, float))
        else {"confirmed": 1.0, "potential": 0.5, "informational": 0.2}[classification]
    )
    normalized.update({
        "id": f"{scanner}-{index}",
        "scanner": scanner,
        "source": scanner,
        "classification": classification,
        "confidence": numeric_confidence,
        "verification_status": "unverified",
        "evidence": {
            **(finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}),
            "parser_confidence": parser_confidence,
            "raw_output_file": output_name,
        },
    })
    return normalized

def _write_markdown_report(
    output_dir: Path,
    scan_id: str,
    target: str,
    scanner_status: Dict[str, str],
    scanner_details: Dict[str, Dict[str, Any]],
    categorized_results: Dict[str, List[Dict[str, Any]]],
    overall_status: str,
    technology_detection: Optional[Dict[str, Any]] = None,
) -> Path:
    report_path = output_dir / "security_assessment_report.md"
    lines = [
        "# Unified Security Assessment",
        "",
        f"- Scan ID: `{scan_id}`",
        f"- Target: `{target}`",
        f"- Status: `{overall_status}`",
        "",
        "## Scanner Status",
        "",
        "| Scanner | Status | Exit code | Evidence |",
        "|---|---|---:|---|",
    ]
    for scanner in SCANNERS:
        detail = scanner_details[scanner]
        lines.append(
            f"| {scanner} | {scanner_status[scanner]} | {detail.get('exit_code')} | `scan-results/{scan_id}/{scanner}.txt` |"
        )
        # Technology Detection
    if technology_detection:
        lines.extend([
            "",
            "## Technology Detection",
            "",
            f"- Status: `{technology_detection.get('status', 'unknown')}`",
            f"- Technologies detected: `{technology_detection.get('technology_count', 0)}`",
            "",
            "| Technology | Category | Confidence |",
            "|---|---|---:|",
        ])

        technologies = technology_detection.get("technologies", [])

        if technologies:
            for technology in technologies:
                lines.append(
                    f"| {technology.get('name', 'Unknown')} | "
                    f"{technology.get('category', 'Unknown')} | "
                    f"{technology.get('confidence', 0)}% |"
                )
        else:
            lines.append("| None detected | — | — |")

    for classification in ("confirmed", "potential", "informational", "incomplete"):
        findings = categorized_results[classification]
        lines.extend(["", f"## {classification.title()} ({len(findings)})", ""])
        if not findings:
            lines.append("None.")
            continue
        for finding in findings:
            scanner = finding.get("scanner", "unknown")
            title = finding.get("title") or finding.get("path") or finding.get("message") or "Scanner observation"
            lines.append(f"- **{scanner}: {title}**")
            if finding.get("target_url"):
                lines.append(f"  - Target: `{finding['target_url']}`")
            if finding.get("status_code") is not None:
                lines.append(f"  - HTTP {finding['status_code']}; {finding.get('response_size', 'unknown')} bytes")
            lines.append(f"  - Verification: `{finding.get('verification_status', 'unverified')}`")
            raw_output = finding.get("raw_line") or finding.get("description") or finding.get("message")
            if raw_output:
                lines.append(f"  - Evidence: `{finding.get('evidence', {}).get('raw_output_file', finding.get('raw_output_file', 'scanner output'))}`")
                lines.append(f"  - Observation: {str(raw_output).replace(chr(10), ' ')[:500]}")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


async def _run_unified_assessment(scan_id: str, db) -> None:
    """Run the five scanners concurrently and persist independent outcomes."""
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan or scan.get("status") == "cancelled":
        return

    target = scan.get("target_url")
    output_dir = SCAN_RESULTS_ROOT / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    status_data: Dict[str, Any] = {
        "scan_id": scan_id,
        "target": target,
        "status": "running",
        "started_at": _utc_now(),
        "completed_at": None,
        "scanners": {name: "queued" for name in SCANNERS},
        "scanner_details": {
            name: {
                "scanner": name, "status": "queued", "target": target,
                "stdout": "", "stderr": "", "exit_code": None,
                "duration": 0.0, "error": None, "classification": "unverified",
                "started_at": None, "completed_at": None,
            }
            for name in SCANNERS
        },
    }
    state_lock = asyncio.Lock()

    async def update_scanner(name: str, detail: Dict[str, Any]) -> None:
        async with state_lock:
            status_data["scanners"][name] = detail["status"]
            status_data["scanner_details"][name] = detail
            finished = sum(value in {"completed", "failed", "timed_out", "unavailable", "skipped"} for value in status_data["scanners"].values())
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {
                    "status": "running",
                    "progress": int(finished * 100 / len(SCANNERS)),
                    "scanner_status": dict(status_data["scanners"]),
                    "scanner_details": dict(status_data["scanner_details"]),
                    "runtime_status": status_data.get("runtime_status"),
                }},
            )
            await _write_status_file(output_dir, status_data)

    try:
        normalized_target = validate_assessment_target(target, bool(scan.get("lab_mode", False)))
        status_data["target"] = normalized_target
        await _write_status_file(output_dir, status_data)
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"target_url": normalized_target, "status": "running", "progress": 0}},
        )
    except Exception as exc:
        status_data["status"] = "failed"
        status_data["completed_at"] = _utc_now()
        status_data["error"] = str(exc)
        await _write_status_file(output_dir, status_data)
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"status": "failed", "error_message": str(exc), "ended_at": datetime.now(timezone.utc)}},
        )
        return

    try:
        runtime_status = await scanner_runtime.preflight_matrix(_scanner_runtime_specs())
    except Exception as exc:
        runtime_status = {
            "status": "unavailable", "runtime": "wsl" if os.name == "nt" else "local",
            "distribution": SCANNER_WSL_DISTRIBUTION if os.name == "nt" else None,
            "wsl_available": False if os.name == "nt" else True,
            "distribution_installed": False if os.name == "nt" else True,
            "distribution_state_before_command": "unknown", "command_executable": False,
            "stdout": "", "stderr": "", "error": str(exc) or repr(exc),
            "scanners": {}, "probes": {},
        }
        for name in SCANNERS:
            runtime_status["scanners"][name] = {
                "scanner": name, "available": False, "status": "unavailable",
                "binary": name, "path": None, "stdout": "", "stderr": "",
                "exit_code": None, "error": runtime_status["error"], "reason": "preflight_failed",
            }
    status_data["runtime_status"] = runtime_status
    await _write_status_file(output_dir, status_data)
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)}, {"$set": {"runtime_status": runtime_status}}
    )

    gateway = None
    gateway_error = None
    if os.name == "nt" and runtime_status.get("command_executable") and _target_requires_wsl_gateway(normalized_target):
        try:
            gateway = await _wsl_host_gateway()
        except Exception as exc:
            gateway_error = str(exc) or repr(exc) or type(exc).__name__
            runtime_status["local_target_connectivity"] = {"available": False, "error": gateway_error}
    if gateway is not None:
        runtime_status["local_target_connectivity"] = {"available": True, "gateway": gateway}
    if gateway_error:
        wildcard_size = None
    else:
        probe_target = await _target_for_scanner_runtime(normalized_target, gateway)
        wildcard_size = await _wildcard_response_size(
            probe_target, _runtime_host_header(normalized_target)
        )
    await _write_status_file(output_dir, status_data)
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)}, {"$set": {"runtime_status": runtime_status}}
    )
    wordlist_path = WORDLIST_PATH
    scanner_semaphore = asyncio.Semaphore(SCANNER_CONCURRENCY_LIMIT)

    async def run_one(scanner: str) -> None:
        timeout_seconds = SCANNER_TIMEOUTS[scanner]
        execution_started = time.perf_counter()
        detail: Dict[str, Any] = {
            "scanner": scanner,
            "runtime": _preferred_runtime(scanner),
            "status": "running",
            "target": normalized_target,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "duration": 0.0,
            "classification": "unverified",
            "started_at": _utc_now(),
            "completed_at": None,
            "timeout_seconds": timeout_seconds,
            "output_file": f"scan-results/{scan_id}/{scanner}.txt",
            "stdout_file": f"scan-results/{scan_id}/{scanner}.stdout.txt",
            "stderr_file": f"scan-results/{scan_id}/{scanner}.stderr.txt",
            "error": None,
            "failure_stage": "command_construction",
        }
        await update_scanner(scanner, detail)
        stdout_path = output_dir / f"{scanner}.stdout.txt"
        stderr_path = output_dir / f"{scanner}.stderr.txt"
        output_path = output_dir / f"{scanner}.txt"
        availability = runtime_status.get("scanners", {}).get(scanner, {})
        unavailable_error = None if availability.get("available") else (
            availability.get("error") or runtime_status.get("error") or "Scanner runtime is unavailable"
        )
        if gateway_error:
            unavailable_error = gateway_error
        if unavailable_error:
            raw_stdout = str(availability.get("stdout") or "").encode("utf-8")
            raw_stderr = str(availability.get("stderr") or "").encode("utf-8")
            detail.update({
                "status": "unavailable",
                "completed_at": _utc_now(),
                "failure_stage": "runtime_preflight",
                "error": unavailable_error,
                "stdout": _decode_command_output(raw_stdout),
                "stderr": _decode_command_output(raw_stderr),
            })
            output_path.write_bytes(b"")
            stdout_path.write_bytes(raw_stdout)
            stderr_path.write_bytes(raw_stderr)
            detail["duration"] = round(time.perf_counter() - execution_started, 3)
            detail["execution_seconds"] = detail["duration"]
            await update_scanner(scanner, detail)
            return
        try:
            detail["execution_target"] = (
                _target_for_docker(normalized_target)
                if _preferred_runtime(scanner) == "docker"
                else await _target_for_scanner_runtime(normalized_target, gateway)
            )
            command, output_path = await _build_scanner_command(
                scanner, normalized_target, output_dir, timeout_seconds,
                wordlist_path, wildcard_size, gateway,
            )
            detail["command"] = list(command)
            detail["executable"] = command[0] if command else None
            detail["failure_stage"] = "process_execution"
            process_result = await _timed_process_command(command, timeout_seconds)
            stdout = process_result.pop("stdout")
            stderr = process_result.pop("stderr")
            stdout_path.write_bytes(stdout)
            stderr_path.write_bytes(stderr)
            if not output_path.exists():
                output_path.write_bytes(stdout)
            detail.update(process_result)
            output_error = _scanner_output_error(scanner, stdout, output_path)
            if detail.get("status") == "completed" and output_error:
                detail.update(
                    status="failed",
                    error=output_error,
                    failure_stage="result_validation",
                )
            detail["stdout"] = _decode_command_output(stdout)
            detail["stderr"] = _decode_command_output(stderr)
            if detail.get("status") == "completed":
                detail["failure_stage"] = None
            elif detail.get("failure_stage") != "result_validation":
                detail["failure_stage"] = "process_execution"
            detail["output_file"] = f"scan-results/{scan_id}/{output_path.name}"
            detail["stdout_file"] = f"scan-results/{scan_id}/{stdout_path.name}"
            detail["stderr_file"] = f"scan-results/{scan_id}/{stderr_path.name}"
        except Exception as exc:
            error_message = str(exc) or repr(exc) or type(exc).__name__
            detail.update({"status": "failed", "completed_at": _utc_now(), "error": error_message})
            detail["failure_stage"] = "command_construction" if "command" not in detail else "process_execution"
            if not output_path.exists():
                output_path.write_text("", encoding="utf-8")
            if not stderr_path.exists():
                stderr_path.write_bytes(b"")
        detail["duration"] = round(time.perf_counter() - execution_started, 3)
        detail["execution_seconds"] = detail["duration"]
        await update_scanner(scanner, detail)

    async def run_bounded(scanner: str) -> None:
        async with scanner_semaphore:
            started = time.perf_counter()
            try:
                await run_one(scanner)
            except Exception as exc:
                detail = status_data["scanner_details"][scanner]
                message = str(exc) or repr(exc) or type(exc).__name__
                detail.update({
                    "status": "failed", "completed_at": _utc_now(),
                    "error": message, "failure_stage": "orchestration",
                })
                detail["stderr"] = message
                detail["duration"] = round(time.perf_counter() - started, 3)
                detail["execution_seconds"] = detail["duration"]
                evidence_dir = SCAN_RESULTS_ROOT / scan_id
                evidence_dir.mkdir(parents=True, exist_ok=True)
                (evidence_dir / f"{scanner}.txt").touch(exist_ok=True)
                (evidence_dir / f"{scanner}.stdout.txt").touch(exist_ok=True)
                (evidence_dir / f"{scanner}.stderr.txt").write_text(message, encoding="utf-8")
                try:
                    await update_scanner(scanner, detail)
                except Exception:
                    status_data["scanners"][scanner] = "failed"

    await asyncio.gather(*(run_bounded(name) for name in SCANNERS), return_exceptions=True)
    wappalyzer_result = await _run_wappalyzer(normalized_target)

    normalized_findings: Dict[str, List[Dict[str, Any]]] = {
        "confirmed": [],
        "potential": [],
        "informational": [],
        "incomplete": [],
    }
    parser_by_scanner = {
        "nmap": parse_nmap,
        "nikto": parse_nikto,
        "wapiti": parse_wapiti,
        "sqlmap": parse_sqlmap,
    }
    owner_id = str(scan.get("owner_id", ""))
    asset_id = str(scan.get("asset_id", ""))
    scanner_status = status_data["scanners"]
    scanner_details = status_data["scanner_details"]
    for scanner in SCANNERS:
        if status_data["scanners"].get(scanner) != "completed":
            continue
        raw_output = (output_dir / f"{scanner}.txt").read_text(encoding="utf-8", errors="replace")
        try:
            if scanner == "gobuster":
                parsed_findings = parse_gobuster_observations(raw_output)
                for index, finding in enumerate(parsed_findings, start=1):
                    finding["evidence"] = {"raw_line": finding.get("raw_line", ""), "raw_output_file": f"scan-results/{scan_id}/gobuster.txt"}
                    finding["scan_id"] = scan_id
                    finding["asset_id"] = asset_id
                    finding["owner_id"] = owner_id
                    finding["target_url"] = normalized_target
                    finding["id"] = f"gobuster-{index}"
                    finding["confidence"] = 0.2
                    finding["category"] = "Asset Discovery"
                    finding["owasp_id"] = "N/A"
                    finding["cwe_id"] = "N/A"
                    finding["description"] = (
                        f"Gobuster observed {finding['path']} (HTTP {finding['status_code']}, "
                        f"{finding.get('response_size', 'unknown')} bytes). This is informational and unverified."
                    )
                    finding["ai_analysis"] = {}
                    finding["created_at"] = datetime.now(timezone.utc)
                    normalized_findings["informational"].append(finding)
                continue

            parser = parser_by_scanner[scanner]
            parsed_findings = parser(raw_output, scan_id, normalized_target, owner_id, asset_id)
            for index, finding in enumerate(parsed_findings, start=1):
                normalized = _normalise_parser_finding(
                    scanner, finding, index, f"scan-results/{scan_id}/{scanner}.txt"
                )
                normalized_findings[normalized["classification"]].append(normalized)
        except Exception as exc:
            detail = scanner_details[scanner]
            detail.update({
                "status": "failed",
                "completed_at": _utc_now(),
                "error": f"Result parsing failed: {str(exc) or repr(exc)}",
                "failure_stage": "result_parsing",
            })
            scanner_status[scanner] = "failed"

    for scanner, scanner_state in scanner_status.items():
        if scanner_state != "completed":
            detail = scanner_details[scanner]
            normalized_findings["incomplete"].append({
                "id": f"{scanner}-incomplete",
                "scanner": scanner,
                "source": f"scan-results/{scan_id}/{scanner}.txt",
                "classification": "incomplete",
                "verification_status": "unverified",
                "status": scanner_state,
                "exit_code": detail.get("exit_code"),
                "message": detail.get("error") or f"{scanner} did not complete successfully",
                "raw_output_file": detail.get("output_file"),
                "stderr_file": detail.get("stderr_file"),
            })

    overall_status = aggregate_scanner_status(scanner_status)
    status_data["status"] = overall_status
    status_data["completed_at"] = _utc_now()
    combined_results = {
    "scan_id": scan_id,
    "target": normalized_target,
    "status": overall_status,
    "runtime_status": runtime_status,
    "technology_detection": wappalyzer_result,
    **normalized_findings,
    "scanner_status": dict(scanner_status),
    "scanner_details": dict(scanner_details),
}
    unified_results_path = output_dir / "unified-results.json"
    unified_results_tmp = unified_results_path.with_suffix(".json.tmp")
    unified_results_tmp.write_text(
        json.dumps(combined_results, indent=2, default=str), encoding="utf-8"
    )
    os.replace(unified_results_tmp, unified_results_path)
    await _write_status_file(output_dir, status_data)
    confirmed_findings = normalized_findings["confirmed"]
    risk_score = compute_scan_risk(confirmed_findings)
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in confirmed_findings:
        severity = str(finding.get("severity", "info")).lower()
        severity_summary[severity if severity in severity_summary else "info"] += 1

    all_findings = [
        *normalized_findings["confirmed"],
        *normalized_findings["potential"],
        *normalized_findings["informational"],
    ]
    markdown_report = _write_markdown_report(
        output_dir,
        scan_id,
        normalized_target,
        scanner_status,
        scanner_details,
        normalized_findings,
        overall_status=overall_status,
        technology_detection=wappalyzer_result,
    )
    evidence_files = {
        scanner: f"scan-results/{scan_id}/{scanner}.txt"
        for scanner in SCANNERS
    }
    evidence_files["unified_results"] = f"scan-results/{scan_id}/unified-results.json"
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": overall_status,
            "progress": 100,
            "ended_at": datetime.now(timezone.utc),
            "scanner_status": dict(scanner_status),
            "scanner_details": dict(scanner_details),
            "evidence_files": evidence_files,
            "combined_results": combined_results,
            "results": all_findings,
            "total_findings": len(confirmed_findings),
            "severity_summary": severity_summary,
            "risk_score": risk_score if overall_status == "completed" else None,
            "security_score": risk_score.get("score", 100) if overall_status == "completed" else None,
            "report_md_path": str(markdown_report),
        }},
    )


async def run_unified_assessment(scan_id: str, db) -> None:
    """Ensure unexpected orchestration errors leave a terminal status."""
    try:
        await _run_unified_assessment(scan_id, db)
    except Exception as exc:
        output_dir = SCAN_RESULTS_ROOT / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        status_path = output_dir / "scan-status.json"
        try:
            status_data = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            status_data = {
                "scan_id": scan_id,
                "target": None,
                "scanners": {name: "failed" for name in SCANNERS},
                "scanner_details": {},
            }
        status_data["status"] = "failed"
        status_data["completed_at"] = _utc_now()
        status_data["error"] = str(exc)
        await _write_status_file(output_dir, status_data)
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {
                "status": "failed",
                "ended_at": datetime.now(timezone.utc),
                "error_message": f"Unified assessment finalization failed: {exc}",
            }},
        )
