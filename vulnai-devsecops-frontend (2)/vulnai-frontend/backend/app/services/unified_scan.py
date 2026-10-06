"""Run the authorized scanners independently and preserve their evidence."""

import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)

import copy
import httpx
from app.core.ids import ObjectId

from app.parsers import (
    parse_nmap, extract_nmap_host_discovery,
    parse_nikto,
    parse_sqlmap, extract_sqlmap_assessment,
    parse_wapiti,
)
from app.parsers.gobuster_parser import parse_gobuster_observations
from app.services.finding_correlation import correlate_and_deduplicate_findings
from app.services.assessment_coverage import get_assessment_coverage, get_owasp_coverage_matrix
from app.core.paths import SCAN_RESULTS_ROOT, WORDLIST_PATH
from app.services.risk_scoring import compute_scan_risk
from app.services.scanner import SSRFProtectionError, validate_url_for_ssrf
from app.services.scanner_runtime import decode_output, scanner_runtime
from app.services.scan_job_manager import scan_job_manager
from app.core.config import settings
CORE_SCANNERS = ("nmap", "nikto", "wapiti", "sqlmap", "gobuster")
ALL_SCANNERS = ("nmap", "nikto", "wapiti", "sqlmap", "gobuster", "wappalyzer")
SCANNERS = CORE_SCANNERS


def _is_docker_container() -> bool:
    return Path("/.dockerenv").is_file()


def _is_wsl_host() -> bool:
    return os.name == "nt" and not _is_docker_container()


def _preferred_runtime(scanner: str) -> str:
    if scanner == "nikto" and (_is_wsl_host() or _is_docker_container()):
        return "wsl"
    if scanner in SCANNER_BINARIES:
        return SCANNER_BINARIES[scanner]["runtime"]
    return "python"


SCANNER_BINARIES = {
    "nmap": {"runtime": "wsl", "binary": "nmap"},
    "nikto": {"runtime": "docker", "image": settings.nikto_docker_image},
    "wapiti": {"runtime": "wsl", "binary": "wapiti"},
    "sqlmap": {"runtime": "wsl", "binary": "sqlmap"},
    "gobuster": {"runtime": "wsl", "binary": "gobuster"},
    "wappalyzer": {"runtime": "python", "binary": "wappalyzer"},
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
SCANNER_WSL_DISTRIBUTION = settings.scanner_wsl_distribution


async def _persist_scanner_job(db, scan_id: str, tool_name: str, detail: Dict[str, Any]) -> None:
    if not hasattr(db, "scanner_jobs"):
        return
    job_id = f"{scan_id}_{tool_name}"
    doc = {
        "job_id": job_id,
        "scan_id": scan_id,
        "tool_name": tool_name,
        "status": detail.get("status", "queued"),
        "started_at": detail.get("started_at"),
        "completed_at": detail.get("completed_at"),
        "exit_code": detail.get("exit_code"),
        "stdout": (detail.get("stdout") or "")[:50000],
        "stderr": (detail.get("stderr") or "")[:50000],
        "duration": detail.get("duration", 0.0),
        "error_message": detail.get("error"),
        "updated_at": _utc_now(),
    }
    try:
        await db.scanner_jobs.update_one(
            {"scan_id": scan_id, "tool_name": tool_name},
            {"$set": doc},
            upsert=True,
        )
    except Exception as exc:
        logging.getLogger(__name__).warning("Failed to persist scanner_job for %s: %s", tool_name, exc)


async def _run_wappalyzer(target: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
    """Run the passive technology fingerprinting engine without an artificial timeout limit."""
    try:
        from app.scanners.wappalyzer_scanner import WappalyzerScanner

        if scan_id and scan_job_manager.is_cancelled(scan_id):
            return {
                "tool": "Technology Fingerprinting",
                "type": "technology_detection",
                "target": target,
                "status": "cancelled",
                "technologies": [],
                "technology_count": 0,
                "error": "Scan was cancelled by user",
                "classification": "informational",
            }

        scanner = WappalyzerScanner(target, timeout=settings.scan_job_timeout_seconds)
        result = await asyncio.to_thread(scanner.scan)

        if scan_id and scan_job_manager.is_cancelled(scan_id):
            result["status"] = "cancelled"
            result["error"] = "Scan was cancelled by user"
            return result

        result["classification"] = "informational"
        w_status = "completed" if result.get("status") not in ("failed", "error") else "failed"
        result["status"] = w_status
        return result
    except Exception as exc:
        return {
            "tool": "Technology Fingerprinting",
            "type": "technology_detection",
            "target": target,
            "status": "failed",
            "technologies": [],
            "technology_count": 0,
            "error": str(exc),
            "classification": "informational",
        }


class AssessmentTargetError(ValueError):
    """Raised when an assessment target is invalid or blocked by SSRF rules."""


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
    timeout_seconds: float = 0,
    grace_seconds: Optional[float] = None,
    on_stdout: Optional[Callable[[str], None]] = None,
    on_stderr: Optional[Callable[[str], None]] = None,
    cancel_event: Optional[asyncio.Event] = None,
    on_process_created: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    started_at = _utc_now()
    eff_timeout = (timeout_seconds + (grace_seconds or 0)) if (timeout_seconds and timeout_seconds > 0) else settings.scan_job_timeout_seconds
    result = await scanner_runtime.run_streaming_command(
        command,
        on_stdout=on_stdout,
        on_stderr=on_stderr,
        cancel_event=cancel_event,
        timeout=eff_timeout,
        on_process_created=on_process_created,
    )
    return {
        "status": result.status,
        "exit_code": result.exit_code,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
    }


def aggregate_scanner_status(scanner_states: Dict[str, str], is_cancelled: bool = False) -> str:
    """Return an overall terminal state that reflects every required scanner."""
    if is_cancelled or any(state == "cancelled" for state in scanner_states.values()):
        return "cancelled"
    if not scanner_states or any(state in {"queued", "running"} for state in scanner_states.values()):
        return "running"
    terminal_states = {"completed", "failed", "timed_out", "unavailable", "skipped", "cancelled"}
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
            "nikto", "-h", wsl_target, "-nointeractive", "-output", wsl_output_path, "-Format", "txt",
        ]
        host_header = _runtime_host_header(target) if _is_wsl_host() else None
        if host_header:
            scanner_args.extend(["-vhost", host_header])
        command = scanner_runtime.wrap_runtime_command(scanner_args)
        return command, output_path
    if scanner == "nikto":
        docker_target = _target_for_docker(target)
        command = [
            settings.scanner_docker_command, "run", "--rm",
            "--add-host", "host.docker.internal:host-gateway",
            settings.nikto_docker_image,
            "-h", docker_target, "-nointeractive", "-Format", "txt",
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
            "--store-session", await _wsl_path(output_dir / "wapiti-session"),
            "--no-bugreport", "-f", "txt", "-o", wsl_output_path,
        ]
        host_header = _runtime_host_header(target)
        if host_header:
            scanner_args.extend(["-H", f"Host: {host_header}"])
    elif scanner == "sqlmap":
        scanner_args = [
            "sqlmap", "-u", wsl_target, "--batch", "--risk=1", "--level=1",
            "--technique=BEU", "--threads=1",
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

    command = scanner_runtime.wrap_runtime_command(scanner_args)
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
    combined_results: Optional[Dict[str, Any]] = None,
) -> Path:
    report_path = output_dir / "security_assessment_report.md"
    comb = combined_results or {}
    risk_score = comb.get("risk_score", {})
    score_val = risk_score.get("score")
    score_disp = f"{score_val}/100" if score_val is not None else "Not Fully Determined"
    rating_disp = risk_score.get("rating", "Undetermined")

    c_findings = categorized_results.get("confirmed", [])
    p_findings = categorized_results.get("potential", [])
    i_findings = categorized_results.get("informational", [])
    inc_findings = categorized_results.get("incomplete", [])

    lines = [
        "# VulnAI DevSecOps - Security Assessment Report",
        "",
        "> **Notice:** Automated security assessment report. Scanner output represents indicators that must be manually validated before being treated as confirmed vulnerabilities. Scanner completion does not denote that the target is completely secure.",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Target Host / URL:** `{target}`",
        f"- **Scan ID:** `{scan_id}`",
        f"- **Assessment Status:** `{overall_status.upper()}`",
        f"- **VulnAI Project Risk Score:** `{score_disp}` (Risk Rating: **{rating_disp}**)",
        f"- **Model:** {risk_score.get('model', 'VulnAI Project Risk Score (Project-Defined)')}",
        "",
        "### Finding Verification Classification",
        "",
        "| Category | Count | Definition |",
        "|---|---:|---|",
        f"| **Confirmed Vulnerabilities** | **{len(c_findings)}** | Evidence is sufficiently validated |",
        f"| **Potential Security Findings** | **{len(p_findings)}** | Security indicator detected; requires independent confirmation |",
        f"| **Informational Observations** | **{len(i_findings)}** | Reconnaissance / technology / configuration data |",
        f"| **Incomplete / Timed Out** | **{len(inc_findings)}** | Tool did not complete sufficiently |",
        "",
    ]

    # SQL Injection Summary
    sql_assessment = comb.get("sql_assessment", {})
    if sql_assessment.get("injection_confirmed"):
        lines.append("- **SQL Injection Assessment:** **CONFIRMED SQL Injection Identified**")
    else:
        lines.append("- **SQL Injection Assessment:** No confirmed SQL injection identified.")
    lines.append("")

    # Score breakdown
    lines.extend([
        "## 2. VulnAI Project Risk Score Calculation",
        "",
        "| Factor / Finding | Verification | Severity | Deduction |",
        "|---|---|---|---:|",
        "| Starting Base Score | Standard | Baseline | 100 pts |",
    ])
    for d in (risk_score.get("deductions") or []):
        lines.append(f"| {d.get('finding')} | {d.get('verification_status')} | {str(d.get('severity')).upper()} | -{d.get('deduction', 0)} pts |")
    lines.append(f"| **Final VulnAI Risk Score** | — | **{rating_disp}** | **{score_disp}** |")
    lines.append("")

    # Scanner Status
    lines.extend([
        "## 3. Scanner Execution Summary",
        "",
        "| Scanner | Status | Runtime | Findings | Verification State |",
        "|---|---|---:|---:|---|",
    ])
    for scanner in ALL_SCANNERS:
        detail = scanner_details.get(scanner, {})
        st = scanner_status.get(scanner, "unknown")
        dur = detail.get("duration") or detail.get("execution_seconds") or 0.0
        findings_count = sum(
            1 for group in ("confirmed", "potential", "informational")
            for f in categorized_results.get(group, [])
            if scanner.lower() in [s.lower() for s in f.get("detected_by", [f.get("scanner", "")])]
        )
        lines.append(f"| {scanner.capitalize()} | {st.upper()} | {dur:.2f}s | {findings_count} | {'Completed' if st == 'completed' else 'Incomplete/Failed'} |")
    lines.append("")
    lines.append("> *Notice: 'COMPLETED' indicates the automated subprocess finished executing. It does NOT denote that the target is secure.*")
    lines.append("")

    # Host Discovery
    host_disc = comb.get("host_discovery", {})
    lines.extend([
        "## 4. Host Information & Port Discovery (Nmap)",
        "",
        f"- **Hostname:** `{host_disc.get('hostname', target)}`",
        f"- **Resolved IP:** `{host_disc.get('resolved_ip', 'Not Resolved')}`",
        f"- **Host State:** `{host_disc.get('host_state', 'UP')}`",
        "",
        "| Port / Protocol | State | Service | Product | Version |",
        "|---|---|---|---|---|",
    ])
    open_ports = host_disc.get("open_ports", [])
    if open_ports:
        for p in open_ports:
            lines.append(f"| {p.get('port')}/{p.get('protocol', 'tcp')} | {p.get('state')} | {p.get('service')} | {p.get('product') or '—'} | {p.get('version') or '—'} |")
    else:
        lines.append("| Target web port assessed | OPEN | HTTP/HTTPS | — | — |")
    lines.append("")

    # Technology Detection
    techs = (technology_detection or {}).get("technologies", [])
    lines.extend([
        "## 5. Technology Stack (Wappalyzer)",
        "",
        "> *Classification: INFORMATIONAL. Technology identification maps attack surface; not automatically a vulnerability.*",
        "",
        "| Technology | Category | Version | Confidence |",
        "|---|---|---|---:|",
    ])
    if techs:
        for t in techs:
            lines.append(f"| {t.get('name')} | {t.get('category')} | {t.get('version') or '—'} | {t.get('confidence', 100)}% |")
    else:
        lines.append("| No distinctive technologies detected | — | — | — |")
    lines.append("")

    # Assessment Coverage
    coverage_list = comb.get("assessment_coverage", [])
    if coverage_list:
        lines.extend([
            "## 6. Assessment Coverage & Boundaries",
            "",
            "| Assessment Area | Tool | Status | Methodology Note |",
            "|---|---|---|---|",
        ])
        for cov in coverage_list:
            lines.append(f"| {cov.get('area')} | {cov.get('tool')} | **{cov.get('status')}** | {cov.get('note')} |")
        lines.append("")

    # OWASP Coverage Matrix
    owasp_matrix = comb.get("owasp_coverage", [])
    if owasp_matrix:
        lines.extend([
            "## 7. OWASP Top 10 (2021) Coverage Matrix",
            "",
            "> *Important Disclaimer: OWASP Top 10 coverage represents automated assessment coverage and does not constitute certification or proof of security.*",
            "",
            "| Category | Assessment Status | Findings | Scope Note |",
            "|---|---|---:|---|",
        ])
        for ow in owasp_matrix:
            lines.append(f"| {ow.get('id')} {ow.get('name')} | **{ow.get('status')}** | {ow.get('findings_count', 0)} | {ow.get('notes')} |")
        lines.append("")

    # Detailed Findings
    detailed_findings = [*c_findings, *p_findings]
    lines.extend([
        "## 8. Correlated Security Findings",
        "",
    ])
    if not detailed_findings:
        lines.append("No confirmed or potential security vulnerabilities were identified within the automated assessment scope.")
        lines.append("")
    else:
        for idx, f in enumerate(detailed_findings, start=1):
            f_id = f.get("id") or f"VULNAI-{idx:03d}"
            det_by = ", ".join(f.get("detected_by", [])) if isinstance(f.get("detected_by"), list) else str(f.get("detected_by") or f.get("scanner", ""))
            lines.extend([
                f"### {f_id}: {f.get('title')}",
                "",
                f"- **Severity:** `{str(f.get('severity', 'info')).upper()}`",
                f"- **Verification Status:** `{str(f.get('verification_status', 'POTENTIAL')).upper()}`",
                f"- **Confidence:** `{f.get('confidence', 'MEDIUM')}`",
                f"- **Detected By:** `{det_by}`",
                f"- **Affected Endpoint:** `{f.get('endpoint') or f.get('target_url') or target}`",
                f"- **OWASP Category:** {f.get('owasp_category') or f.get('owasp_id') or 'Not mapped'}",
                f"- **CWE:** {f.get('cwe') or f.get('cwe_id') or 'Not mapped'}",
                f"- **WSTG:** {f.get('wstg', 'Not mapped')}",
                f"- **Description:** {f.get('description', '')}",
                f"- **Security Impact:** {f.get('impact', '')}",
                f"- **Remediation:** {f.get('recommendation', '')}",
                f"- **Raw Evidence Artifact:** `{f.get('raw_evidence_files', ['scan-results/'])[0] if isinstance(f.get('raw_evidence_files'), list) and f.get('raw_evidence_files') else f.get('evidence', {}).get('raw_output_file', 'scan-results/')}`",
                "",
            ])

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


async def _run_unified_assessment(scan_id: str, db) -> None:
    """Run the 6 scanners concurrently and persist independent outcomes."""
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan or scan.get("status") == "cancelled":
        return

    target = scan.get("target_url")
    output_dir = SCAN_RESULTS_ROOT / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_job_manager.register_scan(scan_id, target, list(ALL_SCANNERS))
    overall_started = time.perf_counter()
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
            for name in ALL_SCANNERS
        },
    }
    state_lock = asyncio.Lock()

    async def update_scanner(name: str, detail: Dict[str, Any]) -> None:
        async with state_lock:
            if name in status_data["scanners"]:
                status_data["scanners"][name] = detail["status"]
            status_data["scanner_details"][name] = detail
            finished = sum(value in {"completed", "failed", "timed_out", "unavailable", "skipped", "cancelled"} for value in status_data["scanners"].values())
            is_cancelled = scan_job_manager.is_cancelled(scan_id)
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {
                    "status": "cancelled" if is_cancelled else "running",
                    "progress": int(finished * 100 / len(SCANNERS)),
                    "scanner_status": dict(status_data["scanners"]),
                    "scanner_details": dict(status_data["scanner_details"]),
                    "runtime_status": status_data.get("runtime_status"),
                }},
            )
            await _persist_scanner_job(db, scan_id, name, detail)
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
        if scan_job_manager.is_cancelled(scan_id):
            detail = status_data["scanner_details"][scanner]
            detail.update({
                "status": "cancelled",
                "completed_at": _utc_now(),
                "error": "Scan was cancelled by user",
                "failure_stage": "cancelled",
            })
            await update_scanner(scanner, detail)
            return

        timeout_seconds = settings.scan_job_timeout_seconds
        execution_started = time.perf_counter()
        detail: Dict[str, Any] = {
            "scanner": scanner,
            "runtime": _preferred_runtime(scanner),
            "status": "running",
            "target": normalized_target,
            "stdout": "",
            "stderr": "",
            "output": "",
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
        scan_job_manager.start_tool(scan_id, scanner)
        await update_scanner(scanner, detail)
        stdout_path = output_dir / f"{scanner}.stdout.txt"
        stderr_path = output_dir / f"{scanner}.stderr.txt"
        output_path = output_dir / f"{scanner}.txt"
        stdout_path.write_bytes(b"")
        stderr_path.write_bytes(b"")
        output_path.write_bytes(b"")

        # Don't skip any scanner: always build command and attempt actual process execution

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

            def on_out(line: str):
                try:
                    with open(stdout_path, "a", encoding="utf-8", errors="replace") as f:
                        f.write(line)
                    with open(output_path, "a", encoding="utf-8", errors="replace") as f:
                        f.write(line)
                except Exception:
                    pass
                scan_job_manager.append_output(scan_id, scanner, stdout_text=line)

            def on_err(line: str):
                try:
                    with open(stderr_path, "a", encoding="utf-8", errors="replace") as f:
                        f.write(line)
                except Exception:
                    pass
                scan_job_manager.append_output(scan_id, scanner, stderr_text=line)

            def on_proc(p):
                scan_job_manager.attach_process(scan_id, scanner, p)

            ctx = scan_job_manager.get_scan(scan_id)
            cancel_evt = ctx.cancel_event if ctx else None

            try:
                raw_res = await _timed_process_command(
                    command,
                    timeout_seconds=settings.scan_job_timeout_seconds,
                    on_stdout=on_out,
                    on_stderr=on_err,
                    cancel_event=cancel_evt,
                    on_process_created=on_proc,
                )
            except TypeError:
                raw_res = await _timed_process_command(command, settings.scan_job_timeout_seconds)

            if isinstance(raw_res, dict):
                p_status = raw_res.get("status", "completed")
                p_exit_code = raw_res.get("exit_code", 0)
                stdout = raw_res.get("stdout", b"")
                stderr = raw_res.get("stderr", b"")
                p_error = raw_res.get("error")
            else:
                p_status = raw_res.status
                p_exit_code = raw_res.exit_code
                stdout = raw_res.stdout
                stderr = raw_res.stderr
                p_error = raw_res.error

            if stdout and not stdout_path.read_bytes():
                stdout_path.write_bytes(stdout)
            if stderr and not stderr_path.read_bytes():
                stderr_path.write_bytes(stderr)
            if not output_path.exists() or output_path.stat().st_size == 0:
                output_path.write_bytes(stdout)

            if p_status == "cancelled" or scan_job_manager.is_cancelled(scan_id):
                detail.update(
                    status="cancelled",
                    exit_code=p_exit_code,
                    error="Scan was cancelled by the user",
                    failure_stage="cancelled",
                    completed_at=_utc_now(),
                )
            elif p_status == "timed_out":
                detail.update(
                    status="timed_out",
                    exit_code=p_exit_code,
                    error=f"Scanner exceeded the job safety limit of {settings.scan_job_timeout_seconds}s",
                    failure_stage="job_timeout",
                    completed_at=_utc_now(),
                )
            else:
                detail["status"] = p_status
                detail["exit_code"] = p_exit_code
                detail["completed_at"] = _utc_now()
                output_error = _scanner_output_error(scanner, stdout, output_path)
                if detail.get("status") == "completed" and output_error:
                    detail.update(
                        status="failed",
                        error=output_error,
                        failure_stage="result_validation",
                    )
                else:
                    detail["error"] = p_error

            detail["stdout"] = decode_output(stdout) if isinstance(stdout, bytes) else str(stdout or "")
            detail["stderr"] = decode_output(stderr) if isinstance(stderr, bytes) else str(stderr or "")
            if output_path.exists():
                detail["output"] = output_path.read_text(encoding="utf-8", errors="replace")
            else:
                detail["output"] = detail["stdout"]

            if detail.get("status") == "completed":
                detail["failure_stage"] = None

            detail["output_file"] = f"scan-results/{scan_id}/{output_path.name}"
            detail["stdout_file"] = f"scan-results/{scan_id}/{stdout_path.name}"
            detail["stderr_file"] = f"scan-results/{scan_id}/{stderr_path.name}"
            scan_job_manager.complete_tool(
                scan_id, scanner,
                exit_code=detail.get("exit_code"),
                status=detail["status"],
                error_message=detail.get("error"),
            )
        except Exception as exc:
            error_message = str(exc) or repr(exc) or type(exc).__name__
            detail.update({"status": "failed", "completed_at": _utc_now(), "error": error_message})
            detail["failure_stage"] = "command_construction" if "command" not in detail else "process_execution"
            scan_job_manager.complete_tool(scan_id, scanner, exit_code=None, status="failed", error_message=error_message)

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

    wappalyzer_result: Dict[str, Any] = {
        "tool": "Technology Fingerprinting",
        "type": "technology_detection",
        "target": normalized_target,
        "status": "queued",
        "technologies": [],
        "technology_count": 0,
    }

    async def run_wappalyzer_tool() -> None:
        nonlocal wappalyzer_result
        if scan_job_manager.is_cancelled(scan_id):
            detail = status_data["scanner_details"]["wappalyzer"]
            detail.update({
                "status": "cancelled",
                "completed_at": _utc_now(),
                "error": "Scan was cancelled by user",
                "failure_stage": "cancelled",
            })
            await update_scanner("wappalyzer", detail)
            return

        detail = status_data["scanner_details"]["wappalyzer"]
        detail.update({
            "scanner": "wappalyzer",
            "status": "running",
            "target": normalized_target,
            "started_at": _utc_now(),
            "output_file": f"scan-results/{scan_id}/wappalyzer.json",
            "stdout_file": f"scan-results/{scan_id}/wappalyzer.txt",
            "stderr_file": f"scan-results/{scan_id}/wappalyzer.stderr.txt",
        })
        scan_job_manager.start_tool(scan_id, "wappalyzer")
        await update_scanner("wappalyzer", detail)

        w_started = time.perf_counter()
        try:
            wappalyzer_result = await _run_wappalyzer(normalized_target, scan_id=scan_id)
            detail["completed_at"] = _utc_now()
            detail["duration"] = round(time.perf_counter() - w_started, 3)
            detail["execution_seconds"] = detail["duration"]
            w_status = wappalyzer_result.get("status", "completed")
            detail["status"] = w_status
            detail["error"] = wappalyzer_result.get("error")
            techs = wappalyzer_result.get("technologies", [])
            summary_lines = [f"- {t.get('name')} (v{t.get('version', '')}) [{t.get('category', 'Technology')}]" for t in techs]
            detail["stdout"] = "\n".join(summary_lines) if summary_lines else "No web technologies fingerprinted for this target."
            detail["output"] = detail["stdout"]
            if detail["error"]:
                detail["stderr"] = str(detail["error"])
            await update_scanner("wappalyzer", detail)
            scan_job_manager.complete_tool(
                scan_id, "wappalyzer",
                exit_code=0 if w_status == "completed" else 1,
                status=w_status,
                error_message=detail.get("error"),
            )
        except Exception as exc:
            detail["status"] = "failed"
            detail["completed_at"] = _utc_now()
            detail["duration"] = round(time.perf_counter() - w_started, 3)
            detail["execution_seconds"] = detail["duration"]
            detail["error"] = str(exc)
            detail["stderr"] = str(exc)
            await update_scanner("wappalyzer", detail)
            scan_job_manager.complete_tool(
                scan_id, "wappalyzer",
                exit_code=1,
                status="failed",
                error_message=str(exc),
            )

    await asyncio.gather(
        *(run_bounded(name) for name in CORE_SCANNERS),
        run_wappalyzer_tool(),
        return_exceptions=True,
    )

    wappalyzer_json_path = output_dir / "wappalyzer.json"
    wappalyzer_txt_path = output_dir / "wappalyzer.txt"
    try:
        wappalyzer_json_path.write_text(
            json.dumps(wappalyzer_result, indent=2, default=str), encoding="utf-8"
        )
        tech_lines = [
            f"Technology Detection: {wappalyzer_result.get('target', normalized_target)}",
            f"Status: {wappalyzer_result.get('status', 'unknown')}",
            f"Technologies Detected: {wappalyzer_result.get('technology_count', len(wappalyzer_result.get('technologies', [])))}",
            "",
        ]
        for tech in wappalyzer_result.get("technologies", []):
            ver = f" (v{tech['version']})" if tech.get("version") else ""
            conf = f" [{tech.get('confidence', 0)}%]"
            tech_lines.append(f"- {tech.get('name')}{ver} | {tech.get('category')}{conf} - {tech.get('evidence', '')}")
        if wappalyzer_result.get("error"):
            tech_lines.append(f"\nError: {wappalyzer_result['error']}")
        wappalyzer_txt_path.write_text("\n".join(tech_lines), encoding="utf-8")
    except Exception as exc:
        logging.getLogger(__name__).warning("Failed to write wappalyzer evidence files: %s", exc)

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

    # If scan was cancelled by user, mark any unfinished tool as cancelled
    if scan_job_manager.is_cancelled(scan_id):
        for tool_name in ALL_SCANNERS:
            if scanner_status.get(tool_name) in ("queued", "running"):
                scanner_status[tool_name] = "cancelled"
                scanner_details[tool_name].update({
                    "status": "cancelled",
                    "error": "Scan was cancelled by user",
                    "completed_at": _utc_now(),
                })

    raw_findings_by_scanner: Dict[str, List[Dict[str, Any]]] = {
        "nmap": [],
        "nikto": [],
        "wapiti": [],
        "sqlmap": [],
        "gobuster": [],
    }
    host_discovery_data: Dict[str, Any] = {
        "hostname": normalized_target,
        "resolved_ip": "Not Resolved",
        "host_state": "UP",
        "latency": "",
        "open_ports": []
    }
    sqlmap_assessment_data: Dict[str, Any] = {
        "status": "SQLMap did not run",
        "injection_confirmed": False,
        "summary": "Assessment not performed."
    }

    for scanner in CORE_SCANNERS:
        if status_data["scanners"].get(scanner) != "completed":
            continue
        scanner_file = output_dir / f"{scanner}.txt"
        raw_output = scanner_file.read_text(encoding="utf-8", errors="replace") if scanner_file.is_file() else ""
        try:
            if scanner == "nmap":
                host_discovery_data = extract_nmap_host_discovery(raw_output, normalized_target)
                raw_findings_by_scanner["nmap"] = parse_nmap(raw_output, scan_id, normalized_target, owner_id, asset_id)
            elif scanner == "nikto":
                raw_findings_by_scanner["nikto"] = parse_nikto(raw_output, scan_id, normalized_target, owner_id, asset_id)
            elif scanner == "wapiti":
                raw_findings_by_scanner["wapiti"] = parse_wapiti(raw_output, scan_id, normalized_target, owner_id, asset_id)
            elif scanner == "sqlmap":
                sqlmap_assessment_data = extract_sqlmap_assessment(raw_output)
                raw_findings_by_scanner["sqlmap"] = parse_sqlmap(raw_output, scan_id, normalized_target, owner_id, asset_id)
            elif scanner == "gobuster":
                raw_findings_by_scanner["gobuster"] = parse_gobuster_observations(raw_output)
        except Exception as exc:
            detail = scanner_details[scanner]
            detail.update({
                "status": "failed",
                "completed_at": _utc_now(),
                "error": f"Result parsing failed: {str(exc) or repr(exc)}",
                "failure_stage": "result_parsing",
            })
            scanner_status[scanner] = "failed"

    # Correlate and deduplicate findings across scanners
    correlated_findings_objs = correlate_and_deduplicate_findings(
        raw_findings_by_scanner,
        scan_id=scan_id,
        target=normalized_target,
        asset_id=asset_id,
        owner_id=owner_id,
    )
    correlated_findings_dicts = [f.to_dict() for f in correlated_findings_objs]

    # Split into canonical verification groups
    normalized_findings: Dict[str, List[Dict[str, Any]]] = {
        "confirmed": [],
        "potential": [],
        "informational": [],
        "incomplete": [],
    }

    for f in correlated_findings_dicts:
        verif = str(f.get("verification_status", "POTENTIAL")).lower()
        if verif == "confirmed":
            normalized_findings["confirmed"].append(f)
        elif verif == "informational":
            normalized_findings["informational"].append(f)
        else:
            normalized_findings["potential"].append(f)

    # Add Gobuster path observations into informational group
    gobuster_list = raw_findings_by_scanner.get("gobuster", [])
    for index, finding in enumerate(gobuster_list, start=1):
        normalized_findings["informational"].append({
            "id": f"gobuster-{index}",
            "scanner": "gobuster",
            "path": finding.get("path", "/"),
            "detected_by": ["Gobuster"],
            "title": f"Directory Discovered: {finding.get('path', '/')}",
            "description": f"Gobuster observed {finding.get('path')} (HTTP {finding.get('status_code')}, {finding.get('response_size', 'unknown')} bytes). Informational path discovery.",
            "target": normalized_target,
            "target_url": normalized_target,
            "endpoint": finding.get("path", "/"),
            "severity": "info",
            "confidence": "HIGH",
            "verification_status": "unverified",
            "category": "Directory / Path Discovery",
            "owasp_id": "N/A",
            "owasp_category": "A01:2021 - Broken Access Control",
            "cwe_id": "N/A",
            "cwe": "Not mapped",
            "wstg": "WSTG-INFO-04",
            "evidence": {
                "raw_line": finding.get("raw_line", ""),
                "status_code": finding.get("status_code"),
                "response_size": finding.get("response_size"),
                "raw_output_file": f"scan-results/{scan_id}/gobuster.txt"
            },
            "impact": "Exposed directories and endpoints define the application attack surface.",
            "recommendation": "Review endpoint exposure. Ensure restricted routes enforce server-side authentication.",
            "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver"],
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    # Add detected technologies into informational group
    for idx, tech in enumerate(wappalyzer_result.get("technologies", []), start=1):
        normalized_findings["informational"].append({
            "id": f"wappalyzer-{idx}",
            "scanner": "Wappalyzer",
            "detected_by": ["Wappalyzer"],
            "source": f"scan-results/{scan_id}/wappalyzer.json",
            "classification": "informational",
            "verification_status": "INFORMATIONAL",
            "title": f"Technology Detected: {tech.get('name')}",
            "category": tech.get("category", "Technology Stack"),
            "owasp_id": "N/A",
            "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
            "cwe_id": "N/A",
            "cwe": "Not mapped",
            "wstg": "WSTG-INFO-08",
            "severity": "info",
            "confidence": "HIGH",
            "evidence": {
                "name": tech.get("name"),
                "version": tech.get("version"),
                "category": tech.get("category"),
                "evidence": tech.get("evidence"),
            },
            "target": normalized_target,
            "target_url": normalized_target,
            "description": f"Detected {tech.get('name')} {tech.get('version') or ''} ({tech.get('category')})",
            "impact": "Identified web stack component. Informational reconnaissance data.",
            "recommendation": "Maintain inventory of components and keep libraries updated to latest supported releases.",
            "references": ["https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components/"],
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    for scanner, scanner_state in scanner_status.items():
        if scanner_state != "completed":
            detail = scanner_details[scanner]
            normalized_findings["incomplete"].append({
                "id": f"{scanner}-incomplete",
                "scanner": scanner,
                "detected_by": [scanner.capitalize()],
                "source": f"scan-results/{scan_id}/{scanner}.txt",
                "classification": "incomplete",
                "verification_status": "INCOMPLETE",
                "status": scanner_state,
                "exit_code": detail.get("exit_code"),
                "title": f"Scanner Job Incomplete: {scanner.capitalize()} ({scanner_state})",
                "message": detail.get("error") or f"{scanner} did not complete successfully ({scanner_state})",
                "raw_output_file": detail.get("output_file"),
                "stderr_file": detail.get("stderr_file"),
            })

    tool_summaries = {}
    for tool in ALL_SCANNERS:
        st = scanner_status.get(tool, "unknown")
        dt = scanner_details.get(tool, {})
        tool_findings_count = sum(
            1 for group in ("confirmed", "potential", "informational")
            for f in normalized_findings.get(group, [])
            if tool.lower() in [s.lower() for s in f.get("detected_by", [f.get("scanner", "")])]
        )
        if st == "completed":
            msg = f"{tool_findings_count} finding(s) detected by this tool." if tool_findings_count > 0 else "No findings detected by this tool."
        elif st == "cancelled":
            msg = "Scan was cancelled by the user."
        elif st == "failed":
            msg = f"FAILED (exit code {dt.get('exit_code')}): {dt.get('error') or 'Process failed'}"
        else:
            msg = f"INCOMPLETE ({st}): {dt.get('error') or 'Tool did not complete'}"
        tool_summaries[tool] = {
            "tool_name": tool,
            "status": st,
            "exit_code": dt.get("exit_code"),
            "duration": dt.get("duration", 0.0),
            "findings_count": tool_findings_count,
            "summary_message": msg,
        }

    if scan_job_manager.is_cancelled(scan_id):
        overall_status = "cancelled"
    else:
        overall_status = aggregate_scanner_status(scanner_status)

    status_data["status"] = overall_status
    status_data["completed_at"] = _utc_now()

    confirmed_findings = normalized_findings["confirmed"]
    potential_findings = normalized_findings["potential"]
    informational_findings = normalized_findings["informational"]
    incomplete_findings = normalized_findings["incomplete"]

    # Calculate transparent VulnAI Project Risk Score including potential deductions
    risk_score = compute_scan_risk(
        [*confirmed_findings, *potential_findings],
        scanner_status=scanner_status,
    )
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in [*confirmed_findings, *potential_findings]:
        severity = str(finding.get("severity", "info")).lower()
        if severity in severity_summary:
            severity_summary[severity] += 1
        else:
            severity_summary["info"] += 1

    assessment_coverage = get_assessment_coverage(scanner_status)
    owasp_coverage = get_owasp_coverage_matrix(
        [*confirmed_findings, *potential_findings],
        scanner_status,
    )

    combined_results = {
        "scan_id": scan_id,
        "target": normalized_target,
        "status": overall_status,
        "runtime_status": runtime_status,
        "technology_detection": wappalyzer_result,
        "host_discovery": host_discovery_data,
        "sql_assessment": sqlmap_assessment_data,
        "assessment_coverage": assessment_coverage,
        "owasp_coverage": owasp_coverage,
        "tool_summaries": tool_summaries,
        "confirmed": confirmed_findings,
        "potential": potential_findings,
        "informational": informational_findings,
        "incomplete": incomplete_findings,
        "correlated_findings": correlated_findings_dicts,
        "scanner_status": dict(scanner_status),
        "scanner_details": dict(scanner_details),
        "risk_score": risk_score,
        "counts": {
            "confirmed": len(confirmed_findings),
            "potential": len(potential_findings),
            "informational": len(informational_findings),
            "incomplete": len(incomplete_findings),
        }
    }

    unified_results_path = output_dir / "unified-results.json"
    unified_results_tmp = unified_results_path.with_suffix(".json.tmp")
    unified_results_tmp.write_text(
        json.dumps(combined_results, indent=2, default=str), encoding="utf-8"
    )
    os.replace(unified_results_tmp, unified_results_path)
    await _write_status_file(output_dir, status_data)

    all_findings = [
        *confirmed_findings,
        *potential_findings,
        *informational_findings,
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
        combined_results=combined_results,
    )
    evidence_files = {
        scanner: f"scan-results/{scan_id}/{scanner}.txt"
        for scanner in ALL_SCANNERS
    }
    evidence_files["unified_results"] = f"scan-results/{scan_id}/unified-results.json"
    evidence_files["wappalyzer"] = f"scan-results/{scan_id}/wappalyzer.json"

    # Store findings in db.vulnerabilities
    if all_findings and hasattr(db, "vulnerabilities"):
        try:
            if hasattr(db.vulnerabilities, "delete_many"):
                await db.vulnerabilities.delete_many({"scan_id": scan_id})
            vuln_docs = []
            for f in all_findings:
                doc = copy.deepcopy(f)
                doc.setdefault("scan_id", scan_id)
                doc.setdefault("asset_id", asset_id)
                doc.setdefault("owner_id", owner_id)
                doc.setdefault("target_url", normalized_target)
                doc.setdefault("status", "open")
                doc.setdefault("created_at", datetime.now(timezone.utc))
                vuln_docs.append(doc)
            await db.vulnerabilities.insert_many(vuln_docs)
        except Exception as exc:
            logging.getLogger(__name__).warning("Failed to insert findings into vulnerabilities collection: %s", exc)

    # Persist all scanner jobs to database
    for tool_name in ALL_SCANNERS:
        await _persist_scanner_job(db, scan_id, tool_name, scanner_details.get(tool_name, {}))

    scan_duration = round(time.perf_counter() - overall_started, 3)
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": overall_status,
            "progress": 100 if overall_status != "running" else 0,
            "ended_at": datetime.now(timezone.utc),
            "completed_at": datetime.now(timezone.utc),
            "duration": scan_duration,
            "scanner_status": dict(scanner_status),
            "scanner_details": dict(scanner_details),
            "tool_summaries": tool_summaries,
            "evidence_files": evidence_files,
            "combined_results": combined_results,
            "results": all_findings,
            "total_findings": len(confirmed_findings),
            "findings_count": len(confirmed_findings) + len(potential_findings),
            "confirmed_count": len(confirmed_findings),
            "potential_count": len(potential_findings),
            "informational_count": len(informational_findings),
            "incomplete_count": len(incomplete_findings),
            "severity_summary": severity_summary,
            "risk_score": risk_score,
            "security_score": risk_score.get("score") if (overall_status == "completed" and not risk_score.get("is_indeterminate")) else None,
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
