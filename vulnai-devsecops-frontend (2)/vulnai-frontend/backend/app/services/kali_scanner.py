"""
Kali Linux Assessment Engine Integration Service.

Securely invokes the authorized Bash scanner script (Nmap, Nikto, Wapiti, SQLMap, Gobuster),
streams console execution output in real time, parses raw evidence files into
    normalized findings in Postgres, and computes explainable risk scores.
"""

import asyncio
import json
import os
import shutil
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from app.core.ids import ObjectId

from app.core.config import settings
from app.services.scanner import validate_url_for_ssrf, SSRFProtectionError
from app.services.risk_scoring import compute_scan_risk
from app.parsers import (
    parse_nmap,
    parse_nikto,
    parse_wapiti,
    parse_sqlmap,
    parse_gobuster,
)

# In-memory terminal line buffer for live polling: scan_id -> list of lines
LIVE_TERMINAL_BUFFERS: Dict[str, List[str]] = {}


def validate_wapiti_target(url: str) -> str:
    """Validate a target URL before invoking the Wapiti CLI."""
    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("Target URL is required")

    if any(char in candidate for char in ["\r", "\n", "\x00"]):
        raise ValueError("Target URL contains invalid characters")

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// targets are allowed")
    if not parsed.hostname:
        raise ValueError("Invalid target URL")
    return candidate


def normalize_wapiti_findings(payload: Any, scan_id: str, target: str, owner_id: str, asset_id: str) -> List[Dict[str, Any]]:
    """Normalize Wapiti JSON output into VulnAI finding documents."""
    findings: List[Dict[str, Any]] = []
    if payload is None:
        return findings

    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = payload.get("vulnerabilities") or payload.get("issues") or payload.get("findings") or []
    else:
        items = []

    if isinstance(items, dict):
        items = [items]

    for item in items:
        if not isinstance(item, dict):
            continue

        level = str(item.get("level") or item.get("severity") or item.get("risk") or "info").lower()
        title = str(item.get("name") or item.get("title") or "Potential Wapiti finding")
        description = str(item.get("description") or item.get("details") or title)
        url = str(item.get("url") or item.get("target_url") or target)
        parameter = str(item.get("parameter") or item.get("param") or "N/A")
        module = str(item.get("module") or item.get("source") or "wapiti")

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
        }
        severity = severity_map.get(level, "medium")

        findings.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target_url": url,
            "title": title,
            "severity": severity,
            "confidence": "potential",
            "source": "wapiti",
            "category": "Web Application Security",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "description": description,
            "evidence": {
                "module": module,
                "parameter": parameter,
                "raw": item,
            },
            "ai_analysis": {
                "priority": severity,
                "problem": description,
                "impact": "Potential web application weakness may expose application data or enable user impact.",
                "recommendation": "Review the vulnerability through the reported endpoint and fix the underlying validation or output-handling issue.",
                "verification_steps": [
                    f"Inspect the reported endpoint: {url}",
                    f"Validate the parameter '{parameter}' in a controlled test environment.",
                    "Confirm the issue by reproducing the condition with an explicit proof-of-concept.",
                ],
            },
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    return findings


def get_terminal_output(scan_id: str) -> List[str]:
    """Retrieve in-memory live terminal logs for a running or recent scan."""
    return LIVE_TERMINAL_BUFFERS.get(scan_id, [])


def _resolve_bash_command() -> str:
    """Detect available bash execution binary."""
    # Check if running in Linux or Docker container where /bin/bash exists
    if os.path.exists("/bin/bash"):
        return "/bin/bash"
    if os.path.exists("/usr/bin/bash"):
        return "/usr/bin/bash"

    # On Windows / WSL environments
    for candidate in ["bash", "bash.exe", "wsl", "wsl.exe"]:
        found = shutil.which(candidate)
        if found:
            return found

    return "bash"


async def run_wapiti_scan(scan_id: str, db):
    """Run a direct Wapiti scan without requiring Kali Linux or the bash wrapper script."""
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan or scan.get("status") == "cancelled":
        return

    asset_id = scan.get("asset_id")
    owner_id = scan.get("owner_id", "system")
    target_url = scan.get("target_url")

    if not target_url and asset_id:
        try:
            asset = await db.assets.find_one({"_id": ObjectId(asset_id)})
            if asset and asset.get("target_urls"):
                target_url = asset["target_urls"][0]
        except Exception:
            pass

    if not target_url:
        await _fail_scan(db, scan_id, "No valid target URL specified for Wapiti assessment.")
        return

    try:
        validated_url = validate_wapiti_target(target_url)
    except ValueError as exc:
        await _fail_scan(db, scan_id, str(exc))
        return

    try:
        validate_url_for_ssrf(validated_url, lab_mode=bool(scan.get("lab_mode", False)))
    except SSRFProtectionError as exc:
        await _fail_scan(db, scan_id, f"SSRF Protection blocked target: {str(exc)}")
        return

    wapiti_path = shutil.which("wapiti") or shutil.which("wapiti3")
    if not wapiti_path:
        await _fail_scan(db, scan_id, "Wapiti is not installed. Install wapiti3 in the backend environment.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(settings.scan_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"wapiti_{scan_id}_{timestamp}.json"

    LIVE_TERMINAL_BUFFERS[scan_id] = [
        "[*] Starting direct Wapiti scan...",
        f"[*] Target: {validated_url}",
        f"[*] Output file: {output_file}",
    ]

    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {"status": "running", "progress": 10, "target_url": validated_url, "scanner_status": {"wapiti": "running"}}},
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            wapiti_path,
            "-u",
            validated_url,
            "-f",
            "json",
            "-o",
            str(output_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            if line:
                LIVE_TERMINAL_BUFFERS[scan_id].append(line)
                if len(LIVE_TERMINAL_BUFFERS[scan_id]) > 500:
                    LIVE_TERMINAL_BUFFERS[scan_id].pop(0)

        await proc.wait()

        if proc.returncode not in (0, 1):
            await _fail_scan(db, scan_id, f"Wapiti exited with code {proc.returncode}")
            return

        if not output_file.exists():
            raise FileNotFoundError(f"Wapiti did not create the output file at {output_file}")

        raw = json.loads(output_file.read_text(encoding="utf-8", errors="replace"))
        findings = normalize_wapiti_findings(raw, scan_id, validated_url, owner_id, asset_id)

        if findings:
            await db.vulnerabilities.insert_many(findings)

        score_data = compute_scan_risk(findings)
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = str(finding.get("severity", "info")).lower()
            severity_summary[sev] = severity_summary.get(sev, 0) + 1

        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {
                "status": "completed",
                "progress": 100,
                "ended_at": datetime.now(timezone.utc),
                "scanner_status": {"wapiti": "completed"},
                "evidence_files": {"wapiti": str(output_file)},
                "risk_score": score_data,
                "security_score": score_data.get("score", 100),
                "total_findings": len(findings),
                "severity_summary": severity_summary,
                "results": findings,
            }}
        )
        LIVE_TERMINAL_BUFFERS[scan_id].append("[✓] Wapiti assessment completed successfully.")
    except Exception as exc:
        await _fail_scan(db, scan_id, f"Wapiti scan failed: {str(exc)}")


async def run_kali_scan(scan_id: str, db):
    """
    Execute the authorized Kali assessment bash script as an asynchronous subprocess.
    """
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        return

    if scan.get("status") == "cancelled":
        return

    asset_id = scan.get("asset_id")
    owner_id = scan.get("owner_id", "system")
    target_url = scan.get("target_url")

    # If target_url wasn't saved on scan, resolve from asset
    if not target_url and asset_id:
        try:
            asset = await db.assets.find_one({"_id": ObjectId(asset_id)})
            if asset and asset.get("target_urls"):
                target_url = asset["target_urls"][0]
        except Exception:
            pass

    if not target_url:
        await _fail_scan(db, scan_id, "No valid target URL specified for assessment.")
        return

    # 1. SSRF Validation
    lab_mode = scan.get("lab_mode", False)
    try:
        validated_url = validate_url_for_ssrf(target_url, lab_mode=lab_mode)
    except SSRFProtectionError as e:
        await _fail_scan(db, scan_id, f"SSRF Protection blocked target: {str(e)}")
        return

    # 2. Prepare Output Directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", validated_url.replace("https://", "").replace("http://", "").split("/")[0])
    output_dir = Path(settings.scan_output_dir) / f"security_scan_{safe_host}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    abs_output_dir = str(output_dir.resolve())

    # Script location
    script_path = Path(settings.kali_script_path).resolve()
    if not script_path.exists():
        # Fallback to local project script path
        local_script = Path(__file__).resolve().parent.parent.parent / "scripts" / "kali_scanner.sh"
        if local_script.exists():
            script_path = local_script
        else:
            await _fail_scan(db, scan_id, f"Kali assessment script not found at {script_path}")
            return

    # 3. Initialize scan tracking state
    scanner_status = {
        "nmap": "queued",
        "nikto": "queued",
        "wapiti": "queued",
        "sqlmap": "queued",
        "gobuster": "queued",
    }

    LIVE_TERMINAL_BUFFERS[scan_id] = [
        f"[*] Initializing VulnAI Kali Assessment Engine...",
        f"[*] Target: {validated_url}",
        f"[*] Output directory: {abs_output_dir}",
        f"[*] Script: {script_path}",
    ]

    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {
            "$set": {
                "status": "running",
                "progress": 5,
                "target_url": validated_url,
                "kali_output_dir": abs_output_dir,
                "scanner_status": scanner_status,
                "started_at": datetime.now(timezone.utc),
            }
        }
    )

    bash_bin = _resolve_bash_command()
    wordlist = settings.kali_wordlist

    # Command arguments: strictly parameterized array (NO shell=True)
    cmd = [
        bash_bin,
        str(script_path),
        validated_url,
        wordlist,
        abs_output_dir
    ]

    # Convert Windows backslashes for bash/WSL if needed
    if "wsl" in bash_bin.lower():
        # When invoking wsl, pass linux-friendly paths
        linux_script = str(script_path).replace("\\", "/")
        linux_out = str(abs_output_dir).replace("\\", "/")
        if ":" in linux_script:
            drive, rest = linux_script.split(":", 1)
            linux_script = f"/mnt/{drive.lower()}{rest}"
        if ":" in linux_out:
            drive, rest = linux_out.split(":", 1)
            linux_out = f"/mnt/{drive.lower()}{rest}"
        cmd = [bash_bin, linux_script, validated_url, wordlist, linux_out]

    current_progress = 5
    last_db_sync = datetime.now()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        # Stream stdout line by line
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break

            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            LIVE_TERMINAL_BUFFERS[scan_id].append(line)
            if len(LIVE_TERMINAL_BUFFERS[scan_id]) > 1000:
                LIVE_TERMINAL_BUFFERS[scan_id].pop(0)

            # Analyze output line for progress indicators
            line_upper = line.upper()

            if "NMAP - HOST / PORT" in line_upper:
                scanner_status["nmap"] = "running"
                current_progress = 20
            elif "NMAP COMPLETED" in line_upper or "NMAP REACHED" in line_upper:
                scanner_status["nmap"] = "completed"
                current_progress = 35

            elif "NIKTO - WEB SERVER" in line_upper:
                scanner_status["nmap"] = "completed"
                scanner_status["nikto"] = "running"
                current_progress = 40
            elif "NIKTO COMPLETED" in line_upper or "NIKTO REACHED" in line_upper:
                scanner_status["nikto"] = "completed"
                current_progress = 55

            elif "WAPITI - WEB APPLICATION" in line_upper:
                scanner_status["nikto"] = "completed"
                scanner_status["wapiti"] = "running"
                current_progress = 60
            elif "WAPITI COMPLETED" in line_upper or "WAPITI REACHED" in line_upper:
                scanner_status["wapiti"] = "completed"
                current_progress = 70

            elif "SQLMAP - AUTHORIZED" in line_upper:
                scanner_status["wapiti"] = "completed"
                scanner_status["sqlmap"] = "running"
                current_progress = 75
            elif "SQLMAP COMPLETED" in line_upper or "SQLMAP REACHED" in line_upper:
                scanner_status["sqlmap"] = "completed"
                current_progress = 85

            elif "GOBUSTER - DIRECTORY" in line_upper:
                scanner_status["sqlmap"] = "completed"
                scanner_status["gobuster"] = "running"
                current_progress = 90
            elif "GOBUSTER COMPLETED" in line_upper or "GOBUSTER REACHED" in line_upper:
                scanner_status["gobuster"] = "completed"
                current_progress = 95

            # Sync progress periodically to DB (every 3 seconds)
            now = datetime.now()
            if (now - last_db_sync).total_seconds() >= 3:
                last_db_sync = now
                await db.scans.update_one(
                    {"_id": ObjectId(scan_id)},
                    {
                        "$set": {
                            "progress": current_progress,
                            "scanner_status": scanner_status,
                        }
                    }
                )

        await proc.wait()

        if proc.returncode != 0:
            await _fail_scan(
                db,
                scan_id,
                f"Assessment script exited with code {proc.returncode}; check the terminal output and scanner dependencies.",
            )
            return

        # Mark all active tools completed
        for k in scanner_status:
            if scanner_status[k] in ["queued", "running"]:
                scanner_status[k] = "completed"

        # 4. Parse evidence files generated by Kali scanners
        all_findings = []
        evidence_files = {}

        nmap_file = output_dir / "nmap.txt"
        if nmap_file.exists():
            evidence_files["nmap"] = str(nmap_file)
            content = nmap_file.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(parse_nmap(content, scan_id, validated_url, owner_id, asset_id))

        nikto_file = output_dir / "nikto.txt"
        if nikto_file.exists():
            evidence_files["nikto"] = str(nikto_file)
            content = nikto_file.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(parse_nikto(content, scan_id, validated_url, owner_id, asset_id))

        wapiti_file = output_dir / "wapiti.txt"
        if wapiti_file.exists():
            evidence_files["wapiti"] = str(wapiti_file)
            content = wapiti_file.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(parse_wapiti(content, scan_id, validated_url, owner_id, asset_id))

        sqlmap_file = output_dir / "sqlmap.txt"
        if sqlmap_file.exists():
            evidence_files["sqlmap"] = str(sqlmap_file)
            content = sqlmap_file.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(parse_sqlmap(content, scan_id, validated_url, owner_id, asset_id))

        gobuster_file = output_dir / "gobuster.txt"
        if gobuster_file.exists():
            evidence_files["gobuster"] = str(gobuster_file)
            content = gobuster_file.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(parse_gobuster(content, scan_id, validated_url, owner_id, asset_id))

        html_report = output_dir / "security_assessment_report.html"
        md_report = output_dir / "security_assessment_report.md"

        # Insert findings into vulnerabilities collection
        if all_findings:
            await db.vulnerabilities.insert_many(all_findings)

        # Calculate risk score
        score_data = compute_scan_risk(all_findings)

        # Compute severity summary
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_summary:
                severity_summary[sev] += 1
            else:
                severity_summary["info"] += 1

        # 5. Complete scan record
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": "completed",
                    "progress": 100,
                    "ended_at": datetime.now(timezone.utc),
                    "scanner_status": scanner_status,
                    "evidence_files": evidence_files,
                    "report_html_path": str(html_report) if html_report.exists() else None,
                    "report_md_path": str(md_report) if md_report.exists() else None,
                    "security_score": score_data.get("score", 100),
                    "risk_score": score_data,
                    "total_findings": len(all_findings),
                    "severity_summary": severity_summary,
                }
            }
        )

        LIVE_TERMINAL_BUFFERS[scan_id].append("[✓] Assessment completed successfully.")

    except Exception as e:
        await _fail_scan(db, scan_id, f"Scan failed during execution: {str(e)}")


async def _fail_scan(db, scan_id: str, error_msg: str):
    """Mark scan as failed with error details recorded."""
    if scan_id in LIVE_TERMINAL_BUFFERS:
        LIVE_TERMINAL_BUFFERS[scan_id].append(f"[!] ERROR: {error_msg}")
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {
            "$set": {
                "status": "failed",
                "progress": 0,
                "ended_at": datetime.now(timezone.utc),
                "error_message": error_msg,
            }
        }
    )
