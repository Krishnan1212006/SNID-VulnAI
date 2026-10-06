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
from app.services.scanner_runtime import ScannerRuntime, decode_output
from app.parsers.wapiti_parser import _classify_type
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
    if not payload:
        return findings

    raw_items: List[tuple[str, Dict[str, Any]]] = []

    if isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, dict):
                raw_items.append((str(entry.get("category") or entry.get("name") or "Web Application Security"), entry))
    elif isinstance(payload, dict):
        # 1. Wapiti 3.x dict in 'vulnerabilities'
        vulns_obj = payload.get("vulnerabilities")
        if isinstance(vulns_obj, dict):
            for cat, items_list in vulns_obj.items():
                if isinstance(items_list, list):
                    for item in items_list:
                        if isinstance(item, dict):
                            raw_items.append((cat, item))
        elif isinstance(vulns_obj, list):
            for item in vulns_obj:
                if isinstance(item, dict):
                    raw_items.append((str(item.get("category") or "Web Application Security"), item))

        # 2. Wapiti 3.x dict in 'anomalies'
        anomalies_obj = payload.get("anomalies")
        if isinstance(anomalies_obj, dict):
            for cat, items_list in anomalies_obj.items():
                if isinstance(items_list, list):
                    for item in items_list:
                        if isinstance(item, dict):
                            raw_items.append((cat, item))

        # 3. Flat 'issues' or 'findings' lists
        for alt_key in ("issues", "findings"):
            alt_list = payload.get(alt_key)
            if isinstance(alt_list, list):
                for item in alt_list:
                    if isinstance(item, dict):
                        raw_items.append((str(item.get("category") or "Web Application Security"), item))

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    level_num_map = {
        0: "info",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }

    for cat_name, item in raw_items:
        raw_level = item.get("level")
        raw_sev = item.get("severity") or item.get("risk")
        if isinstance(raw_level, int) and raw_level in level_num_map:
            severity = level_num_map[raw_level]
        elif isinstance(raw_sev, str):
            severity = severity_map.get(raw_sev.lower().strip(), "medium")
        elif isinstance(raw_level, str):
            severity = severity_map.get(raw_level.lower().strip(), "medium")
        else:
            meta_default = _classify_type(cat_name)
            severity = meta_default["severity"]

        info = str(item.get("info") or "").strip()
        name = str(item.get("name") or item.get("title") or "").strip()
        param = item.get("parameter") or item.get("param")
        parameter = str(param) if param else "N/A"

        path = item.get("path")
        item_url = item.get("url") or item.get("target_url")
        if not item_url and path:
            item_url = f"{target.rstrip('/')}{path if path.startswith('/') else '/' + path}"
        url = str(item_url or target)

        module = str(item.get("module") or item.get("source") or "wapiti")

        if cat_name and cat_name != "Web Application Security":
            if parameter != "N/A":
                title = f"{cat_name} via '{parameter}'"
            elif info and info.lower() != cat_name.lower():
                title = f"{cat_name}: {info[:60]}"
            else:
                title = cat_name
        else:
            title = name or info or "Potential Wapiti finding"

        desc = info or item.get("description") or item.get("details") or title
        meta = _classify_type(cat_name or title)

        findings.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target_url": url,
            "title": title,
            "severity": severity,
            "confidence": "potential",
            "source": "wapiti",
            "category": meta["category"],
            "owasp_id": meta["owasp"],
            "cwe_id": meta["cwe"],
            "description": desc,
            "evidence": {
                "module": module,
                "category": cat_name,
                "parameter": parameter,
                "method": item.get("method"),
                "curl_command": item.get("curl_command"),
                "wstg": item.get("wstg") or [],
                "raw": item,
            },
            "ai_analysis": {
                "priority": severity,
                "problem": desc,
                "impact": meta["impact"],
                "recommendation": f"Validate and sanitize input for {parameter}. Implement appropriate security controls, input validation, or framework-level protection.",
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

    runtime = ScannerRuntime()
    wapiti_path = shutil.which("wapiti") or shutil.which("wapiti3")
    uses_wsl = False

    if not wapiti_path and runtime.uses_wsl:
        check = await runtime.capture_runtime(["command", "-v", "wapiti"])
        if check.status == "completed" and check.stdout.strip():
            wapiti_path = "wapiti"
            uses_wsl = True

    if not wapiti_path:
        await _fail_scan(db, scan_id, "Wapiti is not installed. Install wapiti or wapiti3 in the backend or WSL environment.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(settings.scan_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"wapiti_{scan_id}_{timestamp}.json"

    LIVE_TERMINAL_BUFFERS[scan_id] = [
        "[*] Starting direct Wapiti scan...",
        f"[*] Target: {validated_url}",
        f"[*] Output file: {output_file}",
        f"[*] Runtime: {'WSL (' + runtime.distribution + ')' if uses_wsl else 'Host'}",
    ]

    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {"status": "running", "progress": 10, "target_url": validated_url, "scanner_status": {"wapiti": "running"}}},
    )

    try:
        if uses_wsl:
            wsl_path_res = await runtime.capture_runtime(["wslpath", "-a", str(output_file.resolve())])
            target_output = decode_output(wsl_path_res.stdout) if wsl_path_res.status == "completed" else str(output_file)
            cmd = runtime.wrap_runtime_command([
                wapiti_path,
                "-u",
                validated_url,
                "-f",
                "json",
                "-o",
                target_output,
            ])
        else:
            cmd = [
                wapiti_path,
                "-u",
                validated_url,
                "-f",
                "json",
                "-o",
                str(output_file),
            ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
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
