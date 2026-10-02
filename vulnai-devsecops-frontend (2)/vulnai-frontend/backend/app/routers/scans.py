from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List
import os
from app.core.ids import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import HTMLResponse
from app.database import get_database
from app.dependencies import get_current_user
from app.schemas.scan import ScanCreate, ScanResponse, ScanResultResponse
from app.services.scanner import run_safe_scan
from app.services.kali_scanner import run_kali_scan, run_wapiti_scan, get_terminal_output
from app.core.config import settings
from app.core.paths import SCAN_RESULTS_ROOT
from app.routers.audit import log_audit_action
from app.parsers.gobuster_parser import parse_gobuster_observations
from app.services.unified_scan import AssessmentTargetError, run_unified_assessment, validate_assessment_target
from app.services.unified_scan import SCANNER_BINARIES
from app.services.scanner_runtime import scanner_runtime

router = APIRouter()


@router.get("/runtime-status")
async def get_scanner_runtime_status(current_user: dict = Depends(get_current_user)):
    """Check WSL and scanner executables without starting a scan."""
    return await scanner_runtime.preflight_matrix(SCANNER_BINARIES)
NIKTO_RESULT = SCAN_RESULTS_ROOT / "nikto.json"
GOBUSTER_RESULT = SCAN_RESULTS_ROOT / "gobuster.txt"


@router.get("/nikto")
async def get_nikto_results(current_user: dict = Depends(get_current_user)):
    if not NIKTO_RESULT.exists():
        raise HTTPException(status_code=404, detail="Nikto result not found")

    try:
        with NIKTO_RESULT.open("r", encoding="utf-8") as result_file:
            scans = json.load(result_file)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Nikto result contains invalid JSON") from exc

    if not isinstance(scans, list):
        raise HTTPException(status_code=500, detail="Nikto result has an unsupported format")

    for scan in scans:
        host = scan.get("host", "")
        port = scan.get("port")
        is_https = port == 443 or bool(scan.get("ssl_info"))
        scheme = "https" if is_https else "http"
        host_url = f"{scheme}://{host}"
        if port and port not in (80, 443):
            host_url = f"{host_url}:{port}"

        normalized_findings = []
        for index, finding in enumerate(scan.get("vulnerabilities", [])):
            message = finding.get("msg", "")
            lower_message = message.lower()
            lower_url = finding.get("url", "").lower()
            potential = (
                "vulnerability" in lower_message
                or "phpinfo()" in lower_message
                or "control panel" in lower_message
                or "mail package installed" in lower_message
                or "webmail" in lower_url
                or "phpinfo.php" in lower_url
                or "securecontrolpanel" in lower_url
            )
            finding_url = finding.get("url", "")
            target_url = finding_url if finding_url.startswith(("http://", "https://")) else f"{host_url}/{finding_url.lstrip('/')}"
            normalized_findings.append({
                "id": f"{finding.get('id', 'nikto')}-{index}",
                "scanner": "nikto",
                "scanner_id": finding.get("id"),
                "title": message,
                "severity": "potential" if potential else "informational",
                "status": "unverified",
                "target_url": target_url,
                "method": finding.get("method"),
                "references": finding.get("references", ""),
                "raw_message": message,
            })
        scan["normalized_findings"] = normalized_findings

    return scans


@router.get("/gobuster")
async def get_gobuster_results(current_user: dict = Depends(get_current_user)):
    if not GOBUSTER_RESULT.exists():
        raise HTTPException(status_code=404, detail="Gobuster result not found")

    try:
        raw_output = GOBUSTER_RESULT.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Unable to read Gobuster result") from exc

    return {
        "scanner": "gobuster",
        "source": "scan-results/gobuster.txt",
        "status": "completed",
        "raw_output": raw_output,
        "observations": parse_gobuster_observations(raw_output),
    }


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan: ScanCreate, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    if not scan.authorized:
        raise HTTPException(status_code=400, detail="Cannot create scan without confirmed authorization.")

    if scan.kali_mode and not settings.kali_enabled:
        raise HTTPException(status_code=503, detail="Comprehensive scanner mode is disabled on this server.")

    if scan.kali_mode and scan.unified_mode:
        raise HTTPException(status_code=400, detail="Choose either legacy Kali mode or unified assessment mode.")
    
    if not scan.asset_id:
        raise HTTPException(status_code=400, detail="Asset ID is required to start a scan.")
    
    # Verify asset ownership
    db = get_database()
    asset = await db.assets.find_one({
        "_id": ObjectId(scan.asset_id), 
        "owner_id": str(current_user["_id"])
    })
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    target_url = None
    if scan.target_urls and len(scan.target_urls) > 0:
        target_url = scan.target_urls[0]
    elif asset.get("target_urls") and len(asset["target_urls"]) > 0:
        target_url = asset["target_urls"][0]

    if scan.unified_mode:
        if not target_url:
            raise HTTPException(status_code=400, detail="A target URL is required for unified assessment.")
        try:
            target_url = validate_assessment_target(target_url, lab_mode=scan.lab_mode)
        except AssessmentTargetError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    new_scan = {
        "asset_id": scan.asset_id,
        "owner_id": str(current_user["_id"]),
        "status": "queued",
        "progress": 0,
        "lab_mode": scan.lab_mode,
        "kali_mode": scan.kali_mode,
        "unified_mode": scan.unified_mode,
        "target_url": target_url,
        "started_at": datetime.now(timezone.utc),
        "ended_at": None,
        "results": []
    }
    
    result = await db.scans.insert_one(new_scan)
    scan_id = str(result.inserted_id)
    new_scan["id"] = scan_id
    
    # Launch background job based on scan mode. Prefer Wapiti for direct web scanning
    # unless the legacy Kali path is explicitly requested.
    if scan.unified_mode:
        background_tasks.add_task(run_unified_assessment, scan_id, db)
    elif scan.kali_mode:
        background_tasks.add_task(run_kali_scan, scan_id, db)
    else:
        background_tasks.add_task(run_wapiti_scan, scan_id, db)
    
    await log_audit_action(current_user["_id"], "Authorization Confirmed", {"asset_id": scan.asset_id, "target_urls": scan.target_urls, "kali_mode": scan.kali_mode})
    await log_audit_action(current_user["_id"], "Scan Started", {"scan_id": scan_id, "asset_id": scan.asset_id, "kali_mode": scan.kali_mode})
    
    return new_scan

@router.get("/", response_model=List[ScanResponse])
async def get_scans(current_user: dict = Depends(get_current_user)):
    db = get_database()
    scans = await db.scans.find({"owner_id": str(current_user["_id"])}).sort("started_at", -1).to_list(length=100)
    
    formatted_scans = []
    for s in scans:
        s["id"] = str(s["_id"])
        formatted_scans.append(s)
    return formatted_scans

@router.get("/trends")
async def get_scan_trends(current_user: dict = Depends(get_current_user)):
    db = get_database()
    scans = await db.scans.find(
        {"owner_id": str(current_user["_id"]), "status": "completed"}
    ).sort("started_at", -1).limit(5).to_list(length=5)
    
    scans.reverse()
    
    trendData = []
    for s in scans:
        date_str = s.get("started_at").strftime("%b %d") if s.get("started_at") else "Unknown"
        risk_score = s.get("risk_score") or {}
        trendData.append({
            "date": date_str,
            "score": risk_score.get("score", 0) if isinstance(risk_score, dict) else 0
        })
        
    return trendData


@router.get("/{scan_id}/assessment-status")
async def get_assessment_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        scan_object_id = ObjectId(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid scan ID") from exc

    scan = await db.scans.find_one({"_id": scan_object_id, "owner_id": str(current_user["_id"])})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.get("unified_mode"):
        raise HTTPException(status_code=400, detail="Scan is not a unified assessment")

    return {
        "scan_id": scan_id,
        "target": scan.get("target_url"),
        "status": scan.get("status", "unknown"),
        "progress": scan.get("progress", 0),
        "scanners": scan.get("scanner_status", {}),
        "scanner_details": scan.get("scanner_details", {}),
        "runtime_status": scan.get("runtime_status"),
        "started_at": scan.get("started_at"),
        "ended_at": scan.get("ended_at"),
        "error_message": scan.get("error_message"),
    }


@router.get("/{scan_id}/assessment-results")
async def get_assessment_results(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        scan_object_id = ObjectId(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid scan ID") from exc

    scan = await db.scans.find_one({"_id": scan_object_id, "owner_id": str(current_user["_id"])})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.get("unified_mode"):
        raise HTTPException(status_code=400, detail="Scan is not a unified assessment")
    if not scan.get("combined_results"):
        raise HTTPException(status_code=409, detail="Unified assessment results are not ready")
    return scan["combined_results"]

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    s["id"] = str(s["_id"])
    return s

@router.get("/{scan_id}/progress")
async def get_scan_progress(scan_id: str, current_user: dict = Depends(get_current_user)):
    # Simply retrieves the progress %
    s = await get_scan_status(scan_id, current_user)
    return {
        "progress": s.get("progress", 0),
        "status": s.get("status", "unknown"),
        "scanner_status": s.get("scanner_status", {}),
        "scanner_details": s.get("scanner_details", {}),
        "unified_mode": s.get("unified_mode", False),
        "target_url": s.get("target_url"),
        "kali_mode": s.get("kali_mode", False),
        "total_findings": s.get("total_findings", 0),
        "error_message": s.get("error_message")
    }

@router.get("/{scan_id}/results", response_model=ScanResultResponse)
async def get_scan_results(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    results = s.get("results", [])
    return {
        "scan_id": scan_id,
        "status": s.get("status", "unknown"),
        "results": results,
        "issues_found": len(results)
    }

@router.get("/{scan_id}/compare/{previous_id}")
async def compare_scans(scan_id: str, previous_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_cur = ObjectId(scan_id)
        obj_prev = ObjectId(previous_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID(s)")
        
    current_scan = await db.scans.find_one({"_id": obj_cur, "owner_id": str(current_user["_id"])})
    prev_scan = await db.scans.find_one({"_id": obj_prev, "owner_id": str(current_user["_id"])})
    
    if not current_scan or not prev_scan:
        raise HTTPException(status_code=404, detail="One or more scans not found")
        
    cur_vulns = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(length=1000)
    prev_vulns = await db.vulnerabilities.find({"scan_id": previous_id}).to_list(length=1000)
    
    def make_key(v):
        return f"{v.get('title')}-{v.get('target_url')}"
        
    cur_map = {make_key(v): v for v in cur_vulns}
    prev_map = {make_key(v): v for v in prev_vulns}
    
    new_issues = [cur_map[k] for k in cur_map if k not in prev_map]
    resolved_issues = [prev_map[k] for k in prev_map if k not in cur_map]
    
    severity_shifts = []
    unchanged_issues = []
    
    for k in cur_map:
        if k in prev_map:
            cur_sev = cur_map[k].get("severity", "info")
            prev_sev = prev_map[k].get("severity", "info")
            if cur_sev != prev_sev:
                severity_shifts.append({
                    "title": cur_map[k].get("title"),
                    "target_url": cur_map[k].get("target_url"),
                    "old_severity": prev_sev,
                    "new_severity": cur_sev
                })
            else:
                unchanged_issues.append(cur_map[k])
                
    for item_list in [new_issues, resolved_issues, unchanged_issues]:
        for i in item_list:
            i["_id"] = str(i["_id"])
            
    return {
        "scan_id": scan_id,
        "previous_id": previous_id,
        "current_score": current_scan.get("risk_score", {}).get("score", 100),
        "previous_score": prev_scan.get("risk_score", {}).get("score", 100),
        "comparison": {
            "new": len(new_issues),
            "resolved": len(resolved_issues),
            "unchanged": len(unchanged_issues),
            "severity_shifts_count": len(severity_shifts)
        },
        "new_issues": new_issues,
        "resolved_issues": resolved_issues,
        "unchanged_issues": unchanged_issues,
        "severity_shifts": severity_shifts
    }

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if s["status"] in ["completed", "failed"]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in {s['status']} state")
        
    await db.scans.update_one(
        {"_id": obj_id},
        {"$set": {"status": "cancelled", "ended_at": datetime.now(timezone.utc)}}
    )
    
    await log_audit_action(current_user["_id"], "Scan Cancelled", {"scan_id": scan_id})
    
    return {"message": "Scan cancelled"}

@router.get("/{scan_id}/terminal")
async def get_scan_terminal(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    lines = get_terminal_output(scan_id)
    return {
        "scan_id": scan_id,
        "status": s.get("status"),
        "progress": s.get("progress", 0),
        "scanner_status": s.get("scanner_status", {}),
        "lines": lines
    }

@router.get("/{scan_id}/scanner-status")
async def get_scanner_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return {
        "scan_id": scan_id,
        "status": s.get("status"),
        "progress": s.get("progress", 0),
        "scanner_status": s.get("scanner_status", {}),
        "evidence_files": s.get("evidence_files", {}),
    }

@router.get("/{scan_id}/evidence")
async def get_scan_evidence(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    evidence_files = s.get("evidence_files", {})
    evidence_data = {}
    for tool_name, file_path in evidence_files.items():
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    evidence_data[tool_name] = f.read()
            except Exception as e:
                evidence_data[tool_name] = f"Error reading file: {str(e)}"
        else:
            evidence_data[tool_name] = "Evidence file not found."
            
    return {
        "scan_id": scan_id,
        "evidence": evidence_data
    }

@router.get("/{scan_id}/report-html")
async def get_scan_html_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    s = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    html_path = s.get("report_html_path")
    if html_path and os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return HTMLResponse(content=content)
    raise HTTPException(status_code=404, detail="HTML report not yet generated or available.")
