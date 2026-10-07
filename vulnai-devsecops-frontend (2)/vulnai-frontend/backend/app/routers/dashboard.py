from datetime import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from app.database import get_database
from app.dependencies import get_current_user

router = APIRouter()


async def _compile_dashboard_payload(owner_id: str, db) -> Dict[str, Any]:
    # 1. Fetch latest scan for target, score, and timing
    latest_scan = await db.scans.find_one(
        {"owner_id": owner_id},
        sort=[("started_at", -1)]
    )

    # 2. Total completed scans
    scans_completed = await db.scans.count_documents({
        "owner_id": owner_id,
        "status": {"$in": ["completed", "completed_with_failures"]}
    })
    total_scans = await db.scans.count_documents({"owner_id": owner_id})

    # 3. Active incidents
    active_incidents = 0
    if hasattr(db, "incidents"):
        try:
            active_incidents = await db.incidents.count_documents({
                "owner_id": owner_id,
                "status": "active"
            })
        except Exception:
            pass

    # 4. Fetch all user vulnerabilities / findings
    vulns = await db.vulnerabilities.find({"owner_id": owner_id}).to_list(length=1000)

    # If vulns empty in DB, try getting from latest scan's combined_results
    if not vulns and latest_scan and latest_scan.get("combined_results"):
        comb = latest_scan["combined_results"]
        vulns = comb.get("correlated_findings") or [
            *comb.get("confirmed", []),
            *comb.get("potential", []),
            *comb.get("informational", []),
        ]

    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    info_count = 0
    conf_sum = 0
    conf_samples = 0

    for v in vulns:
        sev = str(v.get("severity", "info")).lower()
        if sev == "critical":
            crit_count += 1
        elif sev == "high":
            high_count += 1
        elif sev == "medium":
            med_count += 1
        elif sev == "low":
            low_count += 1
        else:
            info_count += 1

        c_val = v.get("confidence")
        if isinstance(c_val, (int, float)):
            num = c_val if c_val > 1 else c_val * 100
            conf_sum += num
            conf_samples += 1
        elif isinstance(c_val, str):
            c_map = {"CONFIRMED": 95, "HIGH": 85, "POTENTIAL": 75, "MEDIUM": 70, "LOW": 50, "INFORMATIONAL": 20}
            conf_sum += c_map.get(c_val.upper(), 75)
            conf_samples += 1

    avg_confidence = round(conf_sum / conf_samples) if conf_samples > 0 else 85
    confirmed_count = 0
    potential_count = 0
    info_count = 0
    for v in vulns:
        v_stat = str(v.get("verification_status") or v.get("status") or "potential").lower()
        sev = str(v.get("severity", "info")).lower()
        if v_stat == "confirmed":
            confirmed_count += 1
        elif v_stat in ("informational", "info") or sev == "info":
            info_count += 1
        else:
            potential_count += 1

    incomplete_count = 0
    if latest_scan and latest_scan.get("combined_results"):
        comb = latest_scan["combined_results"]
        incomplete_count = len(comb.get("incomplete", []))

    total_all_findings = len(vulns)
    total_actionable_findings = crit_count + high_count + med_count + low_count

    # Extract score & risk level from latest scan
    security_score = 100
    risk_level = "LOW"
    target_url = "None"
    last_scan_time = None

    if latest_scan:
        target_url = latest_scan.get("target_url") or (latest_scan.get("target_urls", ["None"])[0] if latest_scan.get("target_urls") else "None")
        risk_score_obj = latest_scan.get("risk_score") or (latest_scan.get("combined_results", {}).get("risk_score") if isinstance(latest_scan.get("combined_results"), dict) else {})
        if isinstance(risk_score_obj, dict):
            if risk_score_obj.get("score") is not None:
                security_score = risk_score_obj.get("score")
            risk_level = str(risk_score_obj.get("risk_level") or risk_score_obj.get("rating") or "LOW").upper()
        elif latest_scan.get("security_score") is not None:
            security_score = latest_scan.get("security_score")

        dt = latest_scan.get("completed_at") or latest_scan.get("ended_at") or latest_scan.get("started_at")
        last_scan_time = dt.isoformat() if hasattr(dt, "isoformat") else str(dt) if dt else None

    sev_distribution = {
        "critical": crit_count,
        "high": high_count,
        "medium": med_count,
        "low": low_count,
        "info": info_count,
    }

    return {
        "total_findings": total_all_findings,
        "confirmed_vulnerabilities": confirmed_count,
        "potential_vulnerabilities": potential_count,
        "informational_observations": info_count,
        "incomplete_checks": incomplete_count,
        "critical_issues": crit_count,
        "high_issues": high_count,
        "medium_issues": med_count,
        "low_issues": low_count,
        "informational": info_count,
        "scans_completed": scans_completed,
        "average_confidence": avg_confidence,
        "security_score": security_score,
        "risk_level": risk_level,
        "target": target_url,
        "last_scan_time": last_scan_time,
        "severity_distribution": sev_distribution,
        # Legacy frontend compatibility
        "unresolved_findings": total_actionable_findings,
        "active_incidents": active_incidents,
        "total_scans": total_scans,
    }


@router.get("/")
async def get_dashboard(current_user: dict = Depends(get_current_user)):
    """Primary dashboard telemetry endpoint specified in Section 14 & 18."""
    db = get_database()
    owner_id = str(current_user["_id"])
    return await _compile_dashboard_payload(owner_id, db)


@router.get("/metrics")
async def get_dashboard_metrics(current_user: dict = Depends(get_current_user)):
    """Metrics endpoint consumed by Dashboard component."""
    db = get_database()
    owner_id = str(current_user["_id"])
    return await _compile_dashboard_payload(owner_id, db)
