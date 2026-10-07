"""
Findings Router.

Provides standardized access to normalized security findings across all scans
with evidence-first validation, filtering, and search capabilities.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from app.core.ids import ObjectId
from app.database import get_database
from app.dependencies import get_current_user
from urllib.parse import urlsplit

router = APIRouter()


def _normalize_finding_dict(doc: Dict[str, Any], scan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Ensure a finding document conforms to the normalized Finding data model."""
    f_id = str(doc.get("id") or doc.get("_id") or "VULNAI-001")
    scan_id = str(doc.get("scan_id") or (str(scan["_id"]) if scan and "_id" in scan else ""))
    tool = str(doc.get("tool") or doc.get("source") or (doc.get("detected_by", ["nikto"])[0] if doc.get("detected_by") else "nikto")).lower()
    
    # Severity
    sev = str(doc.get("severity", "LOW")).upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev = "LOW"

    # Confidence (0-100)
    conf_raw = doc.get("confidence", 85)
    if isinstance(conf_raw, str):
        try:
            confidence = int(float(conf_raw))
        except ValueError:
            c_map = {"CONFIRMED": 95, "HIGH": 85, "POTENTIAL": 75, "MEDIUM": 70, "LOW": 50, "INFORMATIONAL": 20}
            confidence = c_map.get(conf_raw.upper(), 75)
    elif isinstance(conf_raw, (int, float)):
        if 0 < conf_raw <= 1:
            confidence = int(conf_raw * 100)
        else:
            confidence = int(conf_raw)
    else:
        confidence = 75

    # Status: potential|confirmed|informational|incomplete
    v_stat = str(doc.get("verification_status") or doc.get("status") or "potential").lower()
    if v_stat in ("confirmed", "open") and doc.get("verification_status") == "CONFIRMED":
        status_val = "confirmed"
    elif v_stat in ("informational", "info") or sev == "INFO":
        status_val = "informational"
    elif v_stat in ("incomplete", "timeout"):
        status_val = "incomplete"
    else:
        status_val = "potential"

    # Evidence
    ev = doc.get("evidence", "")
    if isinstance(ev, dict):
        ev_str = ev.get("raw") or ev.get("nikto_finding") or ev.get("raw_line") or str(ev)
    else:
        ev_str = str(ev or "")

    target = str(doc.get("target") or doc.get("target_url") or (scan.get("target_url") if scan else "") or "")
    endpoint = str(doc.get("endpoint") or doc.get("path") or "/")
    desc = str(doc.get("description") or doc.get("title") or "")
    rec = str(doc.get("recommendation") or (doc.get("ai_analysis", {}).get("recommendation") if isinstance(doc.get("ai_analysis"), dict) else "") or "")

    detected_by = doc.get("detected_by")
    if not detected_by:
        detected_by = [tool.capitalize()]

    ts = doc.get("timestamp") or doc.get("first_seen")
    if not ts and doc.get("created_at"):
        c_at = doc.get("created_at")
        ts = c_at.isoformat() if hasattr(c_at, "isoformat") else str(c_at)

    cve = doc.get("cve") or doc.get("cve_id")
    if cve in ("Not mapped", "None", "", None):
        cve = None

    cwe = doc.get("cwe") or doc.get("cwe_id")
    if cwe in ("Not mapped", "None", "", None):
        cwe = None

    return {
        "id": f_id,
        "scan_id": scan_id,
        "tool": tool,
        "title": doc.get("title") or "Security Observation",
        "category": doc.get("category") or "Security Misconfiguration",
        "severity": sev,
        "confidence": confidence,
        "status": status_val,
        "target": target,
        "endpoint": endpoint,
        "evidence": ev_str,
        "description": desc,
        "recommendation": rec,
        "cve": cve,
        "cwe": cwe,
        "source": doc.get("source") or tool,
        "raw_reference": doc.get("raw_reference") or doc.get("output_file") or f"scan-results/{scan_id}/{tool}.txt",
        "timestamp": ts or "",
        # Extended fields for full frontend and report compatibility
        "detected_by": detected_by,
        "target_url": target,
        "verification_status": status_val.upper(),
        "ai_analysis": doc.get("ai_analysis") or {
            "problem": desc,
            "impact": doc.get("impact", ""),
            "recommendation": rec,
            "verification_steps": [
                f"Inspect endpoint {endpoint} on {target}.",
                f"Verify using {tool} evidence."
            ]
        }
    }


@router.get("/", response_model=List[Dict[str, Any]])
async def get_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    target: Optional[str] = None,
    category: Optional[str] = None,
    tool: Optional[str] = None,
    query: Optional[str] = Query(None, description="Search across title, target, endpoint, CVE, tool, category"),
    current_user: dict = Depends(get_current_user),
):
    """
    Returns normalized, evidence-first findings for the user.
    Supports filtering by severity, status, target, category, tool, and text search.
    """
    db = get_database()
    owner_id = str(current_user["_id"])

    # If scan_id is provided, verify scan ownership
    scan_doc = None
    if scan_id:
        try:
            obj_id = ObjectId(scan_id)
            scan_doc = await db.scans.find_one({"_id": obj_id, "owner_id": owner_id})
        except Exception:
            scan_doc = None
        if not scan_doc:
            raise HTTPException(status_code=404, detail="Scan not found")

    # Fetch findings from vulnerabilities collection
    db_query: Dict[str, Any] = {"owner_id": owner_id}
    if scan_id:
        db_query["scan_id"] = scan_id

    vulns = await db.vulnerabilities.find(db_query).sort("created_at", -1).to_list(length=500)

    # If vulns collection is empty for this scan, try compiling from scan's combined_results
    if not vulns and scan_doc and scan_doc.get("combined_results"):
        comb = scan_doc["combined_results"]
        vulns = comb.get("correlated_findings") or [
            *comb.get("confirmed", []),
            *comb.get("potential", []),
            *comb.get("informational", []),
        ]

    normalized_list = [_normalize_finding_dict(v, scan=scan_doc) for v in vulns]

    # In-memory filtering
    filtered = []
    for f in normalized_list:
        if severity and f["severity"].upper() != severity.upper():
            continue
        if status and f["status"].lower() != status.lower():
            continue
        if target and target.lower() not in f["target"].lower():
            continue
        if category and category.lower() not in f["category"].lower():
            continue
        if tool:
            tool_match = (
                f["tool"].lower() == tool.lower() or
                any(tool.lower() in str(d).lower() for d in f.get("detected_by", []))
            )
            if not tool_match:
                continue
        if query:
            q_lower = query.lower()
            haystack = (
                f"{f['title']} {f['description']} {f['target']} {f['endpoint']} "
                f"{f.get('cve') or ''} {f.get('cwe') or ''} {f['tool']} {f['category']} "
                f"{' '.join(f.get('detected_by', []))}"
            ).lower()
            if q_lower not in haystack:
                continue
        filtered.append(f)

    return filtered


@router.get("/{finding_id}")
async def get_finding_by_id(finding_id: str, current_user: dict = Depends(get_current_user)):
    """
    Retrieve an individual normalized finding by ID.
    """
    db = get_database()
    owner_id = str(current_user["_id"])

    # Try database _id or string ID
    doc = None
    try:
        doc = await db.vulnerabilities.find_one({"_id": ObjectId(finding_id), "owner_id": owner_id})
    except Exception:
        pass

    if not doc:
        doc = await db.vulnerabilities.find_one({"id": finding_id, "owner_id": owner_id})

    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")

    return _normalize_finding_dict(doc)
