from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import List, Optional
from bson import ObjectId
from app.database import get_database
from app.dependencies import get_current_user
from app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityUpdate

router = APIRouter()


@router.get("/unified-observations")
async def get_latest_unified_observations(current_user: dict = Depends(get_current_user)):
    """Return normalized observations from the owner's latest unified assessment."""
    db = get_database()
    scan = await db.scans.find_one(
        {"owner_id": str(current_user["_id"]), "unified_mode": True, "combined_results": {"$exists": True}},
        sort=[("ended_at", -1)],
    )
    if not scan:
        return {"scan_id": None, "target": None, "status": "not_available",
                "confirmed": [], "potential": [], "informational": [], "incomplete": []}

    results = scan.get("combined_results", {})
    return {
        "scan_id": str(scan["_id"]),
        "target": results.get("target", scan.get("target_url")),
        "status": results.get("status", scan.get("status")),
        "confirmed": results.get("confirmed", []),
        "potential": results.get("potential", []),
        "informational": results.get("informational", []),
        "incomplete": results.get("incomplete", []),
    }


@router.get("/", response_model=List[VulnerabilityResponse])
async def get_vulnerabilities(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    db = get_database()
    query = {"owner_id": str(current_user["_id"])}
    
    if status_param := status:
        query["status"] = status_param
    if severity_param := severity:
        query["severity"] = severity_param
    if category_param := category:
        query["category"] = category_param
        
    vulns = await db.vulnerabilities.find(query).sort("created_at", -1).to_list(length=200)
    
    formatted = []
    for v in vulns:
        v["id"] = str(v["_id"])
        formatted.append(v)
        
    return formatted

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(vuln_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID")
        
    vuln = await db.vulnerabilities.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    vuln["id"] = str(vuln["_id"])
    return vuln

@router.patch("/{vuln_id}/status", response_model=VulnerabilityResponse)
async def update_vulnerability_status(
    vuln_id: str, 
    update_data: VulnerabilityUpdate, 
    current_user: dict = Depends(get_current_user)
):
    db = get_database()
    try:
        obj_id = ObjectId(vuln_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID")
        
    if not update_data.status:
        raise HTTPException(status_code=400, detail="Status must be provided")
        
    result = await db.vulnerabilities.update_one(
        {"_id": obj_id, "owner_id": str(current_user["_id"])},
        {"$set": {"status": update_data.status}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    vuln = await db.vulnerabilities.find_one({"_id": obj_id})
    vuln["id"] = str(vuln["_id"])
    return vuln
