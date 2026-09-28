from fastapi import APIRouter, Depends
from app.database import get_database
from app.dependencies import get_current_user

router = APIRouter()

@router.get("/metrics")
async def get_dashboard_metrics(current_user: dict = Depends(get_current_user)):
    db = get_database()
    owner_id = str(current_user["_id"])
    
    # Unresolved findings
    unresolved_count = await db.vulnerabilities.count_documents({
        "owner_id": owner_id, 
        "status": {"$in": ["open", "in_progress"]}
    })
    
    # Active incidents
    active_incidents = await db.incidents.count_documents({
        "owner_id": owner_id,
        "status": "active"
    })
    
    total_scans = await db.scans.count_documents({"owner_id": owner_id})
    
    # Severity distribution from unresolved findings
    pipeline = [
        {"$match": {"owner_id": owner_id, "status": {"$in": ["open", "in_progress"]}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    severity_cursor = await db.vulnerabilities.aggregate(pipeline)
    sev_dist = await severity_cursor.to_list(length=10)
    severity_distribution = {doc["_id"]: doc["count"] for doc in sev_dist}
    
    return {
        "unresolved_findings": unresolved_count,
        "active_incidents": active_incidents,
        "total_scans": total_scans,
        "severity_distribution": severity_distribution
    }
