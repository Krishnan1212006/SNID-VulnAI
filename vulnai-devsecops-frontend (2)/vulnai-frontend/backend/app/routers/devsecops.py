from fastapi import APIRouter, HTTPException, BackgroundTasks, status, Query
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.core.ids import ObjectId

from app.database import get_database
from app.services.scanner import run_safe_scan
from app.routers.audit import log_audit_action

router = APIRouter()

class WebhookPayload(BaseModel):
    ref: Optional[str] = None
    repository: Optional[Dict[str, Any]] = None
    commits: Optional[list] = None

@router.post("/webhook")
async def devsecops_webhook(
    payload: WebhookPayload,
    asset_id: str = Query(..., description="The Asset ID to scan"),
    api_key: str = Query(None, description="Optional API key for CI/CD")
):
    db = get_database()
    try:
        obj_id = ObjectId(asset_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid asset ID")

    asset = await db.assets.find_one({"_id": obj_id})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    new_scan = {
        "asset_id": asset_id,
        "owner_id": asset.get("owner_id"),
        "status": "queued",
        "progress": 0,
        "started_at": datetime.now(timezone.utc),
        "ended_at": None,
        "results": []
    }
    
    result = await db.scans.insert_one(new_scan)
    scan_id = str(result.inserted_id)
    new_scan["id"] = scan_id
    
    # Normally we'd use Dependency Injection for BackgroundTasks, 
    # but since this is a simple demo we can trigger it directly if needed,
    # or actually we need BackgroundTasks. Let's add it to the function parameters.
    pass

@router.post("/webhook/trigger")
async def trigger_webhook(
    background_tasks: BackgroundTasks,
    payload: dict,
    asset_id: str = Query(...)
):
    db = get_database()
    try:
        obj_id = ObjectId(asset_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid asset ID")

    asset = await db.assets.find_one({"_id": obj_id})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    new_scan = {
        "asset_id": asset_id,
        "owner_id": asset.get("owner_id"),
        "status": "queued",
        "progress": 0,
        "started_at": datetime.now(timezone.utc),
        "ended_at": None,
        "results": [],
        "trigger": "webhook"
    }
    
    result = await db.scans.insert_one(new_scan)
    scan_id = str(result.inserted_id)
    
    background_tasks.add_task(run_safe_scan, scan_id, db)
    await log_audit_action(asset.get("owner_id"), "CI/CD Webhook Triggered Scan", {"scan_id": scan_id, "asset_id": asset_id})
    
    return {"message": "Scan triggered by webhook", "scan_id": scan_id}

@router.get("/gate/{asset_id}")
async def check_security_gate(asset_id: str):
    db = get_database()
    try:
        obj_id = ObjectId(asset_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid asset ID")
        
    latest_scan = await db.scans.find_one(
        {"asset_id": asset_id, "status": "completed"}, 
        sort=[("started_at", -1)]
    )
    
    if not latest_scan:
        return {"passed": True, "reason": "No completed scans found", "code": 200}
        
    severity = latest_scan.get("severity_summary", {})
    criticals = severity.get("critical", 0)
    highs = severity.get("high", 0)
    
    if criticals > 0:
        return {"passed": False, "reason": f"Gate Failed: Found {criticals} critical vulnerabilities in latest scan ({latest_scan.get('_id')}).", "code": 406}
        
    if highs > 0:
        return {"passed": False, "reason": f"Gate Warning: Found {highs} high vulnerabilities, but no criticals. Proceed with caution.", "code": 200}
        
    return {"passed": True, "reason": "Gate Passed: No critical vulnerabilities found.", "code": 200}

@router.post("/pipeline-runs")
async def create_pipeline_run(payload: Dict[str, Any]):
    db = get_database()
    payload["created_at"] = datetime.now(timezone.utc)
    result = await db.pipeline_runs.insert_one(payload)
    return {"message": "Pipeline run recorded", "id": str(result.inserted_id)}

@router.get("/pipeline-runs")
async def get_pipeline_runs():
    db = get_database()
    runs = await db.pipeline_runs.find().sort("created_at", -1).limit(50).to_list(None)
    for r in runs:
        r["id"] = str(r["_id"])
        del r["_id"]
    return runs

@router.get("/pipeline-runs/latest")
async def get_latest_pipeline_run():
    db = get_database()
    run = await db.pipeline_runs.find_one({}, sort=[("created_at", -1)])
    if not run:
        raise HTTPException(status_code=404, detail="No pipelines found")
    run["id"] = str(run["_id"])
    del run["_id"]
    return run
