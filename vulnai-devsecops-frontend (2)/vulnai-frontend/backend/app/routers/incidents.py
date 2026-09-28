from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from bson import ObjectId

from app.database import get_database
from app.dependencies import get_current_user

router = APIRouter()

@router.get("/")
async def get_incidents(current_user: dict = Depends(get_current_user)):
    db = get_database()
    owner_id = str(current_user["_id"])
    
    incidents = await db.incidents.find({"owner_id": owner_id}).sort("created_at", -1).to_list(length=50)
    
    formatted = []
    for inc in incidents:
        inc["id"] = str(inc["_id"])
        inc.pop("_id", None)
        formatted.append(inc)
        
    return formatted

@router.post("/{incident_id}/status")
async def update_incident_status(incident_id: str, status_payload: Dict[str, str], current_user: dict = Depends(get_current_user)):
    db = get_database()
    owner_id = str(current_user["_id"])
    
    try:
        obj_id = ObjectId(incident_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid incident ID")
        
    new_status = status_payload.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="Status required")
        
    result = await db.incidents.update_one(
        {"_id": obj_id, "owner_id": owner_id},
        {"$set": {"status": new_status.upper()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found or no change made")
        
    return {"message": "Status updated successfully"}
