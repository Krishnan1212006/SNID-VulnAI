from fastapi import APIRouter, Depends, Query, BackgroundTasks, Request
from datetime import datetime, timezone
from typing import Dict, Any, List

from app.database import get_database
from app.dependencies import get_current_user
from app.services.correlation import correlate_incident

router = APIRouter()

@router.get("/")
async def get_events(limit: int = Query(100), current_user: dict = Depends(get_current_user)):
    db = get_database()
    owner_id = str(current_user["_id"])
    
    events = await db.events.find({"owner_id": owner_id}).sort("timestamp", -1).limit(limit).to_list(length=limit)
    
    formatted = []
    for e in events:
        e["id"] = str(e["_id"])
        e.pop("_id", None)
        formatted.append(e)
        
    return formatted

@router.post("/ingest")
async def ingest_event(payload: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    db = get_database()
    owner_id = str(current_user["_id"])
    
    if "timestamp" not in payload:
        payload["timestamp"] = datetime.now(timezone.utc)
        
    payload["owner_id"] = owner_id
    
    # Rely on payload defaults
    if "severity" not in payload:
        payload["severity"] = "Medium"
        
    result = await db.events.insert_one(payload)
    event_id = str(result.inserted_id)
    
    # 2. Correlate critical events into incidents
    await correlate_incident(payload, event_id, db, owner_id)
    
    return {"message": "Ingested", "event_id": event_id}
