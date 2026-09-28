from fastapi import APIRouter, Depends
from typing import List, Optional, Any, Dict
from datetime import datetime, timezone

from app.database import get_database
from app.dependencies import get_current_user
from app.schemas.audit import AuditLogResponse

router = APIRouter()

async def log_audit_action(user_id: str, action: str, details: Optional[Dict[str, Any]] = None):
    db = get_database()
    log_entry = {
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.now(timezone.utc),
        "details": details or {}
    }
    await db.audit_logs.insert_one(log_entry)

@router.get("/", response_model=List[AuditLogResponse])
async def get_audit_logs(
    limit: int = 100,
    skip: int = 0,
    current_user: dict = Depends(get_current_user)
):
    db = get_database()
    # It might be beneficial to allow admin users to see all logs, but for now we filter by owner.
    logs = await db.audit_logs.find({"user_id": str(current_user["_id"])}).sort("timestamp", -1).skip(skip).limit(limit).to_list(length=limit)
    
    formatted_logs = []
    for log in logs:
        log["id"] = str(log["_id"])
        formatted_logs.append(log)
        
    return formatted_logs
