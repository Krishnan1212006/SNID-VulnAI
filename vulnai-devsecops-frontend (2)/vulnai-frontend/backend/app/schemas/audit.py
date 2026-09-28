from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict
from typing import Optional, Any, Dict

class AuditLogCreate(BaseModel):
    action: str
    details: Optional[Dict[str, Any]] = None

class AuditLogResponse(BaseModel):
    id: str
    user_id: str
    action: str
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None
    
    model_config = ConfigDict(extra='ignore')
