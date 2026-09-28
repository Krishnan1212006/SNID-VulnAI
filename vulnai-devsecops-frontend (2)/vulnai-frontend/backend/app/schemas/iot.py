from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime

class DeviceBase(BaseModel):
    name: str
    ip_address: str
    mac_address: Optional[str] = None
    device_type: str = "Unknown Device"
    status: str = "active"
    
class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    device_type: Optional[str] = None

class SecurityEvent(BaseModel):
    source: str
    event_type: str
    source_ip: str
    destination_ip: str
    severity: str
    message: str
    timestamp: datetime
    raw_event: Dict[str, Any] = Field(default_factory=dict)
