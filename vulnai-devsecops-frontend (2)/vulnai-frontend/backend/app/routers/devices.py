from fastapi import APIRouter, Depends, HTTPException
from app.database import get_database
from app.dependencies import get_current_user
from app.schemas.iot import DeviceCreate, DeviceUpdate
from bson import ObjectId
from datetime import datetime, timezone

router = APIRouter()

@router.get("/")
async def get_devices(current_user: dict = Depends(get_current_user)):
    db = get_database()
    devices = await db.devices.find({"owner_id": str(current_user["_id"])}).to_list(100)
    for d in devices:
        d["id"] = str(d["_id"])
    return devices

@router.post("/")
async def create_device(device: DeviceCreate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    dev_dict = device.model_dump() if hasattr(device, 'model_dump') else device.dict()
    dev_dict["owner_id"] = str(current_user["_id"])
    dev_dict["created_at"] = datetime.now(timezone.utc)
    dev_dict["last_seen"] = datetime.now(timezone.utc)
    
    res = await db.devices.insert_one(dev_dict)
    dev_dict["id"] = str(res.inserted_id)
    return dev_dict

@router.patch("/{device_id}")
async def update_device(device_id: str, updates: DeviceUpdate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    update_data = {k: v for k, v in (updates.model_dump() if hasattr(updates, 'model_dump') else updates.dict()).items() if v is not None}
    
    if not update_data:
        return {"message": "No updates"}
        
    res = await db.devices.update_one(
        {"_id": ObjectId(device_id), "owner_id": str(current_user["_id"])},
        {"$set": update_data}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Device not found")
        
    return {"message": "Device updated"}
