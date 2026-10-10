"""
Device Inventory and Local Network Discovery Router.
Provides real device discovery, status tracking, search, and inventory management.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.database import get_database
from app.dependencies import get_current_user
from app.schemas.iot import DeviceCreate, DeviceUpdate, DiscoveryTriggerRequest
from app.core.ids import ObjectId
from app.services.device_discovery import DeviceDiscoveryEngine, is_subnet_authorized

router = APIRouter()


@router.get("/summary")
async def get_devices_summary(current_user: dict = Depends(get_current_user)):
    """Summary metric counts matching dashboard cards (online, known, unknown, high_risk)."""
    db = get_database()
    owner_id = str(current_user["_id"])
    devices = await db.devices.find({"owner_id": owner_id}).to_list(1000)

    # 15 minutes without observation = stale
    fifteen_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=15)

    online_count = 0
    stale_count = 0
    total_known = 0
    unknown_count = 0
    high_risk_count = 0

    for d in devices:
        last_seen = d.get("last_seen")
        is_online = d.get("status") == "online"
        if last_seen and isinstance(last_seen, datetime):
            if last_seen < fifteen_mins_ago and is_online:
                is_online = False
                stale_count += 1

        if is_online:
            online_count += 1

        classification = d.get("inventory_classification", "unknown").lower()
        if classification == "authorized":
            total_known += 1
        else:
            unknown_count += 1

        if d.get("risk") == "high":
            high_risk_count += 1

    return {
        "devices_online": online_count,
        "stale_devices": stale_count,
        "total_known_devices": total_known,
        "unknown_devices": unknown_count,
        "high_risk_devices": high_risk_count,
        "total_devices": len(devices),
        "timestamp": datetime.now(timezone.utc),
    }


@router.get("/")
async def get_devices(
    search: Optional[str] = Query(None, description="Search by name, IP, MAC, hostname, or manufacturer"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: online, stale, offline"),
    classification: Optional[str] = Query(None, description="Filter by classification: authorized, unknown, rogue_candidate"),
    risk: Optional[str] = Query(None, description="Filter by risk: low, medium, high"),
    limit: int = Query(200, le=500),
    current_user: dict = Depends(get_current_user),
):
    """List discovered network devices with search, filtering, and telemetry status."""
    db = get_database()
    owner_id = str(current_user["_id"])
    query = {"owner_id": owner_id}

    if status_filter:
        query["status"] = status_filter
    if classification:
        query["inventory_classification"] = classification
    if risk:
        query["risk"] = risk

    devices = await db.devices.find(query).sort("last_seen", -1).to_list(limit)
    formatted = []
    fifteen_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=15)

    for d in devices:
        d["id"] = str(d["_id"])
        d.pop("_id", None)

        # Evaluate stale status dynamically
        last_seen = d.get("last_seen")
        if last_seen and isinstance(last_seen, datetime) and last_seen < fifteen_mins_ago and d.get("status") == "online":
            d["status"] = "stale"

        # Apply in-memory text search if provided
        if search:
            q = search.lower().strip()
            text_pool = f"{d.get('name', '')} {d.get('ip_address', '')} {d.get('mac_address', '')} {d.get('hostname', '')} {d.get('manufacturer', '')}".lower()
            if q not in text_pool:
                continue

        formatted.append(d)

    return formatted


@router.post("/discovery")
async def initiate_discovery(
    request: DiscoveryTriggerRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Initiate real network device discovery job for an explicitly authorized local subnet.
    Strictly verifies authorization to prevent unpermitted active network scanning.
    """
    db = get_database()
    owner_id = str(current_user["_id"])

    if request.authorized_subnet and not is_subnet_authorized(request.authorized_subnet):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Subnet '{request.authorized_subnet}' is not authorized. Authorized subnets: RFC 1918 private ranges (192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12).",
        )

    engine = DeviceDiscoveryEngine(db, owner_id)
    try:
        summary = await engine.run_discovery_job(
            authorized_subnet=request.authorized_subnet,
            active_sweep=request.active_sweep,
        )
        return summary
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Discovery failed: {exc}")


@router.get("/discovery/{job_id}")
async def get_discovery_job(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve audit record and result of a specific discovery job."""
    db = get_database()
    owner_id = str(current_user["_id"])

    job = await db.discovery_jobs.find_one({"_id": ObjectId(job_id), "owner_id": owner_id})
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery job not found")
    job["id"] = str(job["_id"])
    job.pop("_id", None)
    return job


@router.get("/{device_id}")
async def get_device(
    device_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve full device details and observation history."""
    db = get_database()
    owner_id = str(current_user["_id"])

    device = await db.devices.find_one({"_id": ObjectId(device_id), "owner_id": owner_id})
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    device["id"] = str(device["_id"])
    device.pop("_id", None)
    return device


@router.post("/")
async def create_device(
    device: DeviceCreate,
    current_user: dict = Depends(get_current_user),
):
    """Manually register a device into network inventory."""
    db = get_database()
    owner_id = str(current_user["_id"])
    dev_dict = device.model_dump() if hasattr(device, "model_dump") else device.dict()
    dev_dict["owner_id"] = owner_id
    dev_dict["first_seen"] = datetime.now(timezone.utc)
    dev_dict["last_seen"] = datetime.now(timezone.utc)

    res = await db.devices.insert_one(dev_dict)
    dev_dict["id"] = str(res.inserted_id)
    return dev_dict


@router.patch("/{device_id}")
async def update_device(
    device_id: str,
    updates: DeviceUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Update device metadata, authorization status, or classification."""
    db = get_database()
    owner_id = str(current_user["_id"])
    update_data = {
        k: v for k, v in (updates.model_dump() if hasattr(updates, "model_dump") else updates.dict()).items() if v is not None
    }

    if not update_data:
        return {"message": "No updates provided"}

    res = await db.devices.update_one(
        {"_id": ObjectId(device_id), "owner_id": owner_id},
        {"$set": update_data},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    return {"message": "Device inventory updated successfully"}


@router.delete("/{device_id}")
async def delete_device(
    device_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Remove a device record from inventory."""
    db = get_database()
    owner_id = str(current_user["_id"])

    res = await db.devices.delete_one({"_id": ObjectId(device_id), "owner_id": owner_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    return {"message": "Device removed from inventory"}
