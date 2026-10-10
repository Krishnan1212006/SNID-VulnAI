"""
SNID Wireless Monitoring & ESP32 Defensive Sensor Router.
Handles sensor event ingestion, sensor health heartbeats, and authorized access point baselines.
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.database import get_database
from app.dependencies import get_current_user, get_optional_current_user
from app.schemas.iot import WirelessEventIngest, AuthorizedAPCreate, SensorRegisterRequest
from app.services.wireless_monitor import WirelessMonitorEngine
from app.core.ids import ObjectId

router = APIRouter()


@router.post("/wireless-events")
async def ingest_wireless_event(
    event: WirelessEventIngest,
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Ingest a defensive wireless RF observation from an ESP32 sensor (ProjectHydra / SNID node).
    Requires sensor authentication via X-Sensor-Key header or valid user session.
    """
    db = get_database()
    owner_id = str(current_user["_id"]) if current_user else None

    # If sensor key provided, attempt sensor authentication
    sensor_key = x_sensor_key or event.sensor_key
    if not owner_id:
        if not sensor_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required: Provide X-Sensor-Key header or Bearer token.",
            )
        # Find sensor in database by sensor_id & api_key
        sensor = await db.wireless_sensors.find_one({
            "sensor_id": event.sensor_id,
            "api_key": sensor_key,
        })
        if not sensor:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid sensor credentials or unprovisioned sensor ID.",
            )
        owner_id = sensor["owner_id"]

    engine = WirelessMonitorEngine(db, owner_id)
    result = await engine.ingest_wireless_event(event.model_dump())
    return result


@router.get("/wireless-events")
async def get_wireless_events(
    event_type: Optional[str] = Query(None, description="Filter by deauth_burst, beacon_observation, duplicate_ssid"),
    severity: Optional[str] = Query(None, description="Filter by low, medium, high"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by observed, potential_threat, corroborated"),
    limit: int = Query(100, le=500),
    current_user: dict = Depends(get_current_user),
):
    """Retrieve wireless security observations and rogue AP alerts."""
    db = get_database()
    owner_id = str(current_user["_id"])
    query = {"owner_id": owner_id}

    if event_type:
        query["event_type"] = event_type
    if severity:
        query["severity"] = severity
    if status_filter:
        query["verification_status"] = status_filter

    events = await db.wireless_events.find(query).sort("timestamp", -1).to_list(limit)
    for e in events:
        e["id"] = str(e["_id"])
        e.pop("_id", None)
    return events


@router.get("/sensors")
async def get_sensors(current_user: dict = Depends(get_current_user)):
    """List registered ESP32 defensive sensors and their connection health."""
    db = get_database()
    owner_id = str(current_user["_id"])
    sensors = await db.wireless_sensors.find({"owner_id": owner_id}).to_list(100)
    for s in sensors:
        s["id"] = str(s["_id"])
        s.pop("_id", None)
        # Don't expose secret key in list API
        s.pop("api_key", None)
    return sensors


@router.post("/sensors/register")
async def register_sensor(
    payload: SensorRegisterRequest,
    current_user: dict = Depends(get_current_user),
):
    """Register or provision an ESP32 defensive sensor node."""
    db = get_database()
    owner_id = str(current_user["_id"])

    sensor_doc = {
        "sensor_id": payload.sensor_id,
        "name": payload.name,
        "api_key": payload.api_key,
        "firmware_version": payload.firmware_version,
        "owner_id": owner_id,
        "status": "registered",
        "registered_at": datetime.now(timezone.utc),
        "last_seen": None,
    }

    await db.wireless_sensors.update_one(
        {"sensor_id": payload.sensor_id, "owner_id": owner_id},
        {"$set": sensor_doc},
        upsert=True,
    )
    return {"message": "Sensor registered successfully", "sensor_id": payload.sensor_id}


@router.get("/access-points")
async def get_authorized_access_points(current_user: dict = Depends(get_current_user)):
    """Retrieve list of authorized corporate/lab access points used for Rogue AP detection."""
    db = get_database()
    owner_id = str(current_user["_id"])
    aps = await db.authorized_access_points.find({"owner_id": owner_id}).to_list(100)
    for ap in aps:
        ap["id"] = str(ap["_id"])
        ap.pop("_id", None)
    return aps


@router.post("/access-points")
async def create_authorized_access_point(
    ap: AuthorizedAPCreate,
    current_user: dict = Depends(get_current_user),
):
    """Register an authorized access point in the baseline inventory."""
    db = get_database()
    owner_id = str(current_user["_id"])
    from app.services.mac_vendor import normalize_mac

    bssid_norm = normalize_mac(ap.bssid)
    if not bssid_norm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid BSSID MAC address format.",
        )

    doc = {
        "ssid": ap.ssid.strip(),
        "bssid": bssid_norm,
        "channel": ap.channel,
        "security_type": ap.security_type,
        "notes": ap.notes,
        "owner_id": owner_id,
        "created_at": datetime.now(timezone.utc),
    }

    res = await db.authorized_access_points.insert_one(doc)
    doc["id"] = str(res.inserted_id)
    doc.pop("_id", None)
    return doc


@router.delete("/access-points/{ap_id}")
async def delete_authorized_access_point(
    ap_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Remove an access point from the authorized baseline inventory."""
    db = get_database()
    owner_id = str(current_user["_id"])

    res = await db.authorized_access_points.delete_one({"_id": ObjectId(ap_id), "owner_id": owner_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized AP not found")
    return {"message": "Authorized AP removed"}
