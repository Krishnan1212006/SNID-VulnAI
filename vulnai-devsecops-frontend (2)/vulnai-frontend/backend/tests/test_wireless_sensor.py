import pytest
from app.core.ids import ObjectId
from fastapi.testclient import TestClient
from app.main import app
from app.dependencies import get_current_user

client = TestClient(app)


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "test-user-rf"})
    return client


def test_unauthenticated_sensor_submission_rejected():
    """Verify that submitting wireless events without sensor key or user auth is rejected with 401."""
    res = client.post("/api/snid/wireless-events", json={
        "sensor_id": "esp32-node-99",
        "event_type": "deauth_burst",
        "frame_count": 25,
    })
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


@pytest.mark.asyncio
async def test_wireless_event_deduplication_and_rogue_detection():
    """Verify event deduplication and rogue AP comparison heuristics."""
    from app.services.wireless_monitor import WirelessMonitorEngine

    class MockCollection:
        def __init__(self):
            self.docs = []

        async def find_one(self, query):
            for doc in self.docs:
                match = True
                for k, v in query.items():
                    if doc.get(k) != v:
                        match = False
                        break
                if match:
                    return doc
            return None

        async def insert_one(self, doc):
            doc["_id"] = ObjectId()
            self.docs.append(doc)
            class Res:
                inserted_id = doc["_id"]
            return Res()

        async def update_one(self, query, update, upsert=False):
            doc = await self.find_one(query)
            if doc:
                if "$set" in update:
                    doc.update(update["$set"])
                if "$inc" in update:
                    for k, v in update["$inc"].items():
                        doc[k] = doc.get(k, 0) + v
            elif upsert:
                new_doc = query.copy()
                if "$set" in update:
                    new_doc.update(update["$set"])
                new_doc["_id"] = ObjectId()
                self.docs.append(new_doc)

    class MockDB:
        def __init__(self):
            self.wireless_events = MockCollection()
            self.wireless_sensors = MockCollection()
            self.authorized_access_points = MockCollection()
            self.incidents = MockCollection()

    db = MockDB()
    owner_id = "test-user-wireless"

    # Register authorized corporate AP: SSID 'Corp-Secure', BSSID '00:11:22:33:44:55'
    await db.authorized_access_points.insert_one({
        "owner_id": owner_id,
        "ssid": "Corp-Secure",
        "bssid": "00:11:22:33:44:55",
        "security_type": "WPA2",
    })

    engine = WirelessMonitorEngine(db, owner_id)

    # 1. Normal beacon matching authorized AP
    normal_res = await engine.ingest_wireless_event({
        "sensor_id": "esp32-01",
        "event_type": "beacon_observation",
        "bssid": "00:11:22:33:44:55",
        "ssid": "Corp-Secure",
        "channel": 6,
        "security": "WPA2",
    })
    assert normal_res["severity"] == "low"
    assert normal_res["verification_status"] == "observed"

    # 2. Rogue AP / Evil Twin: Same SSID 'Corp-Secure' but rogue BSSID '24:0A:C4:AA:BB:CC' and OPEN security!
    rogue_res = await engine.ingest_wireless_event({
        "sensor_id": "esp32-01",
        "event_type": "beacon_observation",
        "bssid": "24:0A:C4:AA:BB:CC",
        "ssid": "Corp-Secure",
        "channel": 11,
        "security": "OPEN",
    })
    assert rogue_res["severity"] == "high"
    assert rogue_res["verification_status"] == "corroborated"

    # 3. High frequency deauth burst
    deauth_res = await engine.ingest_wireless_event({
        "sensor_id": "esp32-01",
        "event_type": "deauth_burst",
        "bssid": "00:11:22:33:44:55",
        "ssid": "Corp-Secure",
        "frame_count": 30,
        "window_seconds": 5,
    })
    assert deauth_res["severity"] == "high"
    assert deauth_res["verification_status"] == "potential_threat"

    # 4. Deduplication: Send identical deauth burst immediately
    dedup_res = await engine.ingest_wireless_event({
        "sensor_id": "esp32-01",
        "event_type": "deauth_burst",
        "bssid": "00:11:22:33:44:55",
        "ssid": "Corp-Secure",
        "frame_count": 10,
        "window_seconds": 5,
    })
    assert dedup_res["status"] == "deduplicated"
