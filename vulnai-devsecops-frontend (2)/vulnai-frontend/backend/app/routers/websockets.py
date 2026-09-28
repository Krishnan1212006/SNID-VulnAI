from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict
from asyncio import sleep
from app.database import get_database
from bson import ObjectId

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        if client_id not in self.active_connections:
            self.active_connections[client_id] = []
        self.active_connections[client_id].append(websocket)

    def disconnect(self, websocket: WebSocket, client_id: str):
        if client_id in self.active_connections:
            self.active_connections[client_id].remove(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: dict, client_id: str):
        if client_id in self.active_connections:
            for connection in self.active_connections[client_id]:
                await connection.send_json(message)

manager = ConnectionManager()

@router.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, f"scan_{scan_id}")
    db = get_database()
    try:
        while True:
            # Poll database for current progress (In a real app, use Redis pub/sub)
            scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
            if scan:
                await websocket.send_json({
                    "status": scan.get("status", "unknown"),
                    "progress": scan.get("progress", 0),
                    "results_count": len(scan.get("results", [])),
                    "scanner_status": scan.get("scanner_status", {}),
                    "kali_mode": scan.get("kali_mode", False),
                    "total_findings": scan.get("total_findings", 0)
                })
                if scan.get("status") in ["completed", "failed", "cancelled"]:
                    break
            await sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket, f"scan_{scan_id}")
    except Exception as e:
        manager.disconnect(websocket, f"scan_{scan_id}")

@router.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    await manager.connect(websocket, "dashboard_global")
    try:
        while True:
            # Example global ping, push total counts etc.
            await websocket.send_json({"type": "ping", "message": "alive"})
            await sleep(5)
    except WebSocketDisconnect:
        manager.disconnect(websocket, "dashboard_global")

@router.websocket("/ws/events")
async def events_websocket(websocket: WebSocket):
    await manager.connect(websocket, "events_global")
    db = get_database()
    try:
        last_count = await db.events.count_documents({})
        while True:
            current_count = await db.events.count_documents({})
            if current_count > last_count:
                # Fetch new events
                new_events = await db.events.find().sort("timestamp", -1).limit(current_count - last_count).to_list(None)
                for e in new_events:
                    e["_id"] = str(e["_id"])
                    await websocket.send_json({"type": "new_event", "data": e})
                last_count = current_count
            await sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket, "events_global")
    except Exception as e:
        manager.disconnect(websocket, "events_global")
