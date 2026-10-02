import asyncio
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import os
import random
import sys
from app.database import connect_to_postgres, close_postgres_connection, get_database

# Ensure backend module is available
sys.path.append(os.path.dirname(__file__))
from app.services.correlation import correlate_incident

load_dotenv()
DB = None

async def seed():
    global DB
    await connect_to_postgres()
    DB = get_database()
    try:
        await seed_data()
    finally:
        await close_postgres_connection()

async def seed_data():
    # Grab the first user
    user = await DB.users.find_one({})
    if not user:
        print("No user found. Please register an account first.")
        return
        
    owner_id = str(user["_id"])
    print(f"Seeding for user {owner_id}")
    
    # 1. Devices
    devices = [
        {"name": "Office Thermostat", "ip_address": "192.168.1.20", "device_type": "ESP32", "status": "active"},
        {"name": "Storage Node", "ip_address": "192.168.1.25", "device_type": "Raspberry Pi", "status": "active"},
        {"name": "Lobby Security Cam", "ip_address": "192.168.1.40", "device_type": "Camera", "status": "active"},
        {"name": "Unregistered Node", "ip_address": "192.168.1.55", "device_type": "Unknown Device", "status": "warning"}
    ]
    await DB.devices.delete_many({"owner_id": owner_id})
    for d in devices:
        d["owner_id"] = owner_id
        d["created_at"] = datetime.now(timezone.utc)
        d["last_seen"] = datetime.now(timezone.utc)
    await DB.devices.insert_many(devices)
    print("Seeded IoT Devices (ESP32, Camera, Unknown).")
    
    # 2. Network Metrics (Normal vs Abnormal)
    await DB.network_metrics.delete_many({"owner_id": owner_id})
    normal_metrics = []
    
    now = datetime.now(timezone.utc)
    for i in range(50):
        t = now - timedelta(minutes=60-i)
        normal_metrics.append({
            "owner_id": owner_id,
            "timestamp": t,
            "packets_per_second": random.randint(100, 300),
            "bytes_per_second": random.randint(5000, 15000),
            "active_connections": random.randint(5, 15),
            "failed_connections": random.randint(0, 2),
            "unique_destination_ips": random.randint(2, 5),
            "dns_requests": random.randint(1, 5)
        })
        
    # Generate abnormal metric spike at the end
    abnormal = {
        "owner_id": owner_id,
        "timestamp": now,
        "packets_per_second": 5200,
        "bytes_per_second": 890000,
        "active_connections": 250,
        "failed_connections": 130,
        "unique_destination_ips": 45,
        "dns_requests": 210
    }
    await DB.network_metrics.insert_many(normal_metrics + [abnormal])
    print("Seeded Network Metrics (Baseline + Outlier).")
    
    # 3. Security Events prompting Correlation
    await DB.events.delete_many({"owner_id": owner_id})
    await DB.incidents.delete_many({"owner_id": owner_id})
    
    events = [
        {"source": "Zeek", "event_type": "Unknown Device", "source_ip": "192.168.1.55", "destination_ip": "192.168.1.1", "severity": "Medium", "message": "New MAC found on network", "timestamp": now - timedelta(minutes=5), "owner_id": owner_id},
        {"source": "Suricata", "event_type": "Abnormal Traffic", "source_ip": "192.168.1.55", "destination_ip": "8.8.8.8", "severity": "Medium", "message": "High outlier connection packet rates", "timestamp": now - timedelta(minutes=4), "owner_id": owner_id},
        {"source": "Wazuh", "event_type": "IDS Alert", "source_ip": "192.168.1.55", "destination_ip": "192.168.1.100", "severity": "High", "message": "Attempted SSH Brute Force signature match", "timestamp": now - timedelta(minutes=3), "owner_id": owner_id},
        {"source": "VulnAI ML", "event_type": "AI Anomaly", "source_ip": "192.168.1.55", "destination_ip": "Multiple", "severity": "Critical", "message": "Isolation Forest detection flag: extreme active connections", "timestamp": now - timedelta(minutes=2), "owner_id": owner_id}
    ]
    
    for e in events:
        res = await DB.events.insert_one(e)
        await correlate_incident(e, str(res.inserted_id), DB, owner_id)
        
    print("Triggered Event ingestion and Correlation pipelines mapping Source IP groupings!")
    print("Success. Phase 7 DB ready.")

if __name__ == "__main__":
    asyncio.run(seed())
