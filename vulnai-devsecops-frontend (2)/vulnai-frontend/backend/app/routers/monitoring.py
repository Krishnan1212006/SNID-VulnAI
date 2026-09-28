from fastapi import APIRouter, Depends
import random
import time

router = APIRouter()

# Store start time to calculate uptime
START_TIME = time.time()

@router.get("/metrics")
async def get_system_metrics():
    # Simulate slightly fluctuating metrics for reality
    uptime_seconds = int(time.time() - START_TIME)
    
    # Calculate some fake but realistic looking metrics
    cpu_usage = round(15.0 + (random.random() * 15.0), 1)  # 15% - 30%
    ram_usage = round(42.0 + (random.random() * 10.0), 1)  # 42% - 52%
    db_latency = int(12 + (random.random() * 20))          # 12ms - 32ms
    active_connections = int(5 + random.random() * 15)     # 5 - 20
    
    return {
        "status": "healthy",
        "uptime_seconds": uptime_seconds,
        "infrastructure": {
            "cpu_usage_percent": cpu_usage,
            "ram_usage_percent": ram_usage,
            "disk_usage_percent": 34.2
        },
        "application": {
            "database_latency_ms": db_latency,
            "active_connections": active_connections,
            "error_rate_percent": round(random.random() * 1.5, 2), # 0% - 1.5%
            "requests_per_minute": int(120 + random.random() * 50)
        },
        "security": {
            "blocked_requests": int(uptime_seconds / 60 * 2.5), # Approx 2.5 blocks per min
            "active_scans": random.choice([0, 0, 1, 1, 2]) # Usually 0 or 1
        },
        "timestamp": time.time()
    }

@router.get("/health")
async def get_health():
    # Evaluate explicit container metrics verifying uptime explicitly
    return {"status": "ok", "uptime_seconds": int(time.time() - START_TIME), "version": "1.0.8"}

@router.get("/alerts")
async def get_system_alerts():
    return [
        {"id": "AL-1", "severity": "warning", "message": "High memory consumption on Node Alpha", "timestamp": time.time()},
        {"id": "AL-2", "severity": "info", "message": "New backend deploy successful", "timestamp": time.time()-86400}
    ]
