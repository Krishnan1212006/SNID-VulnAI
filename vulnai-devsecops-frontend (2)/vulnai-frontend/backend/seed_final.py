import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import os

load_dotenv()
MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
CLIENT = AsyncIOMotorClient(MONGO_URI)
DB = CLIENT["vulnai_platform"]

async def seed():
    # Grab the first user
    user = await DB.users.find_one({})
    if not user:
        print("No user found. Please register an account first.")
        return
        
    owner_id = str(user["_id"])
    print(f"Seeding final endpoints for user {owner_id}")
    
    # 1. DevSecOps Pipelines
    await DB.pipeline_runs.delete_many({"owner_id": owner_id})
    now = datetime.now(timezone.utc)
    
    pipelines = [
        {
            "owner_id": owner_id,
            "commit_hash": "a4d9b2e",
            "branch": "main",
            "trigger": "push",
            "status": "passed",
            "gate_status": "Passed",
            "reason": "Gate Passed: No critical vulnerabilities found.",
            "duration": "1m 45s",
            "stages": [
                {"name": "Semgrep SAST", "status": "passed"},
                {"name": "Pytest Validation", "status": "passed"},
                {"name": "Trivy Container Scan", "status": "passed"}
            ],
            "severity_counts": {"critical": 0, "high": 2, "medium": 5, "low": 12},
            "created_at": now - timedelta(hours=2)
        },
        {
            "owner_id": owner_id,
            "commit_hash": "f103ca7",
            "branch": "feature/payment",
            "trigger": "pull_request",
            "status": "failed",
            "gate_status": "Blocked",
            "reason": "Gate Failed: Found 2 critical vulnerabilities (SQLi, Log4j).",
            "duration": "2m 10s",
            "stages": [
                {"name": "Semgrep SAST", "status": "failed"},
                {"name": "Pytest Validation", "status": "passed"},
                {"name": "Trivy Container Scan", "status": "failed"}
            ],
            "severity_counts": {"critical": 2, "high": 8, "medium": 3, "low": 1},
            "created_at": now - timedelta(minutes=30)
        }
    ]
    
    await DB.pipeline_runs.insert_many(pipelines)
    print("Seeded DevSecOps Pipeline Runs (Passed and Failed/Blocked rules evaluated).")
    print("Success. Final Phase 8 DB ready.")

if __name__ == "__main__":
    asyncio.run(seed())
