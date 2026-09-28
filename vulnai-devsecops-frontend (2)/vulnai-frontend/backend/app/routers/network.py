from fastapi import APIRouter, Depends
from app.database import get_database
from app.dependencies import get_current_user

router = APIRouter()

@router.get("/metrics")
async def get_network_metrics(current_user: dict = Depends(get_current_user)):
    db = get_database()
    metrics = await db.network_metrics.find({"owner_id": str(current_user["_id"])}).sort("timestamp", -1).limit(50).to_list(50)
    for m in metrics:
        m["id"] = str(m["_id"])
    metrics.reverse()
    return metrics
