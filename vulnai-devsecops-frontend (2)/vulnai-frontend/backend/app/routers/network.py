"""
Network Topology and Real Hardware Interface Router.
Provides actual detected operating system adapters, default gateway routes,
and discovery source readiness indicators.
"""
from fastapi import APIRouter, Depends
from app.database import get_database
from app.dependencies import get_current_user
from app.services.network_interfaces import get_all_network_interfaces, get_network_topology_status

router = APIRouter()


@router.get("/interfaces")
async def list_network_interfaces(current_user: dict = Depends(get_current_user)):
    """List detected operating system network interfaces, IP addresses, and CIDR subnets."""
    return get_all_network_interfaces()


@router.get("/status")
async def get_network_status(current_user: dict = Depends(get_current_user)):
    """
    Get current network connection topology, primary adapter, and discovery source status.
    Indicates whether router, ARP, active sweep, or ESP32 sources are available.
    """
    return get_network_topology_status()


@router.get("/metrics")
async def get_network_metrics(current_user: dict = Depends(get_current_user)):
    """Historical network performance metrics."""
    db = get_database()
    owner_id = str(current_user["_id"])
    cursor = db.network_metrics.find({"owner_id": owner_id}).sort("timestamp", -1)
    metrics = await cursor.to_list(50)
    for m in metrics:
        m["id"] = str(m["_id"])
    metrics.reverse()
    return metrics
