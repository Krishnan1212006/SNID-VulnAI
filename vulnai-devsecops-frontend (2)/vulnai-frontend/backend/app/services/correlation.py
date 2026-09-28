from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from bson import ObjectId

async def correlate_incident(event: Dict[str, Any], event_id: str, db, owner_id: str):
    """
    Correlation engine using same source IP and 10-minute time window:
    - Unknown device + IDS alert = medium incident
    - Unknown device + abnormal traffic + IDS alert + AI anomaly = high incident
    - Failed logins + Wazuh alert + traffic spike = possible brute-force incident
    """
    source_ip = event.get("source_ip")
    if not source_ip:
        return
        
    ten_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
    
    # Fetch events in the last 10 minutes from this source_ip
    recent_events = await db.events.find({
        "owner_id": owner_id,
        "source_ip": source_ip,
        "timestamp": {"$gte": ten_mins_ago}
    }).to_list(100)
    
    event_types = [e.get("event_type", "").lower() for e in recent_events]
    sources = [e.get("source", "").lower() for e in recent_events]
    
    incident_severity = None
    incident_title = None
    
    # Rules
    if "wazuh alert" in event_types and "abnormal traffic" in event_types and "failed logins" in event_types:
        incident_severity = "high"
        incident_title = f"Possible Brute-Force Incident from {source_ip}"
    elif "unknown device" in event_types and "abnormal traffic" in event_types and "ids alert" in event_types and "ai anomaly" in event_types:
        incident_severity = "high"
        incident_title = f"High Risk Multi-vector Anomaly from {source_ip}"
    elif "unknown device" in event_types and "ids alert" in event_types:
        incident_severity = "medium"
        incident_title = f"Suspicious Unknown Device Activity from {source_ip}"
        
    if incident_severity and incident_title:
        # Check if an incident for this IP is already open in the last 10 minutes
        recent_incident = await db.incidents.find_one({
            "owner_id": owner_id,
            "source_ip": source_ip,
            "status": "OPEN",
            "created_at": {"$gte": ten_mins_ago}
        })
        
        if recent_incident:
            # Append event to existing incident
            await db.incidents.update_one(
                {"_id": recent_incident["_id"]},
                {"$addToSet": {"related_events": event_id}}
            )
        else:
            # Create new incident
            new_inc = {
                "title": incident_title,
                "severity": incident_severity,
                "status": "OPEN",
                "source_ip": source_ip,
                "created_at": datetime.now(timezone.utc),
                "owner_id": owner_id,
                "description": f"Automated correlation flagged anomalous patterns mapping 10-minute thresholds for {source_ip}.",
                "related_events": [str(e["_id"]) for e in recent_events]
            }
            await db.incidents.insert_one(new_inc)
