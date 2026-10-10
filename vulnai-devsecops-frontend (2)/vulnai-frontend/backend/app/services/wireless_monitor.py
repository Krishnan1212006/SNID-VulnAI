"""
SNID ESP32 Wireless Defensive Monitoring & Rogue Access Point Detection Engine.
Integrates defensive wireless sensor feeds (e.g. ProjectHydra defensive firmware export):
- Deauthentication frame burst monitoring
- Nearby access point beacon observations
- Rogue Access Point / Evil Twin heuristic detection
- Sensor health and telemetry correlation
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from app.services.mac_vendor import normalize_mac, lookup_vendor


class WirelessMonitorEngine:
    """Processes, authenticates, and correlates defensive ESP32 wireless security events."""

    def __init__(self, db, owner_id: str):
        self.db = db
        self.owner_id = owner_id

    async def verify_sensor_key(self, sensor_id: str, sensor_key: str) -> bool:
        """Verify sensor authentication token against registered sensor records."""
        if not sensor_id or not sensor_key:
            return False
        sensor = await self.db.wireless_sensors.find_one({
            "sensor_id": sensor_id,
            "owner_id": self.owner_id,
        })
        if not sensor:
            # If no sensor registered yet, allow registration if sensor_key matches configured default or first provision
            return False
        return sensor.get("api_key") == sensor_key

    async def record_sensor_heartbeat(
        self,
        sensor_id: str,
        name: str = "ESP32 Sensor",
        firmware_version: str = "1.0-defensive",
        battery_level: Optional[float] = None,
        channel: Optional[int] = None,
    ) -> dict[str, Any]:
        """Update or register wireless sensor health status."""
        now = datetime.now(timezone.utc)
        sensor_doc = {
            "sensor_id": sensor_id,
            "name": name,
            "owner_id": self.owner_id,
            "last_seen": now,
            "status": "online",
            "firmware_version": firmware_version,
            "channel": channel,
            "battery_level": battery_level,
        }
        await self.db.wireless_sensors.update_one(
            {"sensor_id": sensor_id, "owner_id": self.owner_id},
            {"$set": sensor_doc},
            upsert=True,
        )
        return sensor_doc

    def _generate_event_fingerprint(
        self,
        sensor_id: str,
        event_type: str,
        bssid: Optional[str],
        ssid: Optional[str],
        timestamp: datetime,
    ) -> str:
        """Create a stable 5-minute time-bucket fingerprint to deduplicate repeated bursts."""
        # 5-minute bucket
        bucket = int(timestamp.timestamp() // 300)
        raw = f"{sensor_id}:{event_type}:{bssid or ''}:{ssid or ''}:{bucket}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    async def ingest_wireless_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize and ingest an authenticated wireless observation.
        The backend independently calculates severity and verification status.
        """
        now = datetime.now(timezone.utc)
        sensor_id = payload.get("sensor_id", "esp32-sensor-01")
        event_type = payload.get("event_type", "beacon_observation")
        raw_bssid = payload.get("bssid")
        bssid = normalize_mac(raw_bssid) if raw_bssid else None
        ssid = payload.get("ssid", "").strip() or None
        channel = payload.get("channel")
        rssi = payload.get("rssi")
        frame_count = payload.get("frame_count", 1)
        window_seconds = payload.get("window_seconds", 5)
        raw_evidence = payload.get("raw_evidence", f"ESP32 RF frame observation: {event_type}")

        # Update sensor heartbeat automatically
        await self.record_sensor_heartbeat(
            sensor_id=sensor_id,
            firmware_version=payload.get("firmware_version", "1.0-defensive"),
            channel=channel,
        )

        fingerprint = self._generate_event_fingerprint(sensor_id, event_type, bssid, ssid, now)

        # Check for deduplication within the 5-minute window
        existing = await self.db.wireless_events.find_one({
            "owner_id": self.owner_id,
            "fingerprint": fingerprint,
        })
        if existing:
            # Increment frame counter and update last seen rather than creating duplicate
            await self.db.wireless_events.update_one(
                {"_id": existing["_id"]},
                {
                    "$inc": {"frame_count": frame_count, "observation_count": 1},
                    "$set": {"last_seen": now, "rssi": rssi or existing.get("rssi")},
                },
            )
            return {
                "message": "Deduplicated repeated event in window",
                "event_id": str(existing["_id"]),
                "status": "deduplicated",
            }

        # Independent rule-based evaluation
        rule_name = "STANDARD_RF_OBSERVATION"
        confidence = 70
        verification_status = "observed"
        severity = "low"
        title = f"Wireless Observation: {event_type}"
        recommendation = "Normal wireless RF activity recorded for baseline."

        if event_type == "deauth_burst":
            # Deauthentication burst detection
            if frame_count >= 15:
                severity = "high"
                verification_status = "potential_threat"
                confidence = 88
                rule_name = "HIGH_FREQUENCY_DEAUTH_BURST"
                title = f"High-Volume 802.11 Deauth Burst ({frame_count} frames/{window_seconds}s)"
                recommendation = "Investigate localized Wi-Fi disruption or potential rogue deauthentication attack near target BSSID."
            else:
                severity = "medium"
                verification_status = "observed"
                confidence = 75
                rule_name = "MODERATE_DEAUTH_ACTIVITY"
                title = f"Moderate 802.11 Deauth Frames Detected ({frame_count} frames)"
                recommendation = "Monitor channel for roaming client disconnections or AP retransmissions."

        elif event_type in ("beacon_observation", "ap_inventory"):
            # Rogue AP Heuristic Analysis
            rogue_eval = await self._evaluate_rogue_access_point(bssid, ssid, channel, payload.get("security"), rssi)
            severity = rogue_eval["severity"]
            confidence = rogue_eval["confidence"]
            verification_status = rogue_eval["verification_status"]
            rule_name = rogue_eval["rule_name"]
            title = rogue_eval["title"]
            recommendation = rogue_eval["recommendation"]

        elif event_type == "duplicate_ssid":
            severity = "medium"
            verification_status = "potential_threat"
            confidence = 80
            rule_name = "UNEXPECTED_DUPLICATE_SSID"
            title = f"Multiple BSSIDs Broadcasting Identical SSID '{ssid}'"
            recommendation = "Compare observed BSSID against authorized AP inventory to confirm legitimate multi-AP mesh or rogue clone."

        event_doc = {
            "owner_id": self.owner_id,
            "sensor_id": sensor_id,
            "event_type": event_type,
            "title": title,
            "timestamp": now,
            "bssid": bssid,
            "ssid": ssid,
            "vendor": lookup_vendor(bssid) if bssid else None,
            "channel": channel,
            "rssi": rssi,
            "frame_count": frame_count,
            "observation_count": 1,
            "window_seconds": window_seconds,
            "severity": severity,
            "confidence": confidence,
            "verification_status": verification_status,
            "detection_rule": rule_name,
            "recommendation": recommendation,
            "raw_evidence": raw_evidence,
            "fingerprint": fingerprint,
        }

        res = await self.db.wireless_events.insert_one(event_doc)
        event_doc["id"] = str(res.inserted_id)

        # Correlate into higher-level incidents if high severity
        if severity == "high":
            await self._correlate_wireless_incident(event_doc)

        return {
            "message": "Event recorded",
            "event_id": event_doc["id"],
            "verification_status": verification_status,
            "severity": severity,
        }

    async def _evaluate_rogue_access_point(
        self,
        bssid: Optional[str],
        ssid: Optional[str],
        channel: Optional[int],
        security: Optional[str],
        rssi: Optional[int],
    ) -> dict[str, Any]:
        """
        Compare observed AP against administrator authorized AP inventory.
        Rules:
        - If SSID matches authorized network but BSSID is NOT in authorized list: Potential Rogue (Evil Twin candidate).
        - If corporate protected SSID is observed with OPEN encryption: High risk rogue.
        - If BSSID matches authorized list: Normal baseline.
        - If both SSID and BSSID are unfamiliar: Unknown neighbor AP (observed, low risk).
        """
        if not ssid or not bssid:
            return {
                "severity": "low",
                "confidence": 60,
                "verification_status": "observed",
                "rule_name": "INCOMPLETE_BEACON_METADATA",
                "title": f"Beacon observation with incomplete BSSID/SSID",
                "recommendation": "Maintain observation.",
            }

        authorized_ap = await self.db.authorized_access_points.find_one({
            "owner_id": self.owner_id,
            "ssid": ssid,
        })

        if authorized_ap:
            authorized_bssid = normalize_mac(authorized_ap.get("bssid"))
            # Check if BSSID is authorized
            if authorized_bssid and authorized_bssid == bssid:
                return {
                    "severity": "low",
                    "confidence": 95,
                    "verification_status": "observed",
                    "rule_name": "AUTHORIZED_AP_MATCH",
                    "title": f"Authorized Access Point Verified: '{ssid}' ({bssid})",
                    "recommendation": "Device matches registered infrastructure baseline.",
                }

            # BSSID mismatch on authorized SSID!
            sec_type = (security or "").upper()
            if "OPEN" in sec_type or sec_type == "NONE":
                return {
                    "severity": "high",
                    "confidence": 92,
                    "verification_status": "corroborated",
                    "rule_name": "ROGUE_AP_OPEN_ENCRYPTION_CLONE",
                    "title": f"CRITICAL: Unencrypted Rogue AP Mimicking Authorized SSID '{ssid}'",
                    "recommendation": "Immediate containment: Rogue AP is broadcasting protected corporate SSID with open security.",
                }

            return {
                "severity": "medium",
                "confidence": 82,
                "verification_status": "potential_threat",
                "rule_name": "UNAUTHORIZED_BSSID_BROADCASTING_AUTH_SSID",
                "title": f"Potential Rogue AP / Evil Twin Candidate: '{ssid}' from {bssid}",
                "recommendation": f"Verify whether {bssid} is an unrecorded mesh repeater or an unauthorized rogue transmitter.",
            }

        # Check if BSSID itself is in authorized list under different SSID
        bssid_match = await self.db.authorized_access_points.find_one({
            "owner_id": self.owner_id,
            "bssid": bssid,
        })
        if bssid_match:
            return {
                "severity": "medium",
                "confidence": 78,
                "verification_status": "potential_threat",
                "rule_name": "AUTHORIZED_BSSID_SSID_CHANGE",
                "title": f"Authorized Hardware Broadcasting Unexpected SSID: '{ssid}'",
                "recommendation": "Investigate configuration change on physical access point.",
            }

        # Normal neighbor network observation
        return {
            "severity": "low",
            "confidence": 75,
            "verification_status": "observed",
            "rule_name": "NEIGHBOR_ACCESS_POINT",
            "title": f"Neighbor Access Point Detected: '{ssid}'",
            "recommendation": "Unmanaged adjacent wireless environment.",
        }

    async def _correlate_wireless_incident(self, event_doc: dict[str, Any]):
        """Create or update an incident in db.incidents when high-risk wireless alerts occur."""
        ten_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
        existing_inc = await self.db.incidents.find_one({
            "owner_id": self.owner_id,
            "status": "OPEN",
            "source_ip": event_doc.get("bssid") or "wireless-rf",
            "created_at": {"$gte": ten_mins_ago},
        })

        if existing_inc:
            await self.db.incidents.update_one(
                {"_id": existing_inc["_id"]},
                {"$addToSet": {"related_events": event_doc["id"]}},
            )
        else:
            await self.db.incidents.insert_one({
                "title": f"Wireless Security Alert: {event_doc['title']}",
                "severity": event_doc["severity"],
                "status": "OPEN",
                "source_ip": event_doc.get("bssid") or "wireless-rf",
                "created_at": datetime.now(timezone.utc),
                "owner_id": self.owner_id,
                "description": f"Automated wireless detection engine triggered rule {event_doc['detection_rule']}: {event_doc['raw_evidence']}",
                "related_events": [event_doc["id"]],
            })
