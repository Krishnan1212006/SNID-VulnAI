from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime


class DeviceBase(BaseModel):
    name: str
    ip_address: str
    mac_address: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: str = "Unclassified"
    status: str = "online"
    is_authorized: bool = False
    inventory_classification: str = "unknown"
    risk: str = "low"
    confidence: int = 80
    discovery_source: str = "arp_cache"
    evidence: Optional[str] = None


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    device_type: Optional[str] = None
    is_authorized: Optional[bool] = None
    inventory_classification: Optional[str] = None
    risk: Optional[str] = None


class DiscoveryTriggerRequest(BaseModel):
    authorized_subnet: Optional[str] = Field(None, description="CIDR subnet to discover, e.g. 192.168.1.0/24")
    active_sweep: bool = Field(False, description="Whether to perform rate-limited ICMP ping sweep on authorized subnet")


class WirelessEventIngest(BaseModel):
    sensor_id: str = Field(..., description="ESP32 hardware or logical sensor identifier")
    sensor_key: Optional[str] = Field(None, description="Pre-shared sensor authentication token")
    event_type: str = Field(..., description="Event type: deauth_burst, beacon_observation, duplicate_ssid, heartbeat")
    bssid: Optional[str] = Field(None, description="Observed BSSID MAC address")
    ssid: Optional[str] = Field(None, description="Observed Wi-Fi SSID network name")
    channel: Optional[int] = Field(None, description="802.11 RF channel number")
    rssi: Optional[int] = Field(None, description="Received signal strength in dBm")
    security: Optional[str] = Field(None, description="WPA2, WPA3, OPEN, etc.")
    frame_count: int = Field(1, ge=1, description="Number of observed frames in window")
    window_seconds: int = Field(5, ge=1, description="Sampling time window in seconds")
    firmware_version: Optional[str] = Field("1.0-defensive", description="Sensor firmware release")
    raw_evidence: Optional[str] = Field(None, description="Raw hex/text evidence from sensor radio")


class AuthorizedAPCreate(BaseModel):
    ssid: str = Field(..., min_length=1)
    bssid: str = Field(..., min_length=11)
    channel: Optional[int] = None
    security_type: str = Field("WPA2", description="WPA2, WPA3, 802.1X")
    notes: Optional[str] = None


class SensorRegisterRequest(BaseModel):
    sensor_id: str
    name: str = "ESP32 Defensive Sensor"
    api_key: str
    firmware_version: str = "1.0-defensive"


class SecurityEvent(BaseModel):
    source: str
    event_type: str
    source_ip: str
    destination_ip: str
    severity: str
    message: str
    timestamp: datetime
    raw_event: Dict[str, Any] = Field(default_factory=dict)
