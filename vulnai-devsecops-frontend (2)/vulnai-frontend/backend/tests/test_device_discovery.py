import pytest
from app.core.ids import ObjectId
from fastapi.testclient import TestClient
from app.main import app
from app.dependencies import get_current_user
from app.services.mac_vendor import lookup_vendor, normalize_mac
from app.services.device_discovery import (
    is_subnet_authorized,
    parse_arp_table,
    determine_device_type,
    evaluate_device_risk,
)

client = TestClient(app)


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: {"_id": "test-user-dev"})
    return client


def test_mac_normalization_and_oui_lookup():
    """Verify MAC normalization and hardware vendor OUI matching."""
    # Espressif
    assert normalize_mac("24-0a-c4-11-22-33") == "24:0A:C4:11:22:33"
    assert lookup_vendor("24:0a:c4:aa:bb:cc") == "Espressif Systems"

    # Raspberry Pi
    assert lookup_vendor("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"

    # Apple
    assert lookup_vendor("f0-18-98-ab-cd-ef") == "Apple"

    # Unknown
    assert lookup_vendor("99:88:77:66:55:44") is None

    # Invalid
    assert normalize_mac("not-a-mac") is None


def test_arp_parser_real_outputs():
    """Verify parsing Windows and Linux ARP neighbor table formats."""
    windows_sample = """
Interface: 192.168.1.50 --- 0x12
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.100         24-0a-c4-99-88-77     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
    parsed = parse_arp_table(windows_sample)
    assert len(parsed) == 2
    assert parsed[0]["ip_address"] == "192.168.1.1"
    assert parsed[0]["mac_address"] == "00:11:22:33:44:55"
    assert parsed[0]["entry_type"] == "dynamic"

    assert parsed[1]["ip_address"] == "192.168.1.100"
    assert parsed[1]["mac_address"] == "24:0A:C4:99:88:77"


def test_subnet_authorization_restrictions():
    """Verify that discovery is strictly restricted to authorized RFC 1918 subnets."""
    # Authorized private ranges
    assert is_subnet_authorized("192.168.1.0/24") is True
    assert is_subnet_authorized("10.0.5.0/24") is True
    assert is_subnet_authorized("172.16.10.0/24") is True
    assert is_subnet_authorized("192.168.1.15") is True

    # Unauthorized public internet subnets
    assert is_subnet_authorized("8.8.8.0/24") is False
    assert is_subnet_authorized("1.1.1.1") is False
    assert is_subnet_authorized("142.250.190.46/24") is False


def test_device_risk_and_type_rules():
    """Verify transparent risk evaluation and device type classification."""
    # Known device
    assert evaluate_device_risk(is_authorized=True, vendor="Apple", entry_type="dynamic", status="online") == "low"

    # Unknown device with known vendor
    assert evaluate_device_risk(is_authorized=False, vendor="Espressif Systems", entry_type="dynamic", status="online") == "medium"

    # Unknown device with unknown vendor
    assert evaluate_device_risk(is_authorized=False, vendor=None, entry_type="dynamic", status="online") == "high"

    # Device type resolution
    assert determine_device_type("Espressif Systems", "esp32-node") == "IoT Sensor"
    assert determine_device_type("Cisco Systems", "gateway.local") == "Edge Compute"
    assert determine_device_type("Hikvision", "cam-01") == "Camera"
    assert determine_device_type(None, None) == "Unclassified"


def test_api_devices_summary_and_empty_state(auth_client, monkeypatch):
    """Verify GET /api/devices/summary and empty inventory state."""
    class MockDB:
        class Devices:
            def find(self, query):
                class Cursor:
                    def sort(self, key, direction):
                        return self
                    async def to_list(self, limit):
                        return []
                return Cursor()
        devices = Devices()

    from app.routers import devices
    monkeypatch.setattr(devices, "get_database", lambda: MockDB())

    res = auth_client.get("/api/devices/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["devices_online"] == 0
    assert data["total_known_devices"] == 0
    assert data["unknown_devices"] == 0
    assert data["total_devices"] == 0


def test_unauthorized_discovery_subnet_rejected(auth_client):
    """Verify that initiating discovery on a public/unauthorized subnet returns 403 Forbidden."""
    res = auth_client.post("/api/devices/discovery", json={
        "authorized_subnet": "8.8.8.0/24",
        "active_sweep": False,
    })
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()
