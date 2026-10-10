"""
IEEE OUI (Organizationally Unique Identifier) Vendor Lookup.
Maps MAC address prefixes to hardware manufacturers reliably.
"""
from typing import Optional
import re

# Curated IEEE OUI prefix table for common network and IoT manufacturers
OUI_TABLE: dict[str, str] = {
    # Espressif (IoT chips, ESP32, ESP8266)
    "24:0A:C4": "Espressif Systems",
    "24:6F:28": "Espressif Systems",
    "30:AE:A4": "Espressif Systems",
    "84:CC:A8": "Espressif Systems",
    "A4:CF:12": "Espressif Systems",
    "AC:67:B2": "Espressif Systems",
    "B4:E6:2D": "Espressif Systems",
    "C4:4F:33": "Espressif Systems",
    "DC:4F:22": "Espressif Systems",
    "EC:FA:BC": "Espressif Systems",
    "80:7D:3A": "Espressif Systems",
    "7C:DF:A1": "Espressif Systems",
    "48:E7:29": "Espressif Systems",

    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",

    # Apple
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:95": "Apple",
    "00:11:24": "Apple",
    "00:17:F2": "Apple",
    "00:1B:63": "Apple",
    "00:1E:C2": "Apple",
    "14:10:9F": "Apple",
    "3C:07:54": "Apple",
    "40:6C:8F": "Apple",
    "70:3E:AC": "Apple",
    "A4:83:E7": "Apple",
    "BC:92:6B": "Apple",
    "F0:18:98": "Apple",

    # Intel
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:0E:0C": "Intel",
    "00:13:E8": "Intel",
    "00:1B:21": "Intel",
    "34:13:E8": "Intel",
    "48:51:B7": "Intel",
    "68:05:CA": "Intel",
    "80:86:F2": "Intel",
    "A4:4C:C8": "Intel",

    # Cisco / Linksys
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:64": "Cisco Systems",
    "00:04:4D": "Cisco Systems",
    "00:06:53": "Cisco Systems",
    "00:0F:23": "Cisco Systems",
    "00:18:74": "Cisco Systems",
    "00:22:BD": "Cisco Systems",
    "00:06:25": "Linksys",
    "00:0C:41": "Linksys",
    "00:14:BF": "Linksys",

    # TP-Link
    "00:19:E0": "TP-Link Technologies",
    "14:CC:20": "TP-Link Technologies",
    "50:BD:5F": "TP-Link Technologies",
    "60:E3:27": "TP-Link Technologies",
    "90:F6:52": "TP-Link Technologies",
    "C0:4A:00": "TP-Link Technologies",
    "EC:08:6B": "TP-Link Technologies",

    # Netgear
    "00:09:5B": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1F:33": "Netgear",
    "00:26:F2": "Netgear",
    "20:E5:2A": "Netgear",

    # Google / Nest
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "64:16:66": "Google",
    "F4:F5:DB": "Google",
    "D8:6C:63": "Google / Nest",

    # Amazon / Ring
    "00:FC:8B": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
    "68:54:5A": "Amazon Technologies",
    "AC:63:BE": "Amazon Technologies",
    "FC:65:DE": "Amazon Technologies",
    "B0:09:DA": "Ring LLC",

    # Microsoft
    "00:0D:3A": "Microsoft",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:50:F2": "Microsoft",
    "7C:1E:52": "Microsoft",

    # Samsung
    "00:07:AB": "Samsung Electronics",
    "00:12:47": "Samsung Electronics",
    "00:15:B9": "Samsung Electronics",
    "00:23:D7": "Samsung Electronics",
    "50:01:D9": "Samsung Electronics",

    # Ubiquiti Networks
    "00:15:6D": "Ubiquiti Networks",
    "00:27:22": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "F4:92:BF": "Ubiquiti Networks",

    # Microchip / Atmel
    "00:04:A3": "Microchip Technology",
    "00:08:DC": "Microchip Technology",
    "D8:80:39": "Microchip Technology",

    # Arduino
    "A8:61:0A": "Arduino LLC",
    "CC:F9:57": "Arduino LLC",
}


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalize MAC address to uppercase XX:XX:XX:XX:XX:XX format."""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac.strip())
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i + 2].upper() for i in range(0, 12, 2))


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Look up hardware manufacturer by MAC address OUI prefix."""
    norm = normalize_mac(mac)
    if not norm:
        return None
    prefix = norm[:8]
    return OUI_TABLE.get(prefix)
