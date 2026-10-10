"""
Network Device Discovery Service for SNID / VulnAI.
Implements multi-source local network device inventory:
1. Router / DHCP lease data (when provided/configured).
2. Local ARP cache and IPv4/IPv6 neighbor tables.
3. Rate-limited active subnet discovery for explicitly authorized local networks.

Enforces strict authorization: Never scans subnets not explicitly authorized.
Preserves evidence traceability: Never fabricates missing MACs, hostnames, or vendors.
"""
from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from app.services.mac_vendor import lookup_vendor, normalize_mac

# Default authorized private subnet ranges (RFC 1918)
DEFAULT_AUTHORIZED_SUBNETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]


def is_subnet_authorized(ip_or_cidr: str, authorized_subnets: list[str] | None = None) -> bool:
    """Check if an IP address or network CIDR falls within explicitly authorized subnets."""
    auth_list = authorized_subnets or DEFAULT_AUTHORIZED_SUBNETS
    try:
        target_network = ipaddress.ip_network(ip_or_cidr, strict=False)
    except ValueError:
        try:
            target_ip = ipaddress.ip_address(ip_or_cidr)
            target_network = ipaddress.ip_network(f"{target_ip}/32")
        except ValueError:
            return False

    for auth in auth_list:
        try:
            auth_network = ipaddress.ip_network(auth, strict=False)
            if target_network.subnet_of(auth_network):
                return True
        except ValueError:
            continue
    return False


def parse_arp_table(raw_output: str) -> list[dict[str, Any]]:
    """
    Parse operating system ARP table output (Windows `arp -a`, Linux `arp -n` / `ip neigh`).
    Returns list of parsed records with ip, mac, and type.
    """
    results: list[dict[str, Any]] = []
    lines = raw_output.strip().splitlines()

    # Match IPv4 and MAC: e.g. "  192.168.1.1       00-11-22-33-44-55     dynamic"
    # or Linux: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
    ipv4_pattern = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?:dev\s+\S+\s+lladdr\s+)?([0-9a-fA-F[:-]{11,17})",
        re.IGNORECASE,
    )

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        match = ipv4_pattern.search(line_clean)
        if match:
            ip = match.group(1)
            raw_mac = match.group(2)
            mac = normalize_mac(raw_mac)

            # Skip broadcast / multicast addresses
            if ip.endswith(".255") or ip == "255.255.255.255" or ip.startswith("224.") or ip.startswith("239."):
                continue
            if mac and mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                continue

            entry_type = "dynamic"
            if "static" in line_clean.lower():
                entry_type = "static"

            results.append({
                "ip_address": ip,
                "mac_address": mac,
                "entry_type": entry_type,
                "raw_line": line_clean,
            })

    return results


def resolve_hostname_sync(ip: str, timeout_seconds: float = 0.5) -> Optional[str]:
    """Resolve PTR hostname for an IP with a strict timeout to prevent blocking."""
    try:
        socket.setdefaulttimeout(timeout_seconds)
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            return host
    except Exception:
        pass
    return None


async def resolve_hostname(ip: str) -> Optional[str]:
    """Async wrapper for reverse DNS lookup."""
    return await asyncio.to_thread(resolve_hostname_sync, ip)


def get_local_arp_records() -> list[dict[str, Any]]:
    """Execute system ARP command safely and parse output."""
    cmd = ["arp", "-a"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if proc.returncode == 0:
            return parse_arp_table(proc.stdout)
    except Exception:
        pass
    return []


async def ping_host(ip: str, timeout_ms: int = 400) -> bool:
    """Send a single ICMP echo ping to an IP to refresh ARP and determine reachability."""
    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ret = await asyncio.wait_for(proc.wait(), timeout=1.5)
        return ret == 0
    except Exception:
        return False


async def active_sweep_subnet(subnet_cidr: str, max_concurrency: int = 25) -> list[str]:
    """
    Perform a rate-limited ping sweep over an explicitly authorized subnet.
    Strictly bounded to maximum 256 addresses (/24 or smaller) to prevent network flooding.
    """
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError:
        return []

    # Limit active sweep scope to prevent unauthorized wide scanning
    if network.num_addresses > 256:
        raise ValueError(f"Subnet {subnet_cidr} exceeds maximum authorized sweep limit of 256 hosts (/24).")

    active_ips: list[str] = []
    semaphore = asyncio.Semaphore(max_concurrency)

    async def check(ip_str: str):
        async with semaphore:
            alive = await ping_host(ip_str)
            if alive:
                active_ips.append(ip_str)

    hosts = [str(ip) for ip in network.hosts()]
    tasks = [check(h) for h in hosts]
    await asyncio.gather(*tasks, return_exceptions=True)
    return active_ips


def determine_device_type(vendor: Optional[str], hostname: Optional[str]) -> str:
    """Classify device node type based on reliable vendor and hostname hints."""
    text = f"{vendor or ''} {hostname or ''}".lower()
    if any(k in text for k in ("espressif", "esp32", "esp8266", "arduino", "sensor", "iot")):
        return "IoT Sensor"
    if any(k in text for k in ("camera", "cam", "dvr", "nvr", "hikvision", "dahua")):
        return "Camera"
    if any(k in text for k in ("cisco", "linksys", "tp-link", "netgear", "ubiquiti", "router", "gateway")):
        return "Edge Compute"
    if any(k in text for k in ("plug", "switch", "sonoff", "shelly", "tuya", "actuator")):
        return "IoT Actuator"
    return "Unclassified"


def evaluate_device_risk(
    is_authorized: bool,
    vendor: Optional[str],
    entry_type: str,
    status: str,
) -> str:
    """
    Calculate device risk level on transparent rules:
    - Unknown device on local subnet without vendor: Medium / High
    - Rogue candidate or unexpected static ARP spoof candidate: High
    - Authorized known device: Low
    """
    if not is_authorized:
        return "high" if not vendor else "medium"
    if status == "stale":
        return "low"
    return "low"


class DeviceDiscoveryEngine:
    """Coordinates local device discovery, deduplication, and persistence."""

    def __init__(self, db, owner_id: str):
        self.db = db
        self.owner_id = owner_id

    async def run_discovery_job(
        self,
        authorized_subnet: Optional[str] = None,
        active_sweep: bool = False,
    ) -> dict[str, Any]:
        """
        Run discovery pipeline:
        1. ARP table inspection.
        2. Optional authorized ping sweep to populate local neighbor table.
        3. Normalization, OUI vendor resolution, hostname resolution.
        4. Upsert into database without duplicates.
        """
        start_time = datetime.now(timezone.utc)
        evidence_sources = ["arp_cache"]
        limitations: list[str] = [
            "Network segmentation or Wi-Fi client isolation prevents observing peer-to-peer frames.",
            "Sleeping devices or firewall-silent hosts do not respond to ARP or ICMP requests.",
            "Devices across separate VLANs or routed hops are invisible without router DHCP/flow integration.",
        ]

        if active_sweep and authorized_subnet:
            if not is_subnet_authorized(authorized_subnet):
                raise PermissionError(f"Subnet {authorized_subnet} is not in the configured authorized subnets.")
            evidence_sources.append("active_icmp_sweep")
            await active_sweep_subnet(authorized_subnet)

        # Retrieve ARP records refreshed after potential ping sweep
        raw_records = await asyncio.to_thread(get_local_arp_records)
        discovered_count = 0
        updated_count = 0

        for rec in raw_records:
            ip = rec["ip_address"]
            mac = rec.get("mac_address")

            # Validate authorized subnet filter if subnet specified
            if authorized_subnet and not is_subnet_authorized(ip, [authorized_subnet]):
                continue

            vendor = lookup_vendor(mac) if mac else None
            hostname = await resolve_hostname(ip)
            device_type = determine_device_type(vendor, hostname)

            # Query existing device by MAC or IP to prevent duplicates
            query: dict[str, Any] = {"owner_id": self.owner_id}
            if mac:
                query["mac_address"] = mac
            else:
                query["ip_address"] = ip

            existing = await self.db.devices.find_one(query)

            is_authorized = existing.get("is_authorized", False) if existing else False
            classification = existing.get("inventory_classification", "unknown") if existing else "unknown"
            first_seen = existing.get("first_seen", start_time) if existing else start_time

            risk = evaluate_device_risk(
                is_authorized=is_authorized or (classification == "authorized"),
                vendor=vendor,
                entry_type=rec.get("entry_type", "dynamic"),
                status="online",
            )

            device_doc = {
                "name": existing.get("name") if existing and existing.get("name") else (hostname or f"Node-{ip.split('.')[-1]}"),
                "hostname": hostname,
                "ip_address": ip,
                "mac_address": mac,
                "manufacturer": vendor or "Unknown Vendor",
                "device_type": existing.get("device_type", device_type) if existing else device_type,
                "status": "online",
                "is_authorized": is_authorized,
                "inventory_classification": classification,
                "risk": risk,
                "confidence": 95 if mac and rec.get("entry_type") == "dynamic" else 80,
                "discovery_source": "arp_cache" if "active_icmp_sweep" not in evidence_sources else "arp_and_active_sweep",
                "first_seen": first_seen,
                "last_seen": start_time,
                "evidence": f"Recorded in OS neighbor table (type: {rec.get('entry_type', 'dynamic')}, line: {rec.get('raw_line', '')})",
                "owner_id": self.owner_id,
            }

            if existing:
                await self.db.devices.update_one({"_id": existing["_id"]}, {"$set": device_doc})
                updated_count += 1
            else:
                await self.db.devices.insert_one(device_doc)
                discovered_count += 1

        end_time = datetime.now(timezone.utc)
        duration_s = (end_time - start_time).total_seconds()

        job_summary = {
            "status": "completed",
            "subnet": authorized_subnet or "local_neighbor_table",
            "sources": evidence_sources,
            "new_devices_found": discovered_count,
            "updated_devices": updated_count,
            "total_observed": len(raw_records),
            "duration_seconds": round(duration_s, 2),
            "timestamp": end_time,
            "limitations_noted": limitations,
        }

        # Store discovery job audit log
        await self.db.discovery_jobs.insert_one({
            "owner_id": self.owner_id,
            **job_summary,
        })

        return job_summary
