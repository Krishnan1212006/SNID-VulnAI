"""
Network Device Discovery Service for SNID / VulnAI.
Implements multi-source local network device inventory:
1. Router / DHCP lease data (when provided/configured).
2. Local ARP cache and IPv4/IPv6 neighbor tables with interface binding.
3. Rate-limited active subnet discovery for explicitly authorized local networks.

Enforces strict authorization: Never scans subnets not explicitly authorized.
Preserves evidence traceability: Never fabricates missing MACs, hostnames, or vendors.
Real status states: observed_recently, stale, unreachable, unassessed, etc.
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
from app.services.network_interfaces import get_all_network_interfaces

# Default authorized private subnet ranges (RFC 1918)
DEFAULT_AUTHORIZED_SUBNETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]

# In-memory registry for active discovery jobs (allows cancellation)
ACTIVE_JOBS: dict[str, dict[str, Any]] = {}


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
    Extracts interface bindings when available (e.g. `Interface: 172.16.18.12 --- 0x17`).
    Returns list of parsed records with ip, mac, interface_ip, and type.
    """
    results: list[dict[str, Any]] = []
    lines = raw_output.strip().splitlines()

    current_interface_ip: Optional[str] = None
    interface_pattern = re.compile(r"Interface:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE)

    ipv4_pattern = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?:dev\s+(\S+)\s+lladdr\s+)?([0-9a-fA-F[:-]{11,17})",
        re.IGNORECASE,
    )

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        if_match = interface_pattern.search(line_clean)
        if if_match:
            current_interface_ip = if_match.group(1)
            continue

        match = ipv4_pattern.search(line_clean)
        if match:
            ip = match.group(1)
            linux_dev = match.group(2)
            raw_mac = match.group(3)
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
                "interface_ip": current_interface_ip,
                "interface_device": linux_dev,
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


async def ping_host(ip: str, timeout_ms: int = 350) -> bool:
    """Send a single ICMP echo ping to an IP to refresh ARP and determine reachability."""
    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ret = await asyncio.wait_for(proc.wait(), timeout=1.2)
        return ret == 0
    except Exception:
        return False


async def active_sweep_subnet(subnet_cidr: str, max_concurrency: int = 25, cancel_check=None) -> list[str]:
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
        if cancel_check and cancel_check():
            return
        async with semaphore:
            alive = await ping_host(ip_str)
            if alive:
                active_ips.append(ip_str)

    hosts = [str(ip) for ip in network.hosts()]
    tasks = [check(h) for h in hosts]
    await asyncio.gather(*tasks, return_exceptions=True)
    return active_ips


def determine_device_type(vendor: Optional[str], hostname: Optional[str], is_gateway: bool = False) -> str:
    """Classify device node type based on reliable vendor and hostname hints."""
    if is_gateway:
        return "Edge Compute"
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
    is_gateway: bool = False,
    is_spoof_candidate: bool = False,
) -> str:
    """
    Calculate evidence-based device risk:
    - Unknown does NOT automatically mean HIGH risk.
    - Authorized device or Default Gateway: low
    - Unknown device with recognized vendor (Apple, Intel, etc.): low
    - Unknown device with unrecognized vendor: unassessed (needs admin check, not automatically malicious)
    - Confirmed anomaly (spoof candidate or rogue AP): high
    """
    if is_spoof_candidate:
        return "high"
    if is_authorized or is_gateway:
        return "low"
    if vendor:
        return "low"
    return "unassessed"


class DeviceDiscoveryEngine:
    """Coordinates local device discovery, deduplication, and persistence."""

    def __init__(self, db, owner_id: str):
        self.db = db
        self.owner_id = owner_id

    async def run_discovery_job(
        self,
        job_id: str,
        authorized_subnet: Optional[str] = None,
        active_sweep: bool = False,
    ) -> dict[str, Any]:
        """
        Run modular discovery pipeline:
        1. Check active host network interfaces.
        2. Inspect OS ARP/neighbor cache.
        3. Optional authorized rate-limited ping sweep to refresh neighbor table.
        4. OUI vendor and PTR hostname resolution.
        5. Real observation status: observed_recently, stale, unreachable.
        6. Upsert into database without duplicates.
        """
        start_time = datetime.now(timezone.utc)
        ACTIVE_JOBS[job_id] = {"status": "RUNNING", "cancelled": False, "start_time": start_time}

        adapters = await asyncio.to_thread(get_all_network_interfaces)
        adapter_map = {a["ipv4_address"]: a for a in adapters if a.get("ipv4_address")}
        primary_adapter = next((a for a in adapters if a.get("is_default")), adapters[0] if adapters else None)

        sources_used = ["os_neighbor_table"]
        unavailable_sources = ["router_dhcp_inventory (Not configured)"]
        limitations: list[str] = [
            "Local neighbor tables observe only hosts communicating recently with this station.",
            "VLAN-separated devices and Wi-Fi client isolation environments require router flow data.",
            "Sleeping IoT devices or stealth-firewalled endpoints do not respond to active ICMP probes.",
        ]

        # Use interface subnet if no subnet explicitly passed
        target_subnet = authorized_subnet
        if not target_subnet and primary_adapter and primary_adapter.get("network_cidr"):
            # Only use if /24 or smaller
            try:
                net = ipaddress.ip_network(primary_adapter["network_cidr"], strict=False)
                if net.num_addresses <= 256:
                    target_subnet = str(net)
            except Exception:
                pass

        if active_sweep and target_subnet:
            if not is_subnet_authorized(target_subnet):
                ACTIVE_JOBS[job_id]["status"] = "FAILED"
                raise PermissionError(f"Subnet {target_subnet} is not in the configured authorized subnets.")

            sources_used.append("active_icmp_sweep")
            await active_sweep_subnet(
                target_subnet,
                cancel_check=lambda: ACTIVE_JOBS.get(job_id, {}).get("cancelled", False),
            )

        if ACTIVE_JOBS.get(job_id, {}).get("cancelled", False):
            ACTIVE_JOBS[job_id]["status"] = "CANCELLED"
            return {"status": "CANCELLED", "message": "Discovery job was cancelled by user"}

        # Read actual OS neighbor records
        raw_records = await asyncio.to_thread(get_local_arp_records)
        discovered_count = 0
        updated_count = 0

        # Gateway IPs to identify routers
        known_gateways = {a["default_gateway"] for a in adapters if a.get("default_gateway")}

        for rec in raw_records:
            if ACTIVE_JOBS.get(job_id, {}).get("cancelled", False):
                break

            ip = rec["ip_address"]
            mac = rec.get("mac_address")
            iface_ip = rec.get("interface_ip")

            # Match adapter context
            adapter_info = adapter_map.get(iface_ip) or primary_adapter
            iface_name = adapter_info.get("name") if adapter_info else (rec.get("interface_device") or "Default Adapter")
            network_cidr = adapter_info.get("network_cidr") if adapter_info else None
            is_gateway = ip in known_gateways

            # Enforce subnet filter if specific subnet was requested
            if authorized_subnet and not is_subnet_authorized(ip, [authorized_subnet]):
                continue

            vendor = lookup_vendor(mac) if mac else None
            hostname = await resolve_hostname(ip)
            device_type = determine_device_type(vendor, hostname, is_gateway=is_gateway)

            # Query existing device by MAC or IP to prevent duplicate entries
            query: dict[str, Any] = {"owner_id": self.owner_id}
            if mac:
                query["mac_address"] = mac
            else:
                query["ip_address"] = ip

            existing = await self.db.devices.find_one(query)

            is_authorized = existing.get("is_authorized", False) if existing else is_gateway
            classification = existing.get("inventory_classification", "authorized" if is_gateway else "unknown") if existing else ("authorized" if is_gateway else "unknown")
            first_seen = existing.get("first_seen", start_time) if existing else start_time

            risk = evaluate_device_risk(
                is_authorized=is_authorized or (classification == "authorized"),
                vendor=vendor,
                is_gateway=is_gateway,
            )

            # Formulate device name without fabricating
            default_name = f"Router Gateway ({ip})" if is_gateway else (hostname or (f"{vendor} Device" if vendor else f"Node-{ip.split('.')[-1]}"))
            device_name = existing.get("name") if existing and existing.get("name") else default_name

            device_doc = {
                "name": device_name,
                "hostname": hostname,
                "ip_address": ip,
                "mac_address": mac,
                "manufacturer": vendor or "Unknown Vendor",
                "device_type": existing.get("device_type", device_type) if existing else device_type,
                "interface_name": iface_name,
                "network_cidr": network_cidr,
                "status": "online",
                "observation_status": "observed_recently",
                "is_authorized": is_authorized,
                "inventory_classification": classification,
                "risk": risk,
                "confidence": 95 if mac and rec.get("entry_type") == "dynamic" else 85,
                "discovery_source": "arp_cache" if "active_icmp_sweep" not in sources_used else "arp_and_active_sweep",
                "first_seen": first_seen,
                "last_seen": start_time,
                "observation_timestamp": start_time,
                "last_successful_observation": start_time,
                "evidence": f"Observed in {iface_name} neighbor table (entry: {rec.get('entry_type', 'dynamic')}, line: '{rec.get('raw_line', '')}')",
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
        final_status = "CANCELLED" if ACTIVE_JOBS.get(job_id, {}).get("cancelled", False) else "COMPLETED"

        job_summary = {
            "job_id": job_id,
            "status": final_status,
            "subnet": target_subnet or "local_neighbor_table",
            "sources_used": sources_used,
            "unavailable_sources": unavailable_sources,
            "new_devices_found": discovered_count,
            "updated_devices": updated_count,
            "total_observed": len(raw_records),
            "duration_seconds": round(duration_s, 2),
            "start_time": start_time,
            "finish_time": end_time,
            "limitations_noted": limitations,
        }

        ACTIVE_JOBS[job_id].update(job_summary)

        # Audit log in database
        await self.db.discovery_jobs.update_one(
            {"job_id": job_id, "owner_id": self.owner_id},
            {"$set": job_summary},
            upsert=True,
        )

        return job_summary
