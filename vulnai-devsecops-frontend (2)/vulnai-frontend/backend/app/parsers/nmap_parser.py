"""
Nmap output parser.

Parses raw Nmap service scan text output and converts it into
normalized finding dicts that match the vulnerability schema.

IMPORTANT: Findings are classified as 'potential' or 'informational'.
Open ports alone are NOT confirmed vulnerabilities — manual review required.
"""

import re
from typing import List, Dict, Any
from datetime import datetime, timezone

# Ports that warrant elevated attention
HIGH_RISK_PORTS: Dict[str, Dict[str, str]] = {
    "21":    {"name": "FTP",              "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-319"},
    "23":    {"name": "Telnet",           "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-319"},
    "25":    {"name": "SMTP",             "severity": "medium", "owasp": "A05:2021", "cwe": "CWE-200"},
    "53":    {"name": "DNS",              "severity": "low",    "owasp": "A05:2021", "cwe": "CWE-200"},
    "110":   {"name": "POP3",             "severity": "medium", "owasp": "A05:2021", "cwe": "CWE-319"},
    "135":   {"name": "RPC",              "severity": "medium", "owasp": "A05:2021", "cwe": "CWE-200"},
    "139":   {"name": "NetBIOS",          "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "445":   {"name": "SMB",              "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "1433":  {"name": "MSSQL",            "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "1521":  {"name": "Oracle DB",        "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "3306":  {"name": "MySQL",            "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "3389":  {"name": "RDP",              "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-319"},
    "5432":  {"name": "PostgreSQL",       "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "5900":  {"name": "VNC",              "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-319"},
    "6379":  {"name": "Redis",            "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "8080":  {"name": "HTTP-Alt",         "severity": "medium", "owasp": "A05:2021", "cwe": "CWE-200"},
    "8443":  {"name": "HTTPS-Alt",        "severity": "low",    "owasp": "A05:2021", "cwe": "CWE-200"},
    "9200":  {"name": "Elasticsearch",    "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
    "27017": {"name": "MongoDB",          "severity": "high",   "owasp": "A05:2021", "cwe": "CWE-200"},
}

# Pattern for open TCP ports from nmap -sV output
PORT_PATTERN = re.compile(
    r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*?)$",
    re.MULTILINE
)

# Pattern for version disclosure in service banner
VERSION_PATTERN = re.compile(
    r"\d+\.\d+(?:\.\d+)?(?:[\w\-\.]+)?",
)

def _make_finding(
    scan_id: str,
    asset_id: str,
    owner_id: str,
    target: str,
    port: str,
    service: str,
    version: str,
    raw_line: str,
) -> Dict[str, Any]:
    """Build a normalised finding dict for one open port."""

    info = HIGH_RISK_PORTS.get(port)
    if info:
        severity = info["severity"]
        owasp_id = info["owasp"]
        cwe_id   = info["cwe"]
        title    = f"High-risk port {port}/tcp open — {info['name']} ({service})"
        confidence = "potential"
        description = (
            f"Port {port}/tcp is open running {service} "
            f"({info['name']}). This service is considered high-risk "
            f"when exposed publicly. "
        )
        recommendation = (
            f"Restrict access to port {port} ({info['name']}) via firewall rules. "
            f"Only expose this service if strictly required and ensure it is "
            f"secured with current authentication and encryption standards."
        )
    else:
        severity = "low"
        owasp_id = "A05:2021"
        cwe_id   = "CWE-200"
        confidence = "informational"
        title    = f"Open port {port}/tcp — {service}"
        description = f"Port {port}/tcp is open running {service}."
        recommendation = (
            f"Verify that port {port}/{service} needs to be publicly accessible. "
            f"Close or firewall services that are not required externally."
        )

    if version:
        description += f" Detected version/banner: {version}."
        if severity == "low":
            severity = "medium"
        confidence = "potential"
        recommendation += (
            " Detected version information may assist attackers in identifying "
            "known CVEs. Consider suppressing version banners."
        )

    return {
        "scan_id":    scan_id,
        "asset_id":   asset_id,
        "owner_id":   owner_id,
        "target_url": target,
        "title":      title,
        "severity":   severity,
        "confidence": confidence,
        "source":     "nmap",
        "category":   "Network Exposure",
        "owasp_id":   owasp_id,
        "cwe_id":     cwe_id,
        "description": description,
        "evidence":   {
            "port":    port,
            "service": service,
            "version": version,
            "raw":     raw_line.strip(),
        },
        "ai_analysis": {
            "priority":           severity,
            "problem":            description,
            "impact":             "Exposed services increase the attack surface and may be directly exploitable.",
            "recommendation":     recommendation,
            "verification_steps": [
                f"Confirm whether port {port} needs to be publicly reachable.",
                "Apply firewall/iptables rules to restrict access.",
                "Check for known CVEs for the detected service version.",
                "Re-run Nmap after remediation to verify closure.",
            ],
        },
        "status":     "open",
        "created_at": datetime.now(timezone.utc),
    }


def parse_nmap(
    raw_output: str,
    scan_id: str,
    target: str,
    owner_id: str,
    asset_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse Nmap -sV output text and return a list of findings.

    Findings are classified as 'potential' or 'informational'.
    They represent indicators that require manual validation,
    not confirmed vulnerabilities.
    """
    findings: List[Dict[str, Any]] = []

    for match in PORT_PATTERN.finditer(raw_output):
        port    = match.group(1)
        service = match.group(2)
        version = match.group(3).strip()
        raw_line = match.group(0)

        finding = _make_finding(
            scan_id=scan_id,
            asset_id=asset_id,
            owner_id=owner_id,
            target=target,
            port=port,
            service=service,
            version=version,
            raw_line=raw_line,
        )
        findings.append(finding)

    return findings


def extract_nmap_host_discovery(raw_output: str, target: str) -> Dict[str, Any]:
    """Extract host discovery and open ports table from raw Nmap output."""
    info: Dict[str, Any] = {
        "hostname": target,
        "resolved_ip": "Not Resolved",
        "host_state": "UP",
        "latency": "",
        "open_ports": []
    }
    if not raw_output:
        return info

    ip_match = re.search(r"Nmap scan report for .*?\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", raw_output)
    if ip_match:
        info["resolved_ip"] = ip_match.group(1)
    else:
        ip_direct = re.search(r"Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_output)
        if ip_direct:
            info["resolved_ip"] = ip_direct.group(1)

    state_match = re.search(r"Host is (\w+)(?:\s*\(([^)]+)\))?", raw_output)
    if state_match:
        info["host_state"] = state_match.group(1).upper()
        if state_match.group(2):
            info["latency"] = state_match.group(2)

    for match in PORT_PATTERN.finditer(raw_output):
        port = match.group(1)
        service = match.group(2)
        version = match.group(3).strip()
        info["open_ports"].append({
            "port": f"{port}/tcp",
            "state": "OPEN",
            "service": service,
            "product_version": version or "N/A"
        })

    return info
