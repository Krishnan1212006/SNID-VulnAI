"""
Gobuster output parser.

Parses Gobuster directory/file discovery output and identifies exposed
endpoints, administration panels, and sensitive files.

IMPORTANT: Automated findings are classified as 'potential' or 'informational'.
Discovered paths alone require manual verification to confirm risk.
"""

import re
from typing import List, Dict, Any
from datetime import datetime, timezone

# Pattern for Gobuster dir output lines:
# /path (Status: 200) [Size: 1234] [--> /target/]
GOBUSTER_LINE = re.compile(
    r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*(\S+)\])?",
    re.MULTILINE
)

# High-risk sensitive files or directories
CRITICAL_PATHS = {
    ".env": "Environment file exposing secrets or credentials",
    ".git": "Git repository metadata exposing source code and commit history",
    ".svn": "SVN repository metadata exposing source code",
    "wp-config": "WordPress configuration file containing database credentials",
    "web.config": "IIS / ASP.NET configuration file",
    "config.php": "Application configuration file",
    "dump.sql": "Database backup or dump file",
    "backup": "Potential archive or backup file",
    "id_rsa": "Private cryptographic key",
    "actuator": "Spring Boot Actuator exposing operational and heap data",
}

# Administrative or sensitive management panels
ADMIN_PATHS = {
    "/admin": "Administrative management portal",
    "/administrator": "Administrative interface",
    "/manager": "Application management console",
    "/phpmyadmin": "Database management interface",
    "/cpanel": "Hosting control panel",
    "/dashboard": "Operational management dashboard",
    "/console": "Interactive console endpoint",
    "/debug": "Debug endpoint",
    "/swagger": "Interactive API documentation",
    "/api-docs": "API schema documentation",
}


def parse_gobuster(
    raw_output: str,
    scan_id: str,
    target: str,
    owner_id: str,
    asset_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse Gobuster text output and return structured findings.
    Prioritizes critical and administrative endpoints; limits noise.
    """
    findings: List[Dict[str, Any]] = []
    if not raw_output or not raw_output.strip():
        return findings

    base_url = target.rstrip("/")
    discovered_routes = []

    for match in GOBUSTER_LINE.finditer(raw_output):
        path = match.group(1).strip()
        status_code = match.group(2).strip()
        size = match.group(3) or "unknown"
        redirect_to = match.group(4) or ""

        clean_path = path if path.startswith("/") else f"/{path}"
        full_url = f"{base_url}{clean_path}"
        path_lower = clean_path.lower()

        # Check for critical / exposed secrets
        is_critical = False
        for crit_key, crit_desc in CRITICAL_PATHS.items():
            if crit_key in path_lower:
                is_critical = True
                findings.append({
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "owner_id": owner_id,
                    "target_url": full_url,
                    "title": f"Sensitive file or repository exposed: {clean_path}",
                    "severity": "high",
                    "confidence": "potential",
                    "source": "gobuster",
                    "category": "Information Disclosure",
                    "owasp_id": "A05:2021",
                    "cwe_id": "CWE-538",
                    "description": f"Gobuster discovered potentially sensitive file/path '{clean_path}' (HTTP {status_code}, {size} bytes). {crit_desc}.",
                    "evidence": {
                        "path": clean_path,
                        "url": full_url,
                        "status_code": status_code,
                        "size": size,
                        "redirect": redirect_to,
                        "raw": match.group(0)
                    },
                    "ai_analysis": {
                        "priority": "high",
                        "problem": f"Sensitive file '{clean_path}' appears accessible externally.",
                        "impact": "Exposure of environment files, source code repositories, or backups allows attackers to retrieve secrets, API keys, and internal logic.",
                        "recommendation": f"Block public access to {clean_path} in web server configuration (e.g., Nginx deny all or Apache FilesMatch directive).",
                        "verification_steps": [
                            f"Send a request to {full_url} to confirm if the response returns sensitive contents.",
                            "Configure web server rules to deny requests to hidden files and known sensitive extensions."
                        ]
                    },
                    "status": "open",
                    "created_at": datetime.now(timezone.utc),
                })
                break

        if is_critical:
            continue

        # Check for administrative panels
        is_admin = False
        for adm_key, adm_desc in ADMIN_PATHS.items():
            if adm_key in path_lower:
                is_admin = True
                findings.append({
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "owner_id": owner_id,
                    "target_url": full_url,
                    "title": f"Management endpoint discovered: {clean_path}",
                    "severity": "medium",
                    "confidence": "informational",
                    "source": "gobuster",
                    "category": "Broken Access Control",
                    "owasp_id": "A01:2021",
                    "cwe_id": "CWE-200",
                    "description": f"Discovered endpoint '{clean_path}' (HTTP {status_code}). {adm_desc}.",
                    "evidence": {
                        "path": clean_path,
                        "url": full_url,
                        "status_code": status_code,
                        "size": size,
                        "redirect": redirect_to,
                        "raw": match.group(0)
                    },
                    "ai_analysis": {
                        "priority": "medium",
                        "problem": f"Administrative or internal interface '{clean_path}' is accessible.",
                        "impact": "Exposed management interfaces can be targeted for credential stuffing, brute force, or default credential attacks.",
                        "recommendation": "Restrict administrative interfaces by IP whitelisting or VPN access. Enforce multi-factor authentication (MFA).",
                        "verification_steps": [
                            f"Confirm if {full_url} requires authentication.",
                            "Verify whether access can be limited to internal management IP ranges."
                        ]
                    },
                    "status": "open",
                    "created_at": datetime.now(timezone.utc),
                })
                break

        if not is_admin:
            discovered_routes.append({
                "path": clean_path,
                "status_code": status_code,
                "size": size,
                "url": full_url
            })

    # Summary finding for general discovered paths if any were found
    if discovered_routes:
        sample_paths = [r["path"] for r in discovered_routes[:10]]
        findings.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target_url": target,
            "title": f"Discovered {len(discovered_routes)} Accessible Endpoints",
            "severity": "low",
            "confidence": "informational",
            "source": "gobuster",
            "category": "Information Disclosure",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "description": (
                f"Directory brute-forcing identified {len(discovered_routes)} endpoints on the target. "
                f"Sample routes: {', '.join(sample_paths)}."
            ),
            "evidence": {
                "total_routes_found": len(discovered_routes),
                "routes_sample": discovered_routes[:20]
            },
            "ai_analysis": {
                "priority": "low",
                "problem": f"Endpoint enumeration discovered {len(discovered_routes)} active routes.",
                "impact": "Enumerated URLs reveal the site directory structure and additional attack surface.",
                "recommendation": "Review all enumerated paths to ensure only intended public endpoints are exposed.",
                "verification_steps": [
                    "Audit the listed routes against your API and web application inventory."
                ]
            },
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    return findings


def parse_gobuster_observations(raw_output: str) -> List[Dict[str, Any]]:
    """Parse Gobuster hits as unverified observations, not vulnerabilities."""
    observations: List[Dict[str, Any]] = []
    if not isinstance(raw_output, str) or not raw_output.strip():
        return observations

    for line_number, line in enumerate(raw_output.splitlines(), start=1):
        raw_line = line.strip()
        match = GOBUSTER_LINE.match(raw_line)
        if not match or match.group(0).strip() != raw_line:
            continue

        try:
            status_code = int(match.group(2))
            response_size = int(match.group(3)) if match.group(3) is not None else None
        except ValueError:
            continue
        if not 100 <= status_code <= 599:
            continue

        path = match.group(1)
        if not path.startswith("/"):
            path = f"/{path}"

        observations.append({
            "id": f"gobuster-{line_number}",
            "scanner": "gobuster",
            "source": "scan-results/gobuster.txt",
            "path": path,
            "title": f"Gobuster discovered {path}",
            "status_code": status_code,
            "response_size": response_size,
            "method": None,
            "redirect_to": match.group(4),
            "severity": "informational",
            "classification": "informational",
            "status": "unverified",
            "verification_status": "unverified",
            "message": raw_line,
            "raw_line": raw_line,
        })

    return observations
