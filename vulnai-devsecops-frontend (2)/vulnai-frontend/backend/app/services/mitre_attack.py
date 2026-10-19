"""
VulAi MITRE ATT&CK Mapping & Threat Intelligence Engine.

Provides deep mapping of web and network security findings, scanner observations,
and intrusion detections to MITRE ATT&CK Enterprise Tactics, Techniques,
Sub-techniques, Mitigations, and Threat Actors.

Also generates standard MITRE ATT&CK Navigator Layer JSON (spec v4.5/5.0).
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

# Canonical MITRE ATT&CK Enterprise Tactics
MITRE_TACTICS = {
    "TA0043": {"name": "Reconnaissance", "short_name": "reconnaissance"},
    "TA0042": {"name": "Resource Development", "short_name": "resource-development"},
    "TA0001": {"name": "Initial Access", "short_name": "initial-access"},
    "TA0002": {"name": "Execution", "short_name": "execution"},
    "TA0003": {"name": "Persistence", "short_name": "persistence"},
    "TA0004": {"name": "Privilege Escalation", "short_name": "privilege-escalation"},
    "TA0005": {"name": "Defense Evasion", "short_name": "defense-evasion"},
    "TA0006": {"name": "Credential Access", "short_name": "credential-access"},
    "TA0007": {"name": "Discovery", "short_name": "discovery"},
    "TA0008": {"name": "Lateral Movement", "short_name": "lateral-movement"},
    "TA0009": {"name": "Collection", "short_name": "collection"},
    "TA0011": {"name": "Command and Control", "short_name": "command-and-control"},
    "TA0010": {"name": "Exfiltration", "short_name": "exfiltration"},
    "TA0040": {"name": "Impact", "short_name": "impact"},
}

# Detailed Technique Mapping with Mitigations and Threat Actors
TECHNIQUE_CATALOG = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software (e.g. web servers, databases, content management systems).",
        "mitigations": [
            {"id": "M1050", "name": "Exploit Protection", "description": "Deploy Web Application Firewalls (WAF) and input validation."},
            {"id": "M1042", "name": "Disable or Remove Feature", "description": "Disable unnecessary services, endpoints, and outdated modules."},
            {"id": "M1051", "name": "Update Software", "description": "Regularly patch web servers and dependencies against known CVEs."}
        ],
        "threat_groups": ["APT28 (Fancy Bear)", "APT29 (Cozy Bear)", "Lazarus Group", "FIN7", "Volt Typhoon"]
    },
    "T1059.007": {
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "Adversaries may abuse JavaScript (e.g. XSS payloads) to execute arbitrary commands or steal sensitive session cookies in victims' web browsers.",
        "mitigations": [
            {"id": "M1038", "name": "Execution Prevention", "description": "Enforce strict Content Security Policy (CSP) with nonce-based or hash-based controls."},
            {"id": "M1021", "name": "Restrict Web-Based Content", "description": "Sanitize and encode all untrusted inputs prior to rendering in the DOM."}
        ],
        "threat_groups": ["Magecart", "Lazarus Group", "Kimsuky"]
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries may scan network ports and services across remote IP addresses to locate listening daemons and identify reachable attack surface.",
        "mitigations": [
            {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Implement firewall rules to block unauthorized inbound scanning and rate-limit port probes."},
            {"id": "M1035", "name": "Limit Access to Resource", "description": "Restrict sensitive service ports (SSH, DB, Admin) to trusted management subnets or VPNs."}
        ],
        "threat_groups": ["Wizard Spider", "Sandworm Team", "Turla", "APT39"]
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/002/",
        "description": "Adversaries scan public infrastructure with automated tools (e.g. Nikto, Wapiti) to detect unpatched vulnerabilities, default files, and misconfigurations.",
        "mitigations": [
            {"id": "M1056", "name": "Pre-compromise Protection", "description": "Deploy automated attack surface monitoring and patch discovered perimeter vulnerabilities before adversaries exploit them."}
        ],
        "threat_groups": ["APT41", "HAFNIUM", "MuddyWater"]
    },
    "T1595.003": {
        "name": "Active Scanning: Wordlist Scanning",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/003/",
        "description": "Adversaries brute-force URI directories and subdomains using wordlists (e.g. Gobuster, dirb) to uncover hidden admin portals and backup files.",
        "mitigations": [
            {"id": "M1037", "name": "Filter Network Traffic", "description": "Configure rate-limiting and WAF rules to detect and throttle brute-force directory enumerators."}
        ],
        "threat_groups": ["FIN11", "APT33", "Threat Group-3390"]
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "description": "Adversaries search web roots for exposed backup archives, config files, or .env files containing cleartext API keys, passwords, or connection strings.",
        "mitigations": [
            {"id": "M1027", "name": "Password Policies", "description": "Never store cleartext credentials in web-accessible directories; use secrets management vaults."},
            {"id": "M1042", "name": "Disable or Remove Feature", "description": "Block HTTP access to dot-files (.git, .env) and backup extensions (.bak, .old, .sql)."}
        ],
        "threat_groups": ["LAPSUS$", "Scattered Spider", "BlackCat"]
    },
    "T1557": {
        "name": "Adversary-in-the-Middle (AiTM)",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1557/",
        "description": "Adversaries position themselves between targets to intercept, tamper with, or sniff credentials, such as via Rogue Wi-Fi APs or SSL stripping.",
        "mitigations": [
            {"id": "M1041", "name": "Encrypt Sensitive Information", "description": "Enforce HTTP Strict Transport Security (HSTS) with preloading to prevent SSL-stripping."},
            {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Deploy Wireless Intrusion Detection Systems (WIDS) to alert on rogue BSSIDs."}
        ],
        "threat_groups": ["APT28", "Evil Corp", "FIN6"]
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "TA0040",
        "tactic_name": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Adversaries flood the network or wireless layer (e.g. 802.11 Deauthentication bursts) to degrade or deny service to legitimate endpoints.",
        "mitigations": [
            {"id": "M1037", "name": "Filter Network Traffic", "description": "Enable 802.11w Protected Management Frames (PMF) on Wi-Fi networks to cryptographically authenticate management frames."}
        ],
        "threat_groups": ["Sandworm Team", "Killnet", "Anonymous Sudan"]
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
        "description": "Missing browser defense headers (CSP, X-Frame-Options, X-Content-Type-Options) leaves security boundaries disabled, easing client-side exploitation.",
        "mitigations": [
            {"id": "M1050", "name": "Exploit Protection", "description": "Implement standard browser hardening response headers across all HTTP responses."}
        ],
        "threat_groups": ["APT29", "Chimera"]
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
        "description": "Adversaries exploit file upload or remote code execution vulnerabilities to plant web shells (PHP, JSP, ASPX) for persistent server access.",
        "mitigations": [
            {"id": "M1042", "name": "Disable or Remove Feature", "description": "Prevent direct script execution in uploaded file directories and restrict file extensions."}
        ],
        "threat_groups": ["HAFNIUM", "Lazarus Group", "APT41"]
    }
}


def map_finding_to_mitre(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Intelligently maps any scan finding or intrusion alert to its most relevant
    MITRE ATT&CK Technique, Tactic, Mitigations, and Threat Actors.
    """
    title = str(finding.get("title", "")).lower()
    category = str(finding.get("category", "")).lower()
    desc = str(finding.get("description", "")).lower()
    cwe = str(finding.get("cwe", "")).lower()
    owasp = str(finding.get("owasp_category", "")).lower()

    # 1. SQL Injection / Remote Code Execution / Public exploit
    if "sql injection" in title or "sqli" in title or "cwe-89" in cwe:
        tech_id = "T1190"
    elif "xss" in title or "cross-site scripting" in title or "cwe-79" in cwe or "javascript" in title:
        tech_id = "T1059.007"
    elif "clickjacking" in title or "x-frame-options" in title or "content security policy" in title or "x-content-type-options" in title:
        tech_id = "T1562.001"
    elif "hsts" in title or "strict-transport-security" in title or "ssl-stripping" in title or "man-in-the-middle" in title:
        tech_id = "T1557"
    elif "deauth" in title or "wireless intrusion" in title or "denial of service" in title:
        tech_id = "T1498"
    elif "rogue ap" in title or "evil twin" in title:
        tech_id = "T1557"
    elif "open port" in title or "port discovery" in title:
        tech_id = "T1046"
    elif "gobuster" in str(finding.get("detected_by", [])).lower() or "directory" in title or "uri" in title:
        tech_id = "T1595.003"
    elif "backup" in title or "credential" in title or "env file" in title:
        tech_id = "T1552.001"
    elif "nikto" in str(finding.get("detected_by", [])).lower() or "banner" in title or "version disclosure" in title:
        tech_id = "T1595.002"
    else:
        # Default mapping based on OWASP category
        if "a03" in owasp or "injection" in category:
            tech_id = "T1190"
        elif "a02" in owasp or "cryptographic" in category:
            tech_id = "T1557"
        elif "a05" in owasp or "misconfiguration" in category:
            tech_id = "T1562.001"
        else:
            tech_id = "T1595.002"

    tech_info = TECHNIQUE_CATALOG.get(tech_id, TECHNIQUE_CATALOG["T1190"])
    tactic_code = tech_info["tactic"]
    tactic_meta = MITRE_TACTICS.get(tactic_code, {"name": tech_info["tactic_name"], "short_name": "unknown"})

    return {
        "technique_id": tech_id,
        "technique_name": tech_info["name"],
        "tactic_id": tactic_code,
        "tactic_name": tactic_meta["name"],
        "tactic_short_name": tactic_meta["short_name"],
        "url": tech_info["url"],
        "description": tech_info["description"],
        "mitigations": tech_info["mitigations"],
        "threat_groups": tech_info["threat_groups"]
    }


def build_mitre_navigator_layer(
    findings: List[Dict[str, Any]],
    scan_id: str,
    target: str
) -> Dict[str, Any]:
    """
    Generates a valid MITRE ATT&CK Navigator Layer JSON (spec v4.5)
    representing the scan findings mapped across the ATT&CK Matrix.
    Can be directly uploaded to https://mitre-attack.github.io/attack-navigator/
    """
    technique_scores: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        mitre = f.get("mitre_attack") or map_finding_to_mitre(f)
        tech_id = mitre["technique_id"]
        sev = str(f.get("severity", "LOW")).upper()

        weight = 1
        if sev == "CRITICAL":
            weight = 4
        elif sev == "HIGH":
            weight = 3
        elif sev == "MEDIUM":
            weight = 2

        if tech_id not in technique_scores:
            technique_scores[tech_id] = {
                "score": weight,
                "findings": [f.get("title", "Observation")],
                "tactic": mitre.get("tactic_short_name", "initial-access"),
            }
        else:
            technique_scores[tech_id]["score"] = max(technique_scores[tech_id]["score"], weight)
            technique_scores[tech_id]["findings"].append(f.get("title", "Observation"))

    techniques_layer = []
    for tech_id, info in technique_scores.items():
        techniques_layer.append({
            "techniqueID": tech_id,
            "tactic": info["tactic"],
            "score": info["score"],
            "color": "#ef4444" if info["score"] >= 3 else ("#f59e0b" if info["score"] == 2 else "#3b82f6"),
            "comment": f"Triggered by VulnAI findings:\n- " + "\n- ".join(info["findings"][:5]),
            "enabled": True,
            "metadata": [
                {"name": "VulnAI Finding Count", "value": str(len(info["findings"]))}
            ]
        })

    return {
        "name": f"VulnAI Threat Posture - {target}",
        "versions": {
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Automated MITRE ATT&CK assessment layer generated by VulnAI for target {target} (Scan ID: {scan_id}).",
        "filters": {
            "platforms": ["Linux", "Windows", "macOS", "Network", "IaaS"]
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True
        },
        "hideDisabled": False,
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#3b82f6", "#f59e0b", "#ef4444"],
            "minValue": 1,
            "maxValue": 4
        },
        "legendItems": [
            {"label": "Informational / Low Threat", "color": "#3b82f6"},
            {"label": "Medium Exposure / Misconfiguration", "color": "#f59e0b"},
            {"label": "High / Critical Exploit Viability", "color": "#ef4444"}
        ]
    }


def get_mitre_tactics_matrix(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarizes findings by the 14 Enterprise MITRE ATT&CK Tactics.
    """
    tactics_summary: Dict[str, Dict[str, Any]] = {
        code: {
            "id": code,
            "name": meta["name"],
            "short_name": meta["short_name"],
            "techniques": {},
            "total_findings": 0,
            "highest_severity": "INFO",
            "active": False
        }
        for code, meta in MITRE_TACTICS.items()
    }

    sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for f in findings:
        mitre = f.get("mitre_attack") or map_finding_to_mitre(f)
        t_id = mitre["tactic_id"]
        tech_id = mitre["technique_id"]
        sev = str(f.get("severity", "INFO")).upper()

        if t_id in tactics_summary:
            tact = tactics_summary[t_id]
            tact["active"] = True
            tact["total_findings"] += 1
            if sev_order.get(sev, 0) > sev_order.get(tact["highest_severity"], 0):
                tact["highest_severity"] = sev

            if tech_id not in tact["techniques"]:
                tact["techniques"][tech_id] = {
                    "id": tech_id,
                    "name": mitre["technique_name"],
                    "url": mitre["url"],
                    "count": 1,
                    "threat_groups": mitre["threat_groups"],
                    "mitigations": mitre["mitigations"]
                }
            else:
                tact["techniques"][tech_id]["count"] += 1

    active_count = sum(1 for t in tactics_summary.values() if t["active"])
    return {
        "tactics": tactics_summary,
        "active_tactics_count": active_count,
        "total_mapped_techniques": sum(len(t["techniques"]) for t in tactics_summary.values()),
        "generated_at": datetime.now(timezone.utc).isoformat()
    }
