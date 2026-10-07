"""
Nikto output parser for VulnAI / SNID.

Parses Nikto text output into normalized finding dicts for web server configuration,
missing security headers, outdated software, and exposed files.

CRITICAL RULE:
Categorizes results line by line into:
- server information (severity: info, status: informational)
- security header observation (severity: low, status: potential)
- HTTP method observation (severity: medium, status: potential)
- interesting file (severity: info, status: informational)
- configuration issue (severity: medium, status: potential)
- potential vulnerability (severity: high, status: potential)
- confirmed vulnerability (severity: high/critical, status: confirmed)

DO NOT convert every Nikto line into a vulnerability.
Informational banners and header disclosures must NOT cause risk score deductions.
"""

import re
from typing import List, Dict, Any
from datetime import datetime, timezone

# Filter out standard metadata lines
IGNORED_PATTERNS = [
    r"^-\s*Nikto",
    r"^\+\s*Target IP",
    r"^\+\s*Target Hostname",
    r"^\+\s*Target Port",
    r"^\+\s*Start Time",
    r"^\+\s*End Time",
    r"^-{5,}",
    r"^\+\s*\d+\s+host\(s\)\s+tested",
    r"^\+\s*No web server found",
    r"^\+\s*No CGI Directories found",
    r"^\+\s*ERROR:",
    r"^-\s*STATUS:",
    r"^\+\s*Scan terminated:",
    r"^\+\s*SSL Info:",
    r"^\+\s*Platform:",
    r"^\+\s*Ciphers:",
    r"^\+\s*Issuer:",
    r"^\+\s*SAN:",
    r"^\+\s*CN:",
]

COMPILED_IGNORED = [re.compile(p, re.IGNORECASE) for p in IGNORED_PATTERNS]


def _classify_nikto_line(line_text: str) -> Dict[str, Any]:
    """
    Parse and classify a single Nikto output line into its appropriate category
    and semantic status.
    """
    # Strip Nikto 2.6 ID prefix like "[013587] /: "
    cleaned = re.sub(r"^\[\d+\]\s*[^:]*:\s*", "", line_text).strip()
    lower = cleaned.lower()

    # 1. Server Information / Non-critical headers / Disclosures (INFORMATIONAL)
    if any(k in lower for k in [
        "retrieved via header",
        "link header",
        "alt-svc header",
        "uncommon header",
        "x-redirect-by",
        "x-litespeed",
        "robots.txt contains",
        "server banner",
        "server:",
    ]):
        if "server:" in lower:
            title = "Web Server Banner Disclosure"
            desc = f"Server header disclosed: {cleaned}"
        elif "robots.txt" in lower:
            title = "Robots.txt File Disclosed"
            desc = f"Robots.txt entry observed: {cleaned}"
        elif "link header" in lower:
            title = "HTTP Link Header Disclosed"
            desc = f"HTTP Link header observed: {cleaned}"
        else:
            title = f"Server Header Information: {cleaned[:45]}"
            desc = f"Observed HTTP header: {cleaned}"

        return {
            "title": title,
            "category": "server information",
            "severity": "info",
            "status": "informational",
            "verification_status": "INFORMATIONAL",
            "confidence": 90,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "Disclosed HTTP headers provide server architecture reconnaissance information.",
            "recommendation": "Review response headers and consider removing non-essential headers."
        }

    # 2. Security Header Observations (LOW severity, POTENTIAL status)
    if "content-security-policy" in lower or "missing: csp" in lower:
        return {
            "title": "Missing Content Security Policy (CSP)",
            "category": "security header observation",
            "severity": "low",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 85,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-1021",
            "impact": "Absence of a Content Security Policy increases risk of Cross-Site Scripting (XSS) and data injection.",
            "recommendation": "Define a Content-Security-Policy response header restricting authorized sources of content."
        }
    elif "anti-clickjacking" in lower or "x-frame-options" in lower:
        return {
            "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "category": "security header observation",
            "severity": "low",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 85,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-1021",
            "impact": "Pages can be embedded into third-party iframes, enabling clickjacking attacks.",
            "recommendation": "Configure X-Frame-Options to DENY or SAMEORIGIN, or specify frame-ancestors in Content-Security-Policy."
        }
    elif "x-content-type-options" in lower:
        return {
            "title": "Missing X-Content-Type-Options Header",
            "category": "security header observation",
            "severity": "low",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 85,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-693",
            "impact": "Browser MIME-sniffing could execute uploaded non-executable files as HTML or JavaScript.",
            "recommendation": "Set X-Content-Type-Options: nosniff header on all HTTP responses."
        }
    elif "strict-transport-security" in lower or "hsts" in lower:
        return {
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "category": "security header observation",
            "severity": "low",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 85,
            "owasp_id": "A02:2021",
            "cwe_id": "CWE-319",
            "impact": "Connections may be downgraded to unencrypted HTTP via SSL-stripping attacks.",
            "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to HTTPS responses."
        }

    # 3. HTTP Method Observations (MEDIUM severity, POTENTIAL status)
    if "trace method is active" in lower or "xst" in lower:
        return {
            "title": "HTTP TRACE Method Enabled (XST Risk)",
            "category": "HTTP method observation",
            "severity": "medium",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 90,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "HTTP TRACE can allow attackers to steal HTTP-only session cookies via Cross-Site Tracing (XST).",
            "recommendation": "Disable the HTTP TRACE method in your web server configuration."
        }

    # 4. Configuration Issues (MEDIUM severity)
    if "directory indexing" in lower or "indexing found" in lower:
        return {
            "title": "Directory Indexing Enabled",
            "category": "configuration issue",
            "severity": "medium",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 85,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-548",
            "impact": "Exposed directory listing allows attackers to enumerate files, backups, and source assets.",
            "recommendation": "Disable directory indexing in the web server configuration (e.g. Options -Indexes in Apache)."
        }

    # 5. Potential / Confirmed Vulnerability
    if any(k in lower for k in ["osvdb-", "cve-", "vulnerable", "exploit"]):
        cve_match = re.search(r"CVE-\d{4}-\d+", cleaned)
        cve_id = cve_match.group(0) if cve_match else None
        return {
            "title": f"Server Vulnerability Indicator: {cleaned[:60]}",
            "category": "potential vulnerability",
            "severity": "high",
            "status": "potential",
            "verification_status": "POTENTIAL",
            "confidence": 85,
            "cve_id": cve_id,
            "owasp_id": "A06:2021",
            "cwe_id": "CWE-937",
            "impact": "Potential presence of a known software vulnerability or unpatched component.",
            "recommendation": "Check software versions against security advisories and apply latest vendor patches."
        }

    # 6. Interesting File Discovery (INFORMATIONAL)
    if any(k in lower for k in ["interesting", "found", "retrieved"]):
        return {
            "title": f"Interesting File Observation: {cleaned[:50]}",
            "category": "interesting file",
            "severity": "info",
            "status": "informational",
            "verification_status": "INFORMATIONAL",
            "confidence": 75,
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "Discovered non-standard file or path during reconnaissance.",
            "recommendation": "Verify whether this file or path should be publicly accessible."
        }

    # 7. Fallback Configuration Observation (INFORMATIONAL)
    return {
        "title": f"Server Configuration Observation: {cleaned[:50]}",
        "category": "configuration issue",
        "severity": "info",
        "status": "informational",
        "verification_status": "INFORMATIONAL",
        "confidence": 70,
        "owasp_id": "A05:2021",
        "cwe_id": "CWE-200",
        "impact": "Automated web server scanner flagged a non-standard configuration line.",
        "recommendation": "Review the server configuration and verify against security hardening guidelines."
    }


def parse_nikto(
    raw_output: str,
    scan_id: str,
    target: str,
    owner_id: str,
    asset_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse Nikto text output line by line and return structured findings.
    """
    findings: List[Dict[str, Any]] = []
    if not raw_output or not raw_output.strip():
        return findings

    seen_titles = set()

    raw_lines = []
    for chunk in raw_output.splitlines():
        if "+ " in chunk:
            for sp in re.split(r'(?=\+\s+)', chunk):
                sp_clean = sp.strip()
                if sp_clean:
                    raw_lines.append(sp_clean)
        else:
            chunk_clean = chunk.strip()
            if chunk_clean:
                raw_lines.append(chunk_clean)

    for line_clean in raw_lines:
        if not line_clean.startswith("+"):
            continue

        # Skip banner / metadata lines
        if any(pat.search(line_clean) for pat in COMPILED_IGNORED):
            continue

        detail_text = line_clean.lstrip("+").strip()
        if not detail_text:
            continue

        meta = _classify_nikto_line(detail_text)
        title = meta["title"]
        if title in seen_titles:
            continue
        seen_titles.add(title)

        endpoint_match = re.search(r"^\s*(\/[^\s:]*)", detail_text)
        endpoint = endpoint_match.group(1) if endpoint_match else "/"

        findings.append({
            "id": f"nikto-{len(findings) + 1}",
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target": target,
            "target_url": target,
            "endpoint": endpoint,
            "tool": "nikto",
            "source": "nikto",
            "title": title,
            "category": meta["category"],
            "severity": meta["severity"],
            "confidence": meta.get("confidence", 85),
            "status": meta.get("status", "potential"),
            "verification_status": meta.get("verification_status", "POTENTIAL"),
            "owasp_id": meta["owasp_id"],
            "cwe_id": meta["cwe_id"],
            "cve": meta.get("cve_id"),
            "description": detail_text,
            "evidence": {
                "raw_line": line_clean,
                "detail": detail_text,
                "category": meta["category"]
            },
            "recommendation": meta["recommendation"],
            "impact": meta["impact"],
            "detected_by": ["Nikto"],
            "raw_reference": f"nikto.txt:{len(findings) + 1}",
            "created_at": datetime.now(timezone.utc),
        })

    return findings
