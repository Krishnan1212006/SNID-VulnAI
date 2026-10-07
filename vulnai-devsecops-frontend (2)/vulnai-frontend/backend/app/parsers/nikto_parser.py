"""
Nikto output parser.

Parses Nikto text output into normalized finding dicts for web server configuration,
missing security headers, outdated software, and exposed files.

IMPORTANT: Automated findings are marked as 'potential' or 'informational'.
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
]

COMPILED_IGNORED = [re.compile(p, re.IGNORECASE) for p in IGNORED_PATTERNS]


def _classify_nikto_line(line_text: str) -> Dict[str, Any]:
    lower = line_text.lower()

    if "trace method is active" in lower or "xst" in lower:
        return {
            "title": "HTTP TRACE Method Enabled (XST Risk)",
            "severity": "medium",
            "category": "Security Misconfiguration",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "HTTP TRACE can allow attackers to steal HTTP-only session cookies via Cross-Site Tracing (XST).",
            "recommendation": "Disable the HTTP TRACE method in your web server configuration (e.g., TraceEnable off in Apache)."
        }
    elif "anti-clickjacking" in lower or "x-frame-options" in lower:
        return {
            "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "severity": "low",
            "category": "Security Misconfiguration",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-1021",
            "impact": "Pages can be embedded into third-party iframes, enabling clickjacking attacks.",
            "recommendation": "Configure X-Frame-Options to DENY or SAMEORIGIN, or specify frame-ancestors in Content-Security-Policy."
        }
    elif "x-content-type-options" in lower:
        return {
            "title": "Missing X-Content-Type-Options Header",
            "severity": "low",
            "category": "Security Misconfiguration",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-693",
            "impact": "Browser MIME-sniffing could execute uploaded non-executable files as HTML or JavaScript.",
            "recommendation": "Set X-Content-Type-Options: nosniff header on all HTTP responses."
        }
    elif "strict-transport-security" in lower or "hsts" in lower:
        return {
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "severity": "low",
            "category": "Cryptographic Failures",
            "owasp_id": "A02:2021",
            "cwe_id": "CWE-319",
            "impact": "Connections may be downgraded to unencrypted HTTP via SSL-stripping attacks.",
            "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to HTTPS responses."
        }
    elif "server:" in lower:
        return {
            "title": "Web Server Banner Disclosure",
            "severity": "low",
            "category": "Information Disclosure",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "Revealing the exact server brand and version assists attackers in tailoring version-specific exploits.",
            "recommendation": "Suppress detailed Server headers (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)."
        }
    elif any(k in lower for k in ["osvdb-", "cve-", "vulnerable", "exploit"]):
        return {
            "title": f"Server Vulnerability Indicator: {line_text[:60]}",
            "severity": "high",
            "category": "Vulnerable and Outdated Components",
            "owasp_id": "A06:2021",
            "cwe_id": "CWE-937",
            "impact": "Potential presence of a known software vulnerability or unpatched component.",
            "recommendation": "Check software versions against security advisories and apply latest vendor patches."
        }
    elif any(k in lower for k in ["interesting", "found", "directory indexing", "retrieved"]):
        return {
            "title": f"Potentially Sensitive Endpoint Disclosed: {line_text[:50]}",
            "severity": "medium",
            "category": "Information Disclosure",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "Exposed directories or test files could disclose internal application architecture or credentials.",
            "recommendation": "Remove unused test scripts and restrict access to internal management directories."
        }
    else:
        return {
            "title": f"Web Server Configuration Finding: {line_text[:50]}",
            "severity": "low",
            "category": "Security Misconfiguration",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "impact": "Automated web server scanner flagged a non-standard configuration.",
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
    Parse Nikto text output and return structured findings.
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

        findings.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target_url": target,
            "title": title,
            "severity": meta["severity"],
            "confidence": "potential",
            "source": "nikto",
            "category": meta["category"],
            "owasp_id": meta["owasp_id"],
            "cwe_id": meta["cwe_id"],
            "description": detail_text,
            "evidence": {
                "nikto_finding": detail_text,
                "raw": line_clean
            },
            "ai_analysis": {
                "priority": meta["severity"],
                "problem": detail_text,
                "impact": meta["impact"],
                "recommendation": meta["recommendation"],
                "verification_steps": [
                    "Inspect HTTP response headers using curl -I or browser developer tools.",
                    f"Check web server configuration relating to: {detail_text[:60]}.",
                    "Re-test using Nikto or header validation after applying configuration updates."
                ]
            },
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    return findings
