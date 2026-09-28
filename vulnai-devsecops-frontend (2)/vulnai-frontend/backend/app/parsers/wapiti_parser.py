"""
Wapiti output parser.

Parses Wapiti txt scan reports and extracts discovered vulnerabilities
into normalized finding dicts that match the VulnAI schema.

IMPORTANT: Automated findings are classified as 'potential' and require
manual security verification.
"""

import re
from typing import List, Dict, Any
from datetime import datetime, timezone

VULN_TYPE_MAP = {
    "sql injection": {
        "severity": "high",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "category": "Injection",
        "impact": "Unsanitized database queries may allow attackers to extract, modify, or delete sensitive data."
    },
    "blind sql injection": {
        "severity": "critical",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "category": "Injection",
        "impact": "Blind SQL injection may allow full extraction of database contents and database server compromise."
    },
    "command execution": {
        "severity": "critical",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "category": "Injection",
        "impact": "Operating system commands may be executed in the context of the web server process."
    },
    "cross site scripting": {
        "severity": "high",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "category": "Injection",
        "impact": "Malicious scripts executed in the browser of victim users could steal session tokens or perform actions on their behalf."
    },
    "file handling": {
        "severity": "high",
        "owasp": "A01:2021",
        "cwe": "CWE-22",
        "category": "Broken Access Control",
        "impact": "Arbitrary file inclusion or path traversal could expose sensitive system files or lead to code execution."
    },
    "path traversal": {
        "severity": "high",
        "owasp": "A01:2021",
        "cwe": "CWE-22",
        "category": "Broken Access Control",
        "impact": "Access to files outside the web root may disclose configuration credentials and system secrets."
    },
    "open redirect": {
        "severity": "medium",
        "owasp": "A01:2021",
        "cwe": "CWE-601",
        "category": "Broken Access Control",
        "impact": "Unvalidated redirects can be used in phishing campaigns to redirect users to malicious domains."
    },
    "cross site request forgery": {
        "severity": "medium",
        "owasp": "A01:2021",
        "cwe": "CWE-352",
        "category": "Broken Access Control",
        "impact": "Unauthorized actions may be submitted on behalf of authenticated users without their knowledge."
    },
    "crlf injection": {
        "severity": "medium",
        "owasp": "A03:2021",
        "cwe": "CWE-113",
        "category": "Injection",
        "impact": "HTTP response splitting can allow cache poisoning, session fixation, and XSS."
    },
    "internal server error": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-209",
        "category": "Security Misconfiguration",
        "impact": "Unhandled exceptions may disclose stack traces, framework versions, or internal file paths."
    },
    "cookie": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-614",
        "category": "Security Misconfiguration",
        "impact": "Cookies missing Secure or HttpOnly flags may be intercepted over plain HTTP or accessed via client-side script."
    },
    "content security policy": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-693",
        "category": "Security Misconfiguration",
        "impact": "Missing or weak CSP increases susceptibility to content injection and XSS."
    }
}


def _classify_type(vuln_name: str) -> Dict[str, str]:
    lower = vuln_name.lower().strip()
    for key, val in VULN_TYPE_MAP.items():
        if key in lower:
            return val
    return {
        "severity": "medium",
        "owasp": "A05:2021",
        "cwe": "CWE-200",
        "category": "Web Application Security",
        "impact": "Automated security scanner reported an anomaly that may indicate a vulnerability."
    }


def parse_wapiti(
    raw_output: str,
    scan_id: str,
    target: str,
    owner_id: str,
    asset_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse Wapiti raw text output and return normalized findings.
    Handles both section-based blocks and line-by-line format.
    """
    findings: List[Dict[str, Any]] = []
    if not raw_output or not raw_output.strip():
        return findings

    # Look for blocks starting with 'Vulnerability ...' or '*** ... ***'
    # Pattern 1: Vulnerability <Type>
    pattern_block = re.compile(
        r"(?:Vulnerability\s+([^\n:]+)|(?:\*{3}\s*([^\*]+)\s*\*{3}))\s*:\s*\n(.*?)(?=(?:Vulnerability|\*{3}|\Z))",
        re.DOTALL | re.IGNORECASE
    )

    matches = list(pattern_block.finditer(raw_output))

    if matches:
        for match in matches:
            v_type = (match.group(1) or match.group(2) or "Web Anomaly").strip()
            block_content = match.group(3)

            meta = _classify_type(v_type)

            # Extract details
            url_match = re.search(r"(?:Url|URL):\s*([^\n]+)", block_content)
            param_match = re.search(r"(?:Parameter|Param):\s*([^\n]+)", block_content)
            evil_match = re.search(r"(?:Evil url|Payload):\s*([^\n]+)", block_content)

            found_url = url_match.group(1).strip() if url_match else target
            found_param = param_match.group(1).strip() if param_match else "N/A"
            evil_val = evil_match.group(1).strip() if evil_match else ""

            title = f"{v_type}"
            if found_param != "N/A":
                title += f" via '{found_param}'"

            desc = f"Wapiti detected potential {v_type} on target endpoint {found_url}."
            if found_param != "N/A":
                desc += f" Parameter: {found_param}."

            findings.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "owner_id": owner_id,
                "target_url": found_url,
                "title": title,
                "severity": meta["severity"],
                "confidence": "potential",
                "source": "wapiti",
                "category": meta["category"],
                "owasp_id": meta["owasp"],
                "cwe_id": meta["cwe"],
                "description": desc,
                "evidence": {
                    "vulnerability": v_type,
                    "endpoint": found_url,
                    "parameter": found_param,
                    "payload": evil_val,
                    "raw": block_content[:600].strip(),
                },
                "ai_analysis": {
                    "priority": meta["severity"],
                    "problem": desc,
                    "impact": meta["impact"],
                    "recommendation": f"Validate and sanitize input for {found_param}. Implement contextual output encoding and parameterized queries where applicable.",
                    "verification_steps": [
                        f"Inspect the vulnerable endpoint: {found_url}",
                        f"Test the parameter '{found_param}' with manual payloads to verify reproducibility.",
                        "Verify whether backend error messages or unexpected status codes are returned.",
                        "Apply framework-level validation or parameterization to resolve."
                    ]
                },
                "status": "open",
                "created_at": datetime.now(timezone.utc),
            })
    else:
        # Fallback line-based detection (e.g. "[!] Vulnerability XSS in http://...")
        for line in raw_output.splitlines():
            line_str = line.strip()
            if any(k in line_str.lower() for k in ["vulnerability", "[!]", "warning:"]) and ("found" in line_str.lower() or "injectable" in line_str.lower() or "alert" in line_str.lower()):
                meta = _classify_type(line_str)
                findings.append({
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "owner_id": owner_id,
                    "target_url": target,
                    "title": f"Potential Web Anomaly: {line_str[:60]}",
                    "severity": meta["severity"],
                    "confidence": "potential",
                    "source": "wapiti",
                    "category": meta["category"],
                    "owasp_id": meta["owasp"],
                    "cwe_id": meta["cwe"],
                    "description": line_str,
                    "evidence": {
                        "raw": line_str
                    },
                    "ai_analysis": {
                        "priority": meta["severity"],
                        "problem": line_str,
                        "impact": meta["impact"],
                        "recommendation": "Review the flagged web application response and verify whether security controls are in place.",
                        "verification_steps": [
                            "Review application logs for anomalies at the reported time.",
                            "Manually verify the input vectors in a staging environment."
                        ]
                    },
                    "status": "open",
                    "created_at": datetime.now(timezone.utc),
                })

    return findings
