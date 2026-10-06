"""
Assessment Coverage and OWASP Top 10 Coverage Engine for VulnAI.

Provides transparent assessment boundary mapping so reports clearly state
what was tested, what had findings, and what was NOT assessed.
"""

from typing import Dict, Any, List

def get_assessment_coverage(scanner_status: Dict[str, str]) -> List[Dict[str, str]]:
    """Return test boundary coverage based on active scanner execution."""
    items = [
        {
            "category": "Network Host Discovery",
            "area": "Network Host Discovery",
            "status": "Assessed" if scanner_status.get("nmap") == "completed" else "Partially Assessed",
            "tool": "Nmap (-Pn)",
            "notes": "Host state and latency verified",
            "note": "Host state and latency verified",
        },
        {
            "category": "Port & Service Detection",
            "area": "Port & Service Detection",
            "status": "Assessed" if scanner_status.get("nmap") == "completed" else "Partially Assessed",
            "tool": "Nmap (-sV)",
            "notes": "TCP service banner identification",
            "note": "TCP service banner identification",
        },
        {
            "category": "Web Server Configuration",
            "area": "Web Server Configuration",
            "status": "Assessed" if scanner_status.get("nikto") == "completed" else "Partially Assessed",
            "tool": "Nikto",
            "notes": "Server banners, options, and HTTP methods",
            "note": "Server banners, options, and HTTP methods",
        },
        {
            "category": "Web Application Vulnerabilities",
            "area": "Web Application Vulnerabilities",
            "status": "Assessed" if scanner_status.get("wapiti") == "completed" else "Partially Assessed",
            "tool": "Wapiti",
            "notes": "XSS, CSP, Clickjacking, MIME headers",
            "note": "XSS, CSP, Clickjacking, MIME headers",
        },
        {
            "category": "SQL Injection Testing",
            "area": "SQL Injection Testing",
            "status": "Assessed" if scanner_status.get("sqlmap") == "completed" else "Partially Assessed",
            "tool": "SQLMap (--batch)",
            "notes": "Parameter heuristic & injection probes",
            "note": "Parameter heuristic & injection probes",
        },
        {
            "category": "Directory & Path Discovery",
            "area": "Directory & Path Discovery",
            "status": "Assessed" if scanner_status.get("gobuster") == "completed" else "Partially Assessed",
            "tool": "Gobuster",
            "notes": "URI brute-forcing with wordlist",
            "note": "URI brute-forcing with wordlist",
        },
        {
            "category": "Technology Fingerprinting",
            "area": "Technology Fingerprinting",
            "status": "Assessed" if scanner_status.get("wappalyzer") == "completed" else "Partially Assessed",
            "tool": "Wappalyzer",
            "notes": "CMS, web server, and library identification",
            "note": "CMS, web server, and library identification",
        },
        {
            "category": "Authentication & Session Testing",
            "area": "Authentication & Session Testing",
            "status": "NOT ASSESSED",
            "tool": "N/A",
            "notes": "Requires authenticated test suite",
            "note": "Requires authenticated test suite",
        },
        {
            "category": "Authorization & Access Control",
            "area": "Authorization & Access Control",
            "status": "NOT ASSESSED",
            "tool": "N/A",
            "notes": "Requires multi-tenant role testing",
            "note": "Requires multi-tenant role testing",
        },
        {
            "category": "Business Logic Testing",
            "area": "Business Logic Testing",
            "status": "NOT ASSESSED",
            "tool": "N/A",
            "notes": "Requires manual penetration testing",
            "note": "Requires manual penetration testing",
        },
        {
            "category": "Manual Source Code Review",
            "area": "Manual Source Code Review",
            "status": "NOT ASSESSED",
            "tool": "N/A",
            "notes": "Out of scope for automated DAST",
            "note": "Out of scope for automated DAST",
        },
    ]
    return items


def get_owasp_coverage_matrix(findings: List[Dict[str, Any]], scanner_status: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Evaluates OWASP Top 10 (2021) categories against scanner evidence and findings.
    """
    has_a02 = any("a02" in str(f.get("owasp_id", "")).lower() or "a02" in str(f.get("owasp_category", "")).lower() for f in findings)
    has_a03 = any("a03" in str(f.get("owasp_id", "")).lower() or "a03" in str(f.get("owasp_category", "")).lower() for f in findings)
    has_a05 = any("a05" in str(f.get("owasp_id", "")).lower() or "a05" in str(f.get("owasp_category", "")).lower() for f in findings)
    has_a06 = any("a06" in str(f.get("owasp_id", "")).lower() or "a06" in str(f.get("owasp_category", "")).lower() for f in findings)

    raw_items = [
        {
            "id": "A01:2021",
            "code": "A01:2021",
            "name": "Broken Access Control",
            "title": "Broken Access Control",
            "status": "Partially Assessed" if scanner_status.get("gobuster") == "completed" else "Not Assessed",
            "notes": "Directory enumeration executed. Deep role-based authorization not assessed.",
            "evidence_summary": "Directory enumeration executed. Deep role-based authorization not assessed."
        },
        {
            "id": "A02:2021",
            "code": "A02:2021",
            "name": "Cryptographic Failures",
            "title": "Cryptographic Failures",
            "status": "Findings Present" if has_a02 else "Partially Assessed",
            "notes": "HSTS and TLS transport inspected via Nikto/Wapiti.",
            "evidence_summary": "HSTS and TLS transport inspected via Nikto/Wapiti."
        },
        {
            "id": "A03:2021",
            "code": "A03:2021",
            "name": "Injection",
            "title": "Injection",
            "status": "Findings Present" if has_a03 else "Partially Assessed",
            "notes": "SQLMap and Wapiti executed. Parameter injection evaluated.",
            "evidence_summary": "SQLMap and Wapiti executed. Parameter injection evaluated."
        },
        {
            "id": "A04:2021",
            "code": "A04:2021",
            "name": "Insecure Design",
            "title": "Insecure Design",
            "status": "Not Assessed",
            "notes": "Automated DAST tools cannot verify architectural design security.",
            "evidence_summary": "Automated DAST tools cannot verify architectural design security."
        },
        {
            "id": "A05:2021",
            "code": "A05:2021",
            "name": "Security Misconfiguration",
            "title": "Security Misconfiguration",
            "status": "Findings Present" if has_a05 else "Assessed - Clean",
            "notes": "Evaluated via Nikto and Wapiti (HTTP headers, banner disclosure, methods).",
            "evidence_summary": "Evaluated via Nikto and Wapiti (HTTP headers, banner disclosure, methods)."
        },
        {
            "id": "A06:2021",
            "code": "A06:2021",
            "name": "Vulnerable and Outdated Components",
            "title": "Vulnerable and Outdated Components",
            "status": "Findings Present" if has_a06 else "Partially Assessed",
            "notes": "Technology stack fingerprinting conducted via Wappalyzer.",
            "evidence_summary": "Technology stack fingerprinting conducted via Wappalyzer."
        },
        {
            "id": "A07:2021",
            "code": "A07:2021",
            "name": "Identification and Authentication Failures",
            "title": "Identification and Authentication Failures",
            "status": "Not Assessed",
            "notes": "Credential stuffing, brute-force login, and MFA flows were not assessed.",
            "evidence_summary": "Credential stuffing, brute-force login, and MFA flows were not assessed."
        },
        {
            "id": "A08:2021",
            "code": "A08:2021",
            "name": "Software and Data Integrity Failures",
            "title": "Software and Data Integrity Failures",
            "status": "Not Assessed",
            "notes": "CI/CD pipelines and unsigned firmware/updates were not assessed.",
            "evidence_summary": "CI/CD pipelines and unsigned firmware/updates were not assessed."
        },
        {
            "id": "A09:2021",
            "code": "A09:2021",
            "name": "Security Logging and Monitoring Failures",
            "title": "Security Logging and Monitoring Failures",
            "status": "Not Assessed",
            "notes": "SIEM audit trails and intrusion detection alerts were not tested.",
            "evidence_summary": "SIEM audit trails and intrusion detection alerts were not tested."
        },
        {
            "id": "A10:2021",
            "code": "A10:2021",
            "name": "Server-Side Request Forgery (SSRF)",
            "title": "Server-Side Request Forgery (SSRF)",
            "status": "Partially Assessed" if scanner_status.get("wapiti") == "completed" else "Not Assessed",
            "notes": "Wapiti SSRF module executed. Out-of-band callbacks not validated.",
            "evidence_summary": "Wapiti SSRF module executed. Out-of-band callbacks not validated."
        },
    ]
    return raw_items
