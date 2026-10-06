"""
VulnAI Security Finding Correlation, Normalization, and Deduplication Engine.

Transforms raw observations from Nmap, Nikto, Wapiti, SQLMap, Gobuster, and Wappalyzer
into unified, deduplicated findings mapped to OWASP Top 10, CWE, and WSTG.
"""

import re
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
from app.models.finding import UnifiedFinding, FindingVerification

def _canonical_key_for_finding(finding: Dict[str, Any], scanner: str) -> Optional[str]:
    """Determine a canonical key for cross-scanner deduplication."""
    title = str(finding.get("title", "")).lower()
    desc = str(finding.get("description", "")).lower()
    raw = str(finding.get("evidence", {}).get("raw", "")).lower()
    combined = f"{title} {desc} {raw}"

    # Clickjacking / X-Frame-Options
    if any(k in combined for k in ["x-frame-options", "clickjacking", "anti-clickjacking", "frame-ancestors"]):
        return "misconfig:clickjacking_x_frame_options"

    # Content Security Policy (CSP)
    if any(k in combined for k in ["content security policy", "csp", "content-security-policy"]):
        return "misconfig:content_security_policy"

    # HSTS / Unencrypted HTTP
    if any(k in combined for k in ["strict-transport-security", "hsts", "unencrypted channels"]):
        return "crypto:missing_hsts"

    # X-Content-Type-Options / MIME Sniffing
    if any(k in combined for k in ["x-content-type-options", "mime type confusion", "mime-sniff"]):
        return "misconfig:x_content_type_options"

    # Web Server Banner Disclosure
    if any(k in combined for k in ["server banner", "server header", "server:"]):
        return "info:server_banner_disclosure"

    # HTTP TRACE / XST
    if any(k in combined for k in ["trace method", "xst"]):
        return "misconfig:http_trace_enabled"

    # SQL Injection on parameter
    param = finding.get("evidence", {}).get("parameter") or finding.get("parameter")
    if "sql injection" in title and param:
        return f"injection:sqli:{param.lower()}"

    # Fallback: specific to scanner and title/endpoint
    endpoint = finding.get("endpoint") or finding.get("target_url") or "/"
    return f"{scanner}:{title[:50]}:{endpoint}"


CANONICAL_DEFINITIONS = {
    "misconfig:clickjacking_x_frame_options": {
        "title": "Missing Clickjacking Protection (X-Frame-Options)",
        "category": "Security Misconfiguration",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021",
        "wstg": "WSTG-CLNT-09",
        "severity": "low",
        "verification_status": FindingVerification.POTENTIAL,
        "impact": "The application lacks frame embedding restrictions, allowing malicious sites to load it within transparent iframes and execute clickjacking attacks against user sessions.",
        "recommendation": "Configure the X-Frame-Options HTTP response header to 'DENY' or 'SAMEORIGIN', or implement the Content-Security-Policy 'frame-ancestors' directive.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ]
    },
    "misconfig:content_security_policy": {
        "title": "Missing Content Security Policy (CSP)",
        "category": "Security Misconfiguration",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
        "wstg": "WSTG-CONF-07",
        "severity": "low",
        "verification_status": FindingVerification.POTENTIAL,
        "impact": "Absence of a Content-Security-Policy header increases exposure to cross-site scripting (XSS), unauthorized script injection, and clickjacking.",
        "recommendation": "Implement an appropriate Content-Security-Policy response header. Validate the policy against application dependencies before enforcing a restrictive production policy.",
        "references": [
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        ]
    },
    "crypto:missing_hsts": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "category": "Cryptographic Failures",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319",
        "wstg": "WSTG-CONF-07",
        "severity": "low",
        "verification_status": FindingVerification.POTENTIAL,
        "impact": "Without HSTS, initial connections or insecure links may be served over plain HTTP, exposing users to SSL-stripping and man-in-the-middle downgrade attacks.",
        "recommendation": "Configure Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains; preload) on all HTTPS endpoints after confirming full SSL/TLS support.",
        "references": [
            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ]
    },
    "misconfig:x_content_type_options": {
        "title": "Missing X-Content-Type-Options Header",
        "category": "Security Misconfiguration",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
        "wstg": "WSTG-CONF-07",
        "severity": "low",
        "verification_status": FindingVerification.POTENTIAL,
        "impact": "Without the 'nosniff' directive, web browsers may attempt to MIME-sniff response bodies, potentially executing uploaded non-executable files as JavaScript or HTML.",
        "recommendation": "Configure: X-Content-Type-Options: nosniff on all HTTP responses.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ]
    },
    "info:server_banner_disclosure": {
        "title": "Web Server Banner Disclosure",
        "category": "Information Disclosure",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "wstg": "WSTG-INFO-02",
        "severity": "low",
        "verification_status": FindingVerification.INFORMATIONAL,
        "impact": "Disclosing the web server software product and version banner assists threat actors in fingerprinting the attack surface and selecting version-specific exploits.",
        "recommendation": "Configure web server tokens to return generic banners (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
        ]
    },
    "misconfig:http_trace_enabled": {
        "title": "HTTP TRACE Method Enabled (XST Risk)",
        "category": "Security Misconfiguration",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "wstg": "WSTG-CONF-06",
        "severity": "medium",
        "verification_status": FindingVerification.POTENTIAL,
        "impact": "HTTP TRACE echoes request bodies back to the client, which can be leveraged in Cross-Site Tracing (XST) attacks to steal HttpOnly cookies.",
        "recommendation": "Disable the HTTP TRACE method in web server configuration (e.g., TraceEnable off in Apache).",
        "references": [
            "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
        ]
    }
}


def correlate_and_deduplicate_findings(
    raw_findings_by_scanner: Dict[str, List[Dict[str, Any]]],
    scan_id: str,
    target: str,
    asset_id: Optional[str] = None,
    owner_id: Optional[str] = None,
) -> List[UnifiedFinding]:
    """
    Correlates findings across all scanners into unified, deduplicated findings.
    
    If multiple scanners (e.g. Nikto and Wapiti) observe the same issue,
    they are merged into ONE finding with detected_by = ['Nikto', 'Wapiti'],
    combined evidence, and elevated confidence.
    """
    canonical_buckets: Dict[str, Dict[str, Any]] = {}
    finding_counter = 1

    for scanner, findings in raw_findings_by_scanner.items():
        scanner_display = scanner.capitalize()
        for f in findings:
            key = _canonical_key_for_finding(f, scanner)
            if not key:
                key = f"{scanner}_{finding_counter}"

            evidence_entry = {
                "scanner": scanner_display,
                "raw_observation": f.get("title") or f.get("description") or f.get("path"),
                "evidence_data": f.get("evidence", {}),
                "raw_line": f.get("raw_line") or f.get("evidence", {}).get("raw"),
                "raw_output_file": f.get("raw_output_file") or f.get("source") or f"scan-results/{scan_id}/{scanner}.txt",
            }

            if key not in canonical_buckets:
                # Initialize new bucket
                canon_def = CANONICAL_DEFINITIONS.get(key, {})
                title = canon_def.get("title") or f.get("title") or "Security Observation"
                category = canon_def.get("category") or f.get("category") or "Security Misconfiguration"
                owasp = canon_def.get("owasp_category") or f.get("owasp_id") or "A05:2021 - Security Misconfiguration"
                cwe = canon_def.get("cwe") or f.get("cwe_id") or "Not mapped"
                wstg = canon_def.get("wstg") or f.get("wstg_id") or "Not mapped"
                severity = (canon_def.get("severity") or f.get("severity") or "info").lower()
                
                # Check verification status
                status_raw = str(f.get("classification") or f.get("verification_status") or "").upper()
                if status_raw in [FindingVerification.CONFIRMED, FindingVerification.POTENTIAL, FindingVerification.INFORMATIONAL, FindingVerification.INCOMPLETE]:
                    verification = status_raw
                else:
                    verification = canon_def.get("verification_status") or FindingVerification.POTENTIAL

                impact = canon_def.get("impact") or f.get("impact") or f.get("ai_analysis", {}).get("impact", "")
                recommendation = canon_def.get("recommendation") or f.get("recommendation") or f.get("ai_analysis", {}).get("recommendation", "")
                references = list(canon_def.get("references") or f.get("references") or [])

                canonical_buckets[key] = {
                    "id": f"VULNAI-{finding_counter:03d}",
                    "title": title,
                    "description": f.get("description") or title,
                    "target": target,
                    "endpoint": f.get("endpoint") or f.get("path") or "/",
                    "parameter": f.get("parameter"),
                    "severity": severity,
                    "confidence": "MEDIUM",
                    "verification_status": verification,
                    "category": category,
                    "owasp_category": owasp,
                    "cwe": cwe,
                    "wstg": wstg,
                    "detected_by": [scanner_display],
                    "evidence_entries": [evidence_entry],
                    "raw_files": [evidence_entry["raw_output_file"]],
                    "impact": impact,
                    "recommendation": recommendation,
                    "references": references,
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "owner_id": owner_id,
                }
                finding_counter += 1
            else:
                # Merge into existing bucket (CORRELATION & DEDUPLICATION)
                bucket = canonical_buckets[key]
                if scanner_display not in bucket["detected_by"]:
                    bucket["detected_by"].append(scanner_display)
                    # Multi-scanner validation increases confidence!
                    bucket["confidence"] = "HIGH"
                
                bucket["evidence_entries"].append(evidence_entry)
                if evidence_entry["raw_output_file"] not in bucket["raw_files"]:
                    bucket["raw_files"].append(evidence_entry["raw_output_file"])

    # Build UnifiedFinding objects
    correlated: List[UnifiedFinding] = []
    for bucket in canonical_buckets.values():
        combined_evidence = {
            "observations_count": len(bucket["evidence_entries"]),
            "corroborated_by": bucket["detected_by"],
            "details": bucket["evidence_entries"]
        }
        unified = UnifiedFinding(
            id=bucket["id"],
            title=bucket["title"],
            description=bucket["description"],
            target=bucket["target"],
            endpoint=bucket["endpoint"],
            parameter=bucket["parameter"],
            severity=bucket["severity"],
            confidence=bucket["confidence"],
            verification_status=bucket["verification_status"],
            category=bucket["category"],
            owasp_category=bucket["owasp_category"],
            cwe=bucket["cwe"],
            wstg=bucket["wstg"],
            detected_by=bucket["detected_by"],
            evidence=combined_evidence,
            impact=bucket["impact"],
            recommendation=bucket["recommendation"],
            references=bucket["references"],
            raw_evidence_files=bucket["raw_files"],
            scan_id=scan_id,
            asset_id=asset_id,
            owner_id=owner_id
        )
        correlated.append(unified)

    return correlated
