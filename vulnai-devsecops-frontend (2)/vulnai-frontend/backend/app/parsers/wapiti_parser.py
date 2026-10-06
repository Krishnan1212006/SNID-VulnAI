"""
Wapiti output parser.

Parses Wapiti txt scan reports and extracts discovered vulnerabilities
into normalized finding dicts that match the VulnAI schema.

Supports Wapiti 3.x formatted reports (asterisk sections with dashed headers),
legacy vulnerability block reports, and fallback line-based formats.

IMPORTANT: Automated findings are classified as 'potential' and require
manual security verification.
"""

import re
from typing import List, Dict, Any, Optional
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
    "reflected cross site scripting": {
        "severity": "high",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "category": "Injection",
        "impact": "Injected scripts reflected immediately from HTTP request parameters can compromise user sessions."
    },
    "stored cross site scripting": {
        "severity": "high",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "category": "Injection",
        "impact": "Injected scripts permanently stored on the target server can compromise multiple visiting users."
    },
    "html injection": {
        "severity": "medium",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "category": "Injection",
        "impact": "Unencoded user input rendered as HTML can alter page layout, deface site content, or phish users."
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
    "unrestricted file upload": {
        "severity": "critical",
        "owasp": "A04:2021",
        "cwe": "CWE-434",
        "category": "Insecure Design",
        "impact": "Uploading unvalidated files could allow remote command execution or complete server takeover."
    },
    "open redirect": {
        "severity": "medium",
        "owasp": "A01:2021",
        "cwe": "CWE-601",
        "category": "Broken Access Control",
        "impact": "Unvalidated redirects can be used in phishing campaigns to redirect users to malicious domains."
    },
    "inconsistent redirection": {
        "severity": "medium",
        "owasp": "A01:2021",
        "cwe": "CWE-601",
        "category": "Broken Access Control",
        "impact": "Inconsistent HTTP redirect handling may leak sensitive parameters or enable phishing."
    },
    "cross site request forgery": {
        "severity": "medium",
        "owasp": "A01:2021",
        "cwe": "CWE-352",
        "category": "Broken Access Control",
        "impact": "Unauthorized actions may be submitted on behalf of authenticated users without their knowledge."
    },
    "csrf": {
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
    "server side request forgery": {
        "severity": "high",
        "owasp": "A10:2021",
        "cwe": "CWE-918",
        "category": "Server-Side Request Forgery (SSRF)",
        "impact": "Internal systems or cloud metadata services may be accessed via forged server requests."
    },
    "ssrf": {
        "severity": "high",
        "owasp": "A10:2021",
        "cwe": "CWE-918",
        "category": "Server-Side Request Forgery (SSRF)",
        "impact": "Internal systems or cloud metadata services may be accessed via forged server requests."
    },
    "log4shell": {
        "severity": "critical",
        "owasp": "A03:2021",
        "cwe": "CWE-502",
        "category": "Injection",
        "impact": "Remote code execution through unvalidated JNDI lookup expressions in Log4j."
    },
    "spring4shell": {
        "severity": "critical",
        "owasp": "A03:2021",
        "cwe": "CWE-94",
        "category": "Injection",
        "impact": "Arbitrary code execution on systems running Spring Framework via class loader manipulation."
    },
    "subdomain takeover": {
        "severity": "high",
        "owasp": "A05:2021",
        "cwe": "CWE-1059",
        "category": "Security Misconfiguration",
        "impact": "Dangling DNS records allow unauthorized actors to host malicious services on recognized domain names."
    },
    "ns takeover": {
        "severity": "high",
        "owasp": "A05:2021",
        "cwe": "CWE-1059",
        "category": "Security Misconfiguration",
        "impact": "Dangling nameserver records allow third parties to commandeer DNS resolution for the zone."
    },
    "ldap injection": {
        "severity": "high",
        "owasp": "A03:2021",
        "cwe": "CWE-90",
        "category": "Injection",
        "impact": "Unsanitized user inputs may manipulate LDAP queries, bypassing authentication or exposing directory records."
    },
    "content security policy": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-693",
        "category": "Security Misconfiguration",
        "impact": "Missing or weak Content Security Policy increases susceptibility to content injection and cross-site scripting."
    },
    "clickjacking": {
        "severity": "medium",
        "owasp": "A05:2021",
        "cwe": "CWE-1021",
        "category": "Security Misconfiguration",
        "impact": "Missing X-Frame-Options or frame-ancestors directive allows malicious framing and user interface redressing."
    },
    "mime type confusion": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-16",
        "category": "Security Misconfiguration",
        "impact": "Missing X-Content-Type-Options header permits browsers to MIME-sniff response bodies into executable contexts."
    },
    "unencrypted channels": {
        "severity": "medium",
        "owasp": "A02:2021",
        "cwe": "CWE-319",
        "category": "Cryptographic Failures",
        "impact": "Traffic served over plain HTTP without HTTPS redirection exposes sensitive user data to eavesdropping and tampering."
    },
    "http strict transport security": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-319",
        "category": "Security Misconfiguration",
        "impact": "Missing Strict-Transport-Security header leaves users vulnerable to SSL stripping attacks on initial connection."
    },
    "hsts": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-319",
        "category": "Security Misconfiguration",
        "impact": "Missing Strict-Transport-Security header leaves users vulnerable to SSL stripping attacks on initial connection."
    },
    "cleartext submission of password": {
        "severity": "high",
        "owasp": "A02:2021",
        "cwe": "CWE-319",
        "category": "Cryptographic Failures",
        "impact": "User credentials transmitted in plaintext can be intercepted on local networks or intermediate proxies."
    },
    "weak credentials": {
        "severity": "high",
        "owasp": "A07:2021",
        "cwe": "CWE-521",
        "category": "Identification and Authentication Failures",
        "impact": "Default or easily guessable authentication credentials allow unauthorized account compromise."
    },
    "potentially dangerous file": {
        "severity": "medium",
        "owasp": "A05:2021",
        "cwe": "CWE-530",
        "category": "Security Misconfiguration",
        "impact": "Accessible backup files, install scripts, or administration utilities disclose source code or sensitive functions."
    },
    "backup file": {
        "severity": "medium",
        "owasp": "A05:2021",
        "cwe": "CWE-530",
        "category": "Security Misconfiguration",
        "impact": "Exposed backup files (e.g., .bak, .old, .swp) may disclose source code, credentials, or internal configuration."
    },
    "cookie": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-614",
        "category": "Security Misconfiguration",
        "impact": "Cookies missing Secure or HttpOnly flags may be intercepted over plain HTTP or accessed via client-side script."
    },
    "secure flag": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-614",
        "category": "Security Misconfiguration",
        "impact": "Cookie missing Secure attribute may be transmitted unencrypted over cleartext HTTP connections."
    },
    "httponly flag": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-1004",
        "category": "Security Misconfiguration",
        "impact": "Cookie missing HttpOnly attribute can be read by malicious client-side JavaScript."
    },
    "internal server error": {
        "severity": "low",
        "owasp": "A05:2021",
        "cwe": "CWE-209",
        "category": "Security Misconfiguration",
        "impact": "Unhandled exceptions may disclose stack traces, framework versions, or internal file paths."
    },
    "information disclosure": {
        "severity": "low",
        "owasp": "A01:2021",
        "cwe": "CWE-200",
        "category": "Security Misconfiguration",
        "impact": "Sensitive system information, full filesystem paths, or debug outputs disclosed to unauthorized users."
    },
    "tls/ssl misconfigurations": {
        "severity": "medium",
        "owasp": "A02:2021",
        "cwe": "CWE-326",
        "category": "Cryptographic Failures",
        "impact": "Weak TLS ciphers, expired certificates, or obsolete protocol versions undermine transport security."
    },
    "vulnerable software": {
        "severity": "high",
        "owasp": "A06:2021",
        "cwe": "CWE-1035",
        "category": "Vulnerable and Outdated Components",
        "impact": "Outdated software components contain known published vulnerabilities and public exploit vectors."
    },
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


def _build_finding_dict(
    scan_id: str,
    asset_id: str,
    owner_id: str,
    target_url: str,
    title: str,
    v_type: str,
    description: str,
    found_param: str,
    evil_val: str,
    raw_evidence: str,
    wstg_codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    meta = _classify_type(v_type)
    return {
        "scan_id": scan_id,
        "asset_id": asset_id,
        "owner_id": owner_id,
        "target_url": target_url,
        "title": title,
        "severity": meta["severity"],
        "confidence": "potential",
        "source": "wapiti",
        "category": meta["category"],
        "owasp_id": meta["owasp"],
        "cwe_id": meta["cwe"],
        "description": description,
        "evidence": {
            "vulnerability": v_type,
            "endpoint": target_url,
            "parameter": found_param,
            "payload": evil_val,
            "wstg": wstg_codes or [],
            "raw": raw_evidence[:1000].strip(),
        },
        "ai_analysis": {
            "priority": meta["severity"],
            "problem": description,
            "impact": meta["impact"],
            "recommendation": f"Validate and sanitize input for {found_param}. Implement contextual output encoding, security headers, or parameterized queries where applicable.",
            "verification_steps": [
                f"Inspect the reported endpoint: {target_url}",
                f"Test the parameter '{found_param}' with manual payloads to verify reproducibility.",
                "Verify whether backend error messages or unexpected status codes are returned.",
                "Apply framework-level validation or parameterization to resolve."
            ]
        },
        "status": "open",
        "created_at": datetime.now(timezone.utc),
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
    Supports Wapiti 3.x asterisk & dashed headers, legacy block format, and fallback lines.
    """
    findings: List[Dict[str, Any]] = []
    if not raw_output or not raw_output.strip():
        return findings

    # Pattern A: Wapiti 3.x format
    # ********************************************************************************
    # Category Title
    # -------------------------------------
    # Finding content...
    wapiti3_section_pattern = re.compile(
        r"(?:^|\n)\*{20,}\s*\n([^\n]+)\n[-=]{3,}\s*\n(.*?)(?=(?:\n\*{20,}\s*\n[^\n]+\n[-=]{3,}|\Z))",
        re.DOTALL
    )

    w3_matches = list(wapiti3_section_pattern.finditer(raw_output))
    valid_w3_sections = []
    for match in w3_matches:
        category_name = match.group(1).strip()
        cat_lower = category_name.lower()
        if any(skip_word in cat_lower for skip_word in ["summary", "report for", "date of the scan", "crawled pages", "scope of the scan"]):
            continue
        valid_w3_sections.append((category_name, match.group(2).strip()))

    if valid_w3_sections:
        for category_name, body in valid_w3_sections:
            sub_items = [b.strip() for b in re.split(r"\n\s*(?:\*\s*){3,}\s*\n", body) if b.strip()]
            for sub in sub_items:
                # Extract URL
                url_match = re.search(r"(?:for URL:\s*|URL:\s*|url:\s*)(https?://[^\s\n]+)", sub, re.IGNORECASE)
                curl_match = re.search(r'cURL.*?["\'](https?://[^"\']+)["\']', sub, re.IGNORECASE)
                found_url = url_match.group(1).strip() if url_match else (curl_match.group(1).strip() if curl_match else target)

                # Extract Parameter
                param_match = re.search(r"(?:Parameter|Param):\s*([^\n]+)", sub, re.IGNORECASE)
                found_param = param_match.group(1).strip() if param_match else "N/A"

                # Extract Payload / Proof-of-concept
                poc_match = re.search(r'cURL command PoC\s*:\s*"([^"]+)"', sub, re.IGNORECASE)
                evil_match = re.search(r"(?:Evil url|Payload):\s*([^\n]+)", sub, re.IGNORECASE)
                evil_val = poc_match.group(1).strip() if poc_match else (evil_match.group(1).strip() if evil_match else "")

                # Extract WSTG codes
                wstg_match = re.search(r"WSTG code:\s*\[([^\]]+)\]", sub)
                wstg_codes = [code.strip().strip("'\"") for code in wstg_match.group(1).split(",")] if wstg_match else []

                # Extract primary info line
                lines = [l.strip() for l in sub.splitlines() if l.strip()]
                info_line = lines[0] if lines else category_name
                for candidate_line in lines:
                    if not candidate_line.lower().startswith(("wstg code", "evil request", "curl command", "http_request", "get /", "post /")):
                        info_line = candidate_line
                        break

                title = category_name
                if found_param != "N/A":
                    title += f" via '{found_param}'"
                elif info_line and info_line.lower() != category_name.lower():
                    title = f"{category_name}: {info_line[:60]}"

                desc = f"Wapiti detected potential {category_name} on target endpoint {found_url}."
                if info_line and info_line.lower() != category_name.lower():
                    desc += f" Details: {info_line}"
                if found_param != "N/A":
                    desc += f" Parameter: {found_param}."

                findings.append(
                    _build_finding_dict(
                        scan_id=scan_id,
                        asset_id=asset_id,
                        owner_id=owner_id,
                        target_url=found_url,
                        title=title,
                        v_type=category_name,
                        description=desc,
                        found_param=found_param,
                        evil_val=evil_val,
                        raw_evidence=sub,
                        wstg_codes=wstg_codes,
                    )
                )

        return findings

    # Pattern B: Legacy block format
    pattern_block = re.compile(
        r"(?:Vulnerability\s+([^\n:]+)|(?:\*{3}\s*([^\*]+)\s*\*{3}))\s*:\s*\n(.*?)(?=(?:Vulnerability|\*{3}|\Z))",
        re.DOTALL | re.IGNORECASE
    )

    matches = list(pattern_block.finditer(raw_output))
    if matches:
        for match in matches:
            v_type = (match.group(1) or match.group(2) or "Web Anomaly").strip()
            block_content = match.group(3)

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

            findings.append(
                _build_finding_dict(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    owner_id=owner_id,
                    target_url=found_url,
                    title=title,
                    v_type=v_type,
                    description=desc,
                    found_param=found_param,
                    evil_val=evil_val,
                    raw_evidence=block_content,
                )
            )
        return findings

    # Pattern C: Fallback line-based detection
    for line in raw_output.splitlines():
        line_str = line.strip()
        if any(k in line_str.lower() for k in ["vulnerability", "[!]", "warning:"]) and ("found" in line_str.lower() or "injectable" in line_str.lower() or "alert" in line_str.lower()):
            findings.append(
                _build_finding_dict(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    owner_id=owner_id,
                    target_url=target,
                    title=f"Potential Web Anomaly: {line_str[:60]}",
                    v_type=line_str,
                    description=line_str,
                    found_param="N/A",
                    evil_val="",
                    raw_evidence=line_str,
                )
            )

    return findings
