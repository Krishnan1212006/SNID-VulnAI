"""
SQLMap output parser.

Parses SQLMap text output and extracts discovered SQL injection vulnerabilities
and database fingerprinting information into normalized finding dicts.

IMPORTANT: Automated findings are marked as 'potential' or 'informational'.
"""

import re
from typing import List, Dict, Any
from datetime import datetime, timezone

# Pattern to capture parameter injection point blocks
# Parameter: <name> (<method>)
#     Type: <type>
#     Title: <title>
#     Payload: <payload>
PARAM_BLOCK_PATTERN = re.compile(
    r"Parameter:\s+([^\(\n]+)(?:\s*\(([A-Z]+)\))?\s*\n"
    r"(?:\s+Type:\s+([^\n]+)\s*\n)?"
    r"(?:\s+Title:\s+([^\n]+)\s*\n)?"
    r"(?:\s+Payload:\s+([^\n]+))?",
    re.MULTILINE
)

# Pattern for heuristic detection
HEURISTIC_PATTERN = re.compile(
    r"heuristic \(basic\) test shows that\s+([^\n]+?)\s+might be injectable",
    re.IGNORECASE
)

# Pattern for DBMS detection
DBMS_PATTERN = re.compile(
    r"back-end DBMS:\s*([^\n]+)",
    re.IGNORECASE
)


def parse_sqlmap(
    raw_output: str,
    scan_id: str,
    target: str,
    owner_id: str,
    asset_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse SQLMap text output and return structured findings.
    """
    findings: List[Dict[str, Any]] = []
    if not raw_output or not raw_output.strip():
        return findings

    seen_params = set()

    # 1. Parse confirmed injection points
    for match in PARAM_BLOCK_PATTERN.finditer(raw_output):
        param_name = match.group(1).strip()
        method     = match.group(2) or "GET/POST"
        inj_type   = (match.group(3) or "SQL Injection").strip()
        title      = (match.group(4) or f"SQL Injection in {param_name}").strip()
        payload    = (match.group(5) or "").strip()

        key = f"{param_name}:{inj_type}"
        if key in seen_params:
            continue
        seen_params.add(key)

        findings.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target_url": target,
            "title": f"SQL Injection ({inj_type}) in parameter '{param_name}'",
            "severity": "critical",
            "confidence": "potential",
            "source": "sqlmap",
            "category": "Injection",
            "owasp_id": "A03:2021",
            "cwe_id": "CWE-89",
            "description": (
                f"SQLMap identified an injection point in parameter '{param_name}' "
                f"using {method} requests. Injection technique: {inj_type}. "
                f"Vector title: {title}."
            ),
            "evidence": {
                "parameter": param_name,
                "method": method,
                "type": inj_type,
                "title": title,
                "payload": payload,
                "raw": match.group(0).strip()
            },
            "ai_analysis": {
                "priority": "critical",
                "problem": f"Parameter '{param_name}' appears vulnerable to SQL injection ({inj_type}).",
                "impact": "Attackers can manipulate backend SQL queries to read confidential records, bypass authentication, modify databases, or execute administrative commands.",
                "recommendation": "Use parameterized queries (prepared statements) or Object-Relational Mapping (ORM) with parameterized input. Never concatenate user input directly into SQL statements.",
                "verification_steps": [
                    f"Review database query code handling parameter '{param_name}'.",
                    "Verify if dynamic query concatenation or string formatting is used.",
                    "Replace raw SQL queries with prepared statements.",
                    "Re-run SQLMap or manual test cases to verify the parameter is properly parameterized."
                ]
            },
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    # 2. Heuristic check (if no confirmed injection points found)
    if not findings:
        heuristic_match = HEURISTIC_PATTERN.search(raw_output)
        if heuristic_match:
            detail = heuristic_match.group(1).strip()
            findings.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "owner_id": owner_id,
                "target_url": target,
                "title": f"Potential SQL Injection Indicator: {detail}",
                "severity": "high",
                "confidence": "potential",
                "source": "sqlmap",
                "category": "Injection",
                "owasp_id": "A03:2021",
                "cwe_id": "CWE-89",
                "description": f"SQLMap basic heuristic test indicates that {detail} might be injectable.",
                "evidence": {
                    "heuristic_indicator": detail,
                    "raw": heuristic_match.group(0)
                },
                "ai_analysis": {
                    "priority": "high",
                    "problem": f"Heuristic analysis suggests potential vulnerability in {detail}.",
                    "impact": "If verified, SQL injection could allow unauthorized database access.",
                    "recommendation": "Conduct targeted code review and manual verification on this parameter.",
                    "verification_steps": [
                        f"Check source code handling {detail}.",
                        "Verify whether user input is sanitized and parameterized."
                    ]
                },
                "status": "open",
                "created_at": datetime.now(timezone.utc),
            })

    # 3. Back-end DBMS Fingerprint
    dbms_match = DBMS_PATTERN.search(raw_output)
    if dbms_match:
        dbms_info = dbms_match.group(1).strip()
        findings.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "owner_id": owner_id,
            "target_url": target,
            "title": f"Database Fingerprint Disclosed: {dbms_info}",
            "severity": "low",
            "confidence": "informational",
            "source": "sqlmap",
            "category": "Information Disclosure",
            "owasp_id": "A05:2021",
            "cwe_id": "CWE-200",
            "description": f"SQLMap successfully fingerprinted the backend database management system: {dbms_info}.",
            "evidence": {
                "dbms": dbms_info,
                "raw": dbms_match.group(0)
            },
            "ai_analysis": {
                "priority": "low",
                "problem": f"Backend database management system detected as {dbms_info}.",
                "impact": "Exposed DBMS fingerprint helps attackers tailor DBMS-specific exploitation payloads.",
                "recommendation": "Suppress detailed database error messages and remove identifying headers.",
                "verification_steps": [
                    "Ensure generic error pages are shown to end users instead of raw database errors."
                ]
            },
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        })

    return findings


def extract_sqlmap_assessment(raw_output: str) -> Dict[str, Any]:
    """Evaluate SQLMap assessment outcome accurately."""
    if not raw_output or not raw_output.strip():
        return {
            "status": "SQLMap did not produce output",
            "injection_confirmed": False,
            "summary": "Assessment could not be completed."
        }

    lower = raw_output.lower()
    if PARAM_BLOCK_PATTERN.search(raw_output):
        return {
            "status": "SQL Injection Confirmed",
            "injection_confirmed": True,
            "summary": "One or more injectable parameters were validated."
        }
    elif "all tested parameters do not appear to be injectable" in lower or "does not appear to be injectable" in lower:
        return {
            "status": "No confirmed SQL injection identified",
            "injection_confirmed": False,
            "summary": "SQLMap tested parameters and found no confirmed SQL injection vulnerabilities."
        }
    else:
        return {
            "status": "No confirmed SQL injection identified",
            "injection_confirmed": False,
            "summary": "Tested target; no active SQL injection vectors validated."
        }
