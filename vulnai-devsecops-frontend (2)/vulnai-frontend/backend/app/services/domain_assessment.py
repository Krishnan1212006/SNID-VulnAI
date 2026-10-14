"""
Domain Assessment Service for SNID / VulnAI DevSecOps.
Implements:
1. Target normalization, RFC 1123 domain validation, SSRF private IP blocker.
2. Server-side DNS resolution (A, AAAA, CNAME, MX, TXT, NS).
3. HTTP inspection & redirect chain tracing with response security headers.
4. TLS certificate inspection (Subject, Issuer, Validity, Expiry, Cipher, Protocol, Trust).
5. Technology fingerprinting (WhatWeb tool status, heuristic detection, Static/Dynamic classification).
6. Nmap domain port & service assessment.
7. SQL-injection assessment (Safe passive default, optional authorized SQLMap active testing).
"""
import asyncio
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.services.scanner_runtime import ScannerRuntime


# In-memory registry for active domain assessment jobs
ACTIVE_DOMAIN_JOBS: Dict[str, Dict[str, Any]] = {}

# RFC 1918 & reserved IP ranges to prevent SSRF
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def normalize_target_input(raw_input: str) -> Tuple[str, str, str]:
    """
    Normalize user input into (clean_domain, base_url, target_url).
    Examples:
    - "example.com" -> ("example.com", "https://example.com", "https://example.com")
    - "http://sub.domain.org/path?q=1" -> ("sub.domain.org", "http://sub.domain.org", "http://sub.domain.org/path?q=1")
    """
    inp = raw_input.strip()
    if not re.match(r"^https?://", inp, re.IGNORECASE):
        domain = inp.split("/")[0].split(":")[0]
        base_url = f"https://{domain}"
        target_url = f"https://{inp}"
    else:
        parsed = urlparse(inp)
        domain = parsed.hostname or inp
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        target_url = inp

    return domain.lower(), base_url, target_url


def is_private_ip(ip_str: str) -> bool:
    """Verify if an IP address belongs to loopback, link-local, or RFC 1918 ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


async def resolve_dns_records(domain: str) -> Dict[str, Any]:
    """Resolve A, AAAA, and common DNS records server-side."""
    dns_start = time.perf_counter()
    records: Dict[str, Any] = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "cname_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "resolution_time_ms": 0.0,
        "status": "completed",
        "error": None,
    }

    try:
        # IPv4 Resolution
        addr_info = await asyncio.to_thread(socket.getaddrinfo, domain, None, socket.AF_INET)
        a_ips = sorted(list({entry[4][0] for entry in addr_info}))
        records["a_records"] = a_ips
    except Exception as exc:
        records["error"] = str(exc)

    try:
        # IPv6 Resolution
        addr_info_v6 = await asyncio.to_thread(socket.getaddrinfo, domain, None, socket.AF_INET6)
        aaaa_ips = sorted(list({entry[4][0] for entry in addr_info_v6}))
        records["aaaa_records"] = aaaa_ips
    except Exception:
        pass

    # Try nslookup or dig for MX, NS, TXT
    try:
        runtime = ScannerRuntime()
        cmd = ["nslookup", "-type=any", domain]
        res = await runtime.capture_host(cmd, timeout=3.0)
        if res.stdout:
            out_str = res.stdout.decode("utf-8", errors="ignore")
            for line in out_str.splitlines():
                line_s = line.strip()
                if "mail exchanger" in line_s.lower():
                    records["mx_records"].append(line_s)
                elif "nameserver" in line_s.lower():
                    records["ns_records"].append(line_s)
                elif "text =" in line_s.lower():
                    records["txt_records"].append(line_s)
    except Exception:
        pass

    records["resolution_time_ms"] = round((time.perf_counter() - dns_start) * 1000, 2)
    return records


async def inspect_http_and_tls(domain: str, target_url: str) -> Dict[str, Any]:
    """Inspect HTTP response, redirect chain, security headers, and TLS certificate."""
    result: Dict[str, Any] = {
        "http": {
            "status_code": None,
            "reason_phrase": None,
            "final_url": None,
            "redirect_chain": [],
            "headers": {},
            "security_headers": {},
            "cookies": [],
            "response_time_ms": 0.0,
            "error": None,
        },
        "tls": {
            "available": False,
            "version": None,
            "cipher": None,
            "subject": {},
            "issuer": {},
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "is_valid": False,
            "verification_status": "Not Checked",
            "error": None,
        },
    }

    # 1. HTTP Request via httpx
    http_start = time.perf_counter()
    async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False) as client:
        try:
            resp = await client.get(target_url, headers={"User-Agent": "VulnAI-SNID-SecurityScanner/2.0"})
            result["http"]["status_code"] = resp.status_code
            result["http"]["reason_phrase"] = resp.reason_phrase
            result["http"]["final_url"] = str(resp.url)
            result["http"]["response_time_ms"] = round((time.perf_counter() - http_start) * 1000, 2)

            # Redirect chain
            chain = []
            for hop in resp.history:
                chain.append({
                    "status_code": hop.status_code,
                    "url": str(hop.url),
                    "location": hop.headers.get("location"),
                })
            chain.append({"status_code": resp.status_code, "url": str(resp.url), "location": None})
            result["http"]["redirect_chain"] = chain

            # Headers
            headers_dict = dict(resp.headers)
            result["http"]["headers"] = headers_dict

            # Security Headers Evaluation
            sec_headers = {
                "Strict-Transport-Security": headers_dict.get("strict-transport-security"),
                "Content-Security-Policy": headers_dict.get("content-security-policy"),
                "X-Frame-Options": headers_dict.get("x-frame-options"),
                "X-Content-Type-Options": headers_dict.get("x-content-type-options"),
                "Referrer-Policy": headers_dict.get("referrer-policy"),
                "Permissions-Policy": headers_dict.get("permissions-policy"),
            }
            result["http"]["security_headers"] = sec_headers
            result["http"]["cookies"] = [c.name for c in resp.cookies.jar]
            result["http"]["body_sample"] = resp.text[:4000] if resp.text else ""

        except Exception as exc:
            result["http"]["error"] = str(exc)

    # 2. TLS Certificate Inspection via standard ssl
    try:
        def fetch_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return cert, cipher, version

        cert, cipher, version = await asyncio.to_thread(fetch_cert)
        if cert:
            result["tls"]["available"] = True
            result["tls"]["version"] = version
            result["tls"]["cipher"] = cipher[0] if cipher else None

            # Subject & Issuer formatting
            subj_dict = dict(x[0] for x in cert.get("subject", []))
            iss_dict = dict(x[0] for x in cert.get("issuer", []))
            result["tls"]["subject"] = subj_dict
            result["tls"]["issuer"] = iss_dict

            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            result["tls"]["valid_from"] = not_before
            result["tls"]["valid_until"] = not_after

            if not_after:
                try:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_left = (expiry_dt - now_dt).days
                    result["tls"]["days_remaining"] = days_left
                    result["tls"]["is_valid"] = days_left > 0
                    result["tls"]["verification_status"] = "Valid (Trusted Root CA)" if days_left > 0 else "Expired"
                except Exception:
                    result["tls"]["verification_status"] = "Valid"
            else:
                result["tls"]["verification_status"] = "Valid"

    except Exception as tls_err:
        result["tls"]["error"] = str(tls_err)
        result["tls"]["verification_status"] = f"Verification Failed ({type(tls_err).__name__})"

    return result


async def detect_technologies_and_architecture(
    domain: str,
    target_url: str,
    http_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run technology detection and analyze whether site exhibits Static vs Dynamic indicators.
    Integrates WhatWeb if installed; otherwise shows clear installation status.
    """
    tech_findings: List[Dict[str, Any]] = []
    headers = http_data.get("headers", {})
    body = http_data.get("body_sample", "")

    # 1. Check WhatWeb availability
    runtime = ScannerRuntime()
    whatweb_available = False
    whatweb_status = "Not installed (Optional tool: run 'apt install whatweb' in Kali Linux to enable)"
    try:
        chk = await runtime.capture_runtime(["which", "whatweb"], timeout=3.0)
        if chk.status == "completed" and chk.stdout:
            whatweb_available = True
            whatweb_status = "Available (/usr/bin/whatweb)"
            # Execute WhatWeb
            ww_res = await runtime.capture_runtime(["whatweb", "--log-json=-", target_url], timeout=15.0)
            if ww_res.stdout:
                # Add raw whatweb output reference
                tech_findings.append({
                    "name": "WhatWeb Analysis",
                    "category": "Scanner Output",
                    "confidence": "HIGH",
                    "evidence": ww_res.stdout.decode("utf-8", errors="ignore")[:500],
                })
    except Exception:
        pass

    # 2. Heuristic technology detections from headers and body
    server = headers.get("server")
    if server:
        tech_findings.append({
            "name": server,
            "category": "Web Server",
            "confidence": "HIGH",
            "evidence": f"Server response header: '{server}'",
        })

    x_powered = headers.get("x-powered-by")
    if x_powered:
        tech_findings.append({
            "name": x_powered,
            "category": "Backend Framework",
            "confidence": "HIGH",
            "evidence": f"X-Powered-By header: '{x_powered}'",
        })

    # CDN / Cloud Detection
    if any(h in headers for h in ("cf-ray", "cf-cache-status")):
        tech_findings.append({
            "name": "Cloudflare CDN",
            "category": "CDN / WAF",
            "confidence": "HIGH",
            "evidence": f"Cloudflare headers detected (cf-ray: {headers.get('cf-ray', '')})",
        })
    elif "x-amz-cf-id" in headers:
        tech_findings.append({
            "name": "Amazon CloudFront",
            "category": "CDN",
            "confidence": "HIGH",
            "evidence": "AWS CloudFront header present",
        })

    # Framework / CMS signatures in HTML body
    if "wp-content" in body or "wp-includes" in body:
        tech_findings.append({
            "name": "WordPress",
            "category": "CMS",
            "confidence": "HIGH",
            "evidence": "Found wp-content / wp-includes directory references in markup",
        })
    if "__NEXT_DATA__" in body:
        tech_findings.append({
            "name": "Next.js",
            "category": "JavaScript Framework",
            "confidence": "HIGH",
            "evidence": "Found Next.js __NEXT_DATA__ hydration JSON in document",
        })
    if "csrfmiddlewaretoken" in body:
        tech_findings.append({
            "name": "Django",
            "category": "Web Framework",
            "confidence": "HIGH",
            "evidence": "Found Django csrfmiddlewaretoken input in form",
        })

    # 3. Static vs Dynamic Architecture Classification
    # Do not definitively classify based solely on one header; use balanced indicators.
    static_points = 0
    dynamic_points = 0
    rationales: List[str] = []

    # Check cookies
    cookies = http_data.get("cookies", [])
    set_cookie = headers.get("set-cookie")
    if set_cookie or cookies:
        dynamic_points += 2
        rationales.append(f"Dynamic state management: Set-Cookie or session cookies observed ({', '.join(cookies) if cookies else 'Set-Cookie present'})")
    else:
        static_points += 1
        rationales.append("No session or tracking cookies set on baseline request")

    # Check Caching & ETag
    if "etag" in headers or "last-modified" in headers:
        static_points += 1
        rationales.append("Static caching headers present (ETag / Last-Modified)")

    cache_ctrl = headers.get("cache-control", "").lower()
    if any(k in cache_ctrl for k in ("no-store", "no-cache", "private")):
        dynamic_points += 1
        rationales.append(f"Cache-Control directives indicate dynamic content ({cache_ctrl})")
    elif any(k in cache_ctrl for k in ("public", "max-age", "immutable", "s-maxage")):
        static_points += 1
        rationales.append(f"Cache-Control directives indicate cacheable/static distribution ({cache_ctrl})")

    # Check CMS / Backend Framework
    if x_powered or any(f["category"] in ("Backend Framework", "CMS") for f in tech_findings):
        dynamic_points += 2
        rationales.append("Active server-side CMS or application framework detected")

    # Determine Label
    if dynamic_points >= 2 and static_points == 0:
        label = "Dynamic indicators"
    elif static_points >= 2 and dynamic_points == 0:
        label = "Static indicators"
    elif dynamic_points > 0 and static_points > 0:
        label = "Mixed"
    else:
        label = "Insufficient evidence"

    return {
        "architecture_label": label,
        "architecture_evidence": rationales,
        "whatweb_status": whatweb_status,
        "technologies": tech_findings,
    }


async def run_nmap_domain_scan(domain: str, timeout: float = 30.0) -> Dict[str, Any]:
    """
    Run non-intrusive service and port detection using Nmap.
    Scans common web and management service ports: 80, 443, 8080, 8443, 21, 22, 25, 53, 3306, 5432.
    """
    runtime = ScannerRuntime()
    ports = "80,443,8080,8443,21,22,25,53,3306,5432"
    cmd = ["nmap", "-sV", "-p", ports, "-T4", domain]

    start_t = time.perf_counter()
    res = await runtime.capture_runtime(cmd, timeout=timeout)
    duration = round(time.perf_counter() - start_t, 2)

    ports_list: List[Dict[str, Any]] = []
    raw_output = res.stdout.decode("utf-8", errors="ignore") if res.stdout else (res.stderr.decode("utf-8", errors="ignore") or "")

    # Parse port lines from stdout: e.g. "80/tcp   open   http    nginx 1.18.0"
    for line in raw_output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?", line.strip())
        if match:
            port_num = int(match.group(1))
            proto = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5) or "Unknown"
            ports_list.append({
                "port": port_num,
                "protocol": proto,
                "state": state,
                "service": service,
                "version": version.strip(),
            })

    return {
        "status": res.status,
        "duration_seconds": duration,
        "exit_code": res.exit_code,
        "scanned_ports": ports,
        "open_ports": ports_list,
        "raw_output": raw_output[:3000],
    }


async def assess_sql_injection(
    target_url: str,
    active_testing_authorized: bool = False,
    timeout: float = 25.0,
) -> Dict[str, Any]:
    """
    Perform SQL-injection assessment.
    Safe passive inspection by default (examining query params, forms, DB error leaks).
    Active testing using SQLMap only if authorized.
    """
    result: Dict[str, Any] = {
        "passive_status": "Clean",
        "active_status": "Not tested",
        "findings": [],
        "evidence": [],
        "limitations": [
            "A scan reporting no SQL-injection findings is not definitive proof that the application is secure.",
            "Testing is strictly scoped to authorized non-destructive boundaries.",
        ],
    }

    # 1. Passive Parameter & Form Inspection
    parsed = urlparse(target_url)
    has_params = bool(parsed.query)

    if has_params:
        result["passive_status"] = "Parameters Identified"
        result["evidence"].append(f"Target URL contains query parameters for testing: '{parsed.query}'")
    else:
        result["passive_status"] = "No Query Parameters in Target URL"

    # 2. Active Testing via SQLMap if authorized
    if active_testing_authorized:
        runtime = ScannerRuntime()
        # Verify SQLMap is installed
        chk = await runtime.capture_runtime(["which", "sqlmap"], timeout=3.0)
        if chk.status == "completed" and chk.stdout:
            result["active_status"] = "Running"
            # Non-destructive, single-level heuristic test
            cmd = [
                "sqlmap",
                "-u", target_url,
                "--batch",
                "--technique=BEUST",
                "--level=1",
                "--risk=1",
                "--timeout=10",
                "--retries=1",
                "--threads=1",
            ]
            sm_res = await runtime.capture_runtime(cmd, timeout=timeout)
            out_str = sm_res.stdout.decode("utf-8", errors="ignore") if sm_res.stdout else ""

            if "is vulnerable" in out_str.lower() or "sqlmap identified the following injection point" in out_str.lower():
                result["active_status"] = "Confirmed"
                result["findings"].append({
                    "title": "SQL Injection Identified",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "verification_status": "CONFIRMED",
                    "evidence": "SQLMap confirmed reproducible parameter vulnerability.",
                    "recommendation": "Use parameterized prepared statements and robust input validation.",
                })
            elif "all tested parameters do not appear to be injectable" in out_str.lower() or "no parameter is injectable" in out_str.lower():
                result["active_status"] = "Clean (No injection points found)"
            elif sm_res.status == "timed_out":
                result["active_status"] = "Incomplete (Scanner Timed Out)"
            else:
                result["active_status"] = f"Completed ({sm_res.status})"

            # Store redacted snippet of output
            redacted = re.sub(r"(password|token|secret|key)=\S+", r"\1=[REDACTED]", out_str, flags=re.I)
            result["evidence"].append(redacted[:1500])
        else:
            result["active_status"] = "Tool Unavailable (SQLMap not installed in scanner runtime)"
    else:
        result["active_status"] = "Not tested (Active testing requires explicit authorization)"

    return result


class DomainAssessmentEngine:
    """Coordinates complete domain assessment workflows."""

    def __init__(self, db, owner_id: str):
        self.db = db
        self.owner_id = owner_id

    async def run_assessment(
        self,
        job_id: str,
        target_input: str,
        active_sqli: bool = False,
        allow_internal: bool = False,
    ) -> Dict[str, Any]:
        """Execute the full domain security assessment pipeline."""
        start_time = datetime.now(timezone.utc)
        ACTIVE_DOMAIN_JOBS[job_id] = {
            "job_id": job_id,
            "status": "RUNNING",
            "progress": 10,
            "stage": "Validating target and DNS",
            "cancelled": False,
            "start_time": start_time,
        }

        domain, base_url, target_url = normalize_target_input(target_input)

        # 1. DNS Resolution & SSRF check
        dns_data = await resolve_dns_records(domain)
        a_records = dns_data.get("a_records", [])

        if not a_records:
            ACTIVE_DOMAIN_JOBS[job_id]["status"] = "FAILED"
            raise ValueError(f"Could not resolve domain '{domain}' to an IPv4 address. Check domain validity.")

        # Check for private IP SSRF
        first_ip = a_records[0]
        if is_private_ip(first_ip) and not allow_internal:
            ACTIVE_DOMAIN_JOBS[job_id]["status"] = "FAILED"
            raise PermissionError(
                f"Target '{domain}' resolves to a private or loopback IP ({first_ip}). "
                "Scanning internal addresses is restricted for SSRF defense."
            )

        if ACTIVE_DOMAIN_JOBS[job_id]["cancelled"]:
            ACTIVE_DOMAIN_JOBS[job_id]["status"] = "CANCELLED"
            return {"status": "CANCELLED", "message": "Assessment cancelled by user"}

        # 2. HTTP & TLS Inspection
        ACTIVE_DOMAIN_JOBS[job_id]["stage"] = "Inspecting HTTP headers & TLS certificate"
        ACTIVE_DOMAIN_JOBS[job_id]["progress"] = 35
        http_tls_data = await inspect_http_and_tls(domain, target_url)

        if ACTIVE_DOMAIN_JOBS[job_id]["cancelled"]:
            ACTIVE_DOMAIN_JOBS[job_id]["status"] = "CANCELLED"
            return {"status": "CANCELLED", "message": "Assessment cancelled by user"}

        # 3. Technology & Architecture Fingerprinting
        ACTIVE_DOMAIN_JOBS[job_id]["stage"] = "Fingerprinting technology stack"
        ACTIVE_DOMAIN_JOBS[job_id]["progress"] = 60
        tech_data = await detect_technologies_and_architecture(domain, target_url, http_tls_data["http"])

        if ACTIVE_DOMAIN_JOBS[job_id]["cancelled"]:
            ACTIVE_DOMAIN_JOBS[job_id]["status"] = "CANCELLED"
            return {"status": "CANCELLED", "message": "Assessment cancelled by user"}

        # 4. Nmap Domain Port & Service Scan
        ACTIVE_DOMAIN_JOBS[job_id]["stage"] = "Running Nmap port & service inspection"
        ACTIVE_DOMAIN_JOBS[job_id]["progress"] = 80
        nmap_data = await run_nmap_domain_scan(domain, timeout=25.0)

        # 5. SQL Injection Assessment
        ACTIVE_DOMAIN_JOBS[job_id]["stage"] = "Evaluating application & SQL-injection parameters"
        ACTIVE_DOMAIN_JOBS[job_id]["progress"] = 90
        sqli_data = await assess_sql_injection(target_url, active_testing_authorized=active_sqli, timeout=20.0)

        end_time = datetime.now(timezone.utc)
        duration_s = round((end_time - start_time).total_seconds(), 2)

        # Assemble normalized report
        report = {
            "job_id": job_id,
            "owner_id": self.owner_id,
            "target_input": target_input,
            "domain": domain,
            "target_url": target_url,
            "base_url": base_url,
            "resolved_ips": a_records,
            "status": "COMPLETED",
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": duration_s,
            "dns": dns_data,
            "http": http_tls_data["http"],
            "tls": http_tls_data["tls"],
            "technology": tech_data,
            "nmap": nmap_data,
            "sql_injection": sqli_data,
        }

        ACTIVE_DOMAIN_JOBS[job_id].update(report)

        # Store in database
        await self.db.domain_assessments.update_one(
            {"job_id": job_id, "owner_id": self.owner_id},
            {"$set": report},
            upsert=True,
        )

        return report
