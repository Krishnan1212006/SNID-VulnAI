import asyncio
import httpx
import socket
import urllib.parse
import ipaddress
from datetime import datetime, timezone
from app.core.ids import ObjectId
import ssl
from bs4 import BeautifulSoup
import dns.resolver
from app.services.risk_scoring import compute_scan_risk
from app.services.rule_engine import RuleEngine

class SSRFProtectionError(Exception):
    pass

def validate_url_for_ssrf(url: str, lab_mode: bool = False):
    # Parse URL
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        raise SSRFProtectionError(f"Invalid scheme: {parsed.scheme}. Only http and https are permitted.")
        
    hostname = parsed.hostname
    if not hostname:
        raise SSRFProtectionError("No hostname provided.")
        
    if hostname == "metadata.google.internal":
        raise SSRFProtectionError("Target hostname is restricted by SSRF protection.")
        
    # Resolve IP (this is synchronous and could block, but for simplicity it's ok. In production use aio dns)
    try:
        ip_addr = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_addr)
    except Exception as e:
        raise SSRFProtectionError(f"Could not resolve hostname: {hostname}. Error: {str(e)}")
        
    # Check if IP is private/loopback/reserved
    if str(ip) == "169.254.169.254" or ip.is_link_local:
        raise SSRFProtectionError(f"Target IP {ip_addr} is restricted (link-local/metadata).")
        
    if ip.is_loopback or ip.is_private or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        # In a real app we might allow private targets if 'allow_private_targets' is true in config
        if not lab_mode:
            raise SSRFProtectionError(f"Target IP {ip_addr} is private/internal and restricted by SSRF protection.")
        
    return url

async def run_safe_scan(scan_id: str, db):
    # Fetch scan job
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        return
        
    if scan.get("status") == "cancelled":
        return

    await update_scan_status(db, scan_id, "running", 5)

    asset = await db.assets.find_one({"_id": ObjectId(scan["asset_id"])})
    if not asset:
        await update_scan_status(db, scan_id, "failed", 0)
        return
        
    urls = asset.get("target_urls", [])
    if not urls:
        await update_scan_status(db, scan_id, "failed", 0)
        return

    results = []
    
    try:
        lab_mode = scan.get("lab_mode", False)
        # Validate URLs for SSRF
        valid_urls = []
        for url in urls:
            try:
                valid_url = validate_url_for_ssrf(url, lab_mode=lab_mode)
                valid_urls.append(valid_url)
            except SSRFProtectionError as e:
                results.append({
                    "url": url,
                    "type": "error",
                    "title": "SSRF Blocking",
                    "description": str(e),
                    "severity": "info"
                })
        
        await update_scan_status(db, scan_id, "running", 20)
        
        engine = RuleEngine()
        
        # Run Basic HTTP Headers and Cookies check
        if valid_urls:
            timeout = httpx.Timeout(10.0)
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            
            async with httpx.AsyncClient(timeout=timeout, limits=limits, verify=False) as client:
                for idx, url in enumerate(valid_urls):
                    if await check_if_cancelled(db, scan_id):
                        return
                    
                    progress = 20 + int((idx / len(valid_urls)) * 70)
                    await update_scan_status(db, scan_id, "running", progress)
                    
                    try:
                        response = await client.get(url, follow_redirects=True)
                        headers = response.headers
                        
                        # 1. Missing Security Headers Check
                        if "Strict-Transport-Security" not in headers and url.startswith("https"):
                            results.append(engine.evaluate("HSTS_MISSING", url, {"headers": dict(headers)}))
                        if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
                            results.append(engine.evaluate("X_FRAME_OPTIONS_MISSING", url, {"headers": dict(headers)}))
                        if "X-Content-Type-Options" not in headers:
                            results.append(engine.evaluate("X_CONTENT_TYPE_OPTIONS_MISSING", url, {"headers": dict(headers)}))
                        if "Content-Security-Policy" not in headers:
                            results.append(engine.evaluate("CSP_MISSING", url, {"headers": dict(headers)}))
                            
                        # 2. Cookies
                        for cookie_name, cookie_val in response.cookies.items():
                            # Note: To get secure/httponly flags reliably httpx requires digging into Jar, 
                            # we'll do a simple key check but assume worst if not passed explicitly in headers
                            raw_cookie = headers.get("Set-Cookie", "")
                            if cookie_name in raw_cookie:
                                if url.startswith("https") and "Secure" not in raw_cookie:
                                    results.append(engine.evaluate("COOKIE_NOT_SECURE", url, {"cookie": cookie_name}))
                                if "HttpOnly" not in raw_cookie:
                                    results.append(engine.evaluate("COOKIE_NO_HTTPONLY", url, {"cookie": cookie_name}))

                        # 3. Information Disclosure
                        server_header = headers.get("Server", "")
                        if server_header:
                            results.append(engine.evaluate("SERVER_DISCLOSURE", url, {"Server": server_header}))
                            
                        x_powered_by = headers.get("X-Powered-By", "")
                        if x_powered_by:
                            results.append(engine.evaluate("X_POWERED_BY_DISCLOSURE", url, {"X-Powered-By": x_powered_by}))
                            
                        # 4. CORS
                        cors_resp = await client.options(url, headers={"Origin": "https://evil.local"})
                        allow_origin = cors_resp.headers.get("Access-Control-Allow-Origin", "")
                        if allow_origin == "*":
                            results.append(engine.evaluate("CORS_MISCONFIGURATION", url, {"Access-Control-Allow-Origin": "*"}))

                        # 5. Mixed Content
                        if url.startswith("https") and "text/html" in headers.get("Content-Type", ""):
                            soup = BeautifulSoup(response.text, "html.parser")
                            mixed = []
                            for tag in soup.find_all(src=True):
                                if str(tag["src"]).startswith("http://"):
                                    mixed.append(tag["src"])
                            if mixed:
                                results.append(engine.evaluate("MIXED_CONTENT", url, {"mixed_resources": mixed[:5]}))

                        # 6. OPTIONS Method
                        if "Allow" in cors_resp.headers:
                            results.append(engine.evaluate("OPTIONS_METHOD_ENABLED", url, {"Allow": cors_resp.headers["Allow"]}))
                            
                        # 7. DNS (SPF)
                        parsed_url = urllib.parse.urlparse(url)
                        domain = parsed_url.hostname
                        if domain:
                            try:
                                answers = dns.resolver.resolve(domain, 'TXT')
                                if not any('v=spf1' in str(r) for r in answers):
                                    results.append(engine.evaluate("SPF_MISSING", url, {"domain": domain}))
                            except:
                                results.append(engine.evaluate("SPF_MISSING", url, {"domain": domain}))
                                
                    except Exception as e:
                        results.append({
                            "url": url,
                            "type": "error",
                            "title": "Request Failed",
                            "description": str(e),
                            "severity": "info"
                        })
        
        await update_scan_status(db, scan_id, "completed", 100, results)

    except Exception as e:
        error_result = {"type": "error", "title": "Fatal Exception", "description": str(e), "severity": "critical"}
        results.append(error_result)
        await update_scan_status(db, scan_id, "failed", 0, results)


async def check_if_cancelled(db, scan_id: str) -> bool:
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)}, {"status": 1})
    if scan and scan.get("status") == "cancelled":
        return True
    return False

async def update_scan_status(db, scan_id: str, status: str, progress: int, results: list = None):
    update_data = {
        "status": status,
        "progress": progress
    }
    
    if status in ["completed", "failed"]:
        update_data["ended_at"] = datetime.now(timezone.utc)
        
    if results is not None:
        update_data["results"] = results
        if status == "completed":
            score_data = compute_scan_risk(results)
            update_data["risk_score"] = score_data
        
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": update_data}
    )
    
    if status == "completed" and results:
        # Also store vulnerabilities separately
        scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
        owner_id = scan["owner_id"] if scan else "system"
        asset_id = scan["asset_id"] if scan else "unknown"
        
        vulns = []
        for r in results:
            if "target_url" in r: # From RuleEngine
                vulns.append({
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "owner_id": owner_id,
                    "target_url": r.get("target_url"),
                    "title": r.get("title"),
                    "severity": r.get("severity"),
                    "confidence": r.get("confidence", 1.0),
                    "category": r.get("category", "unknown"),
                    "owasp_id": r.get("owasp_id", "Unknown"),
                    "cwe_id": r.get("cwe_id", "Unknown"),
                    "description": r.get("description", ""),
                    "evidence": r.get("evidence", {}),
                    "ai_analysis": r.get("ai_analysis", {}),
                    "status": "open",
                    "created_at": datetime.now(timezone.utc)
                })
        if vulns:
            await db.vulnerabilities.insert_many(vulns)
