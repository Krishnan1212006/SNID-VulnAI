import pytest
from app.parsers.nmap_parser import parse_nmap, parse_nmap_full, extract_nmap_host_discovery, NmapParser
from app.services.risk_scoring import compute_scan_risk

REFERENCE_NMAP_TEXT = """
# Nmap 7.98 scan initiated Wed Apr 15 10:00:00 2026 as: nmap --privileged -sC -sV -O -p- target
Nmap scan report for laudea.acetcbe.edu.in (13.233.180.106)
Host is up (0.045s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-redirect:
|_  https://laudea.acetcbe.edu.in/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: LAUDEA
| ssl-cert: Subject: commonName=laudea.acetcbe.edu.in
| Subject Alternative Name: DNS:laudea.acetcbe.edu.in
| Not valid before: 2026-03-17T00:00:00
|_Not valid after:  2026-06-15T23:59:59
Device type: general purpose
Running: Oracle VirtualBox, AT&T, QEMU
OS CPE: cpe:/a:oracle:virtualbox cpe:/o:qemu:qemu
Aggressive OS guesses: Oracle VirtualBox Slirp NAT bridge (97%), AT&T BGW210 voice gateway (95%), QEMU user mode network gateway (93%)
OS details: Oracle VirtualBox Slirp NAT bridge (97%), AT&T BGW210 voice gateway (95%), QEMU user mode network gateway (93%)

Nmap done: 1 IP address (1 host up) scanned in 362.49 seconds
"""

REFERENCE_NMAP_HTML = """
<!DOCTYPE html>
<html>
<head><title>Nmap Scan Report - laudea.acetcbe.edu.in</title></head>
<body>
<h1>Nmap Scan Report</h1>
<div id="scansummary">
Command: nmap --privileged -sC -sV -O -p- target<br>
Nmap version: 7.98<br>
Scan initiated at 2026-04-15<br>
Scan duration: 362.49 seconds<br>
Target: laudea.acetcbe.edu.in (13.233.180.106)<br>
</div>
<h2>Host laudea.acetcbe.edu.in (13.233.180.106)</h2>
<p>State: up</p>
<p>Not shown: 65533 filtered ports</p>
<table border="1">
<tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
<tr><td>80/tcp</td><td>open</td><td>http</td><td>nginx 1.24.0 (Ubuntu)</td></tr>
<tr><td colspan="4">
<pre>
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-redirect: https://laudea.acetcbe.edu.in/
</pre>
</td></tr>
<tr><td>443/tcp</td><td>open</td><td>http</td><td>nginx 1.24.0 (Ubuntu)</td></tr>
<tr><td colspan="4">
<pre>
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: LAUDEA
| ssl-cert: Subject: commonName=laudea.acetcbe.edu.in
| Subject Alternative Name: DNS:laudea.acetcbe.edu.in
| Not valid before: 2026-03-17
|_Not valid after:  2026-06-15
</pre>
</td></tr>
</table>
<h3>Device / OS Detection</h3>
<p>OS details: Oracle VirtualBox Slirp NAT bridge (97%), AT&T BGW210 voice gateway (95%), QEMU user mode network gateway (93%)</p>
</body>
</html>
"""


def test_reference_nmap_scan_structure_extraction():
    parsed = parse_nmap_full(REFERENCE_NMAP_TEXT, "laudea.acetcbe.edu.in")

    assert parsed["tool"] == "nmap"
    assert parsed["target"] == "laudea.acetcbe.edu.in"
    assert parsed["ip"] == "13.233.180.106"
    assert parsed["hostname"] == "laudea.acetcbe.edu.in"
    assert parsed["nmap_version"] == "7.98"
    assert "362.49" in str(parsed["scan_duration"])
    assert parsed["filtered_ports_count"] == 65533

    # Ports
    assert len(parsed["ports"]) == 2
    p80 = next(p for p in parsed["ports"] if p["port"] == 80)
    assert p80["state"] == "open"
    assert p80["service"] == "http"
    assert p80["product"] == "nginx"
    assert p80["version"] == "1.24.0"

    p443 = next(p for p in parsed["ports"] if p["port"] == 443)
    assert p443["state"] == "open"
    assert p443["product"] == "nginx"

    # HTTP redirect
    assert parsed["http_redirect"] is not None
    assert "https://laudea.acetcbe.edu.in/" in parsed["http_redirect"]["redirects_to"]

    # TLS Certificate
    tls = parsed["tls_certificate"]
    assert tls is not None
    assert tls["cn"] == "laudea.acetcbe.edu.in"
    assert "2026-03-17" in tls["not_before"]
    assert "2026-06-15" in tls["not_after"]

    # OS detection uncertainty
    os_info = parsed["os_detection"]
    assert os_info["status"] == "uncertain"
    assert len(os_info["candidates"]) >= 3
    cand_names = [c["name"] for c in os_info["candidates"]]
    assert any("VirtualBox" in n for n in cand_names)
    assert any("BGW210" in n for n in cand_names)
    assert any("QEMU" in n for n in cand_names)
    assert os_info["overall_confidence"] == 30


def test_reference_nmap_scan_zero_false_vulnerabilities():
    findings = parse_nmap(
        REFERENCE_NMAP_TEXT,
        scan_id="scan-laudea",
        target="laudea.acetcbe.edu.in",
        owner_id="owner-1",
        asset_id="asset-1",
    )

    # All findings must be informational discoveries
    for f in findings:
        assert f["severity"].upper() == "INFO", f"Finding '{f['title']}' must have severity INFO, not {f['severity']}"
        assert f["status"] == "informational", f"Finding '{f['title']}' must have status informational, not {f['status']}"
        assert f["cve"] is None, f"No fabricated CVE allowed: found {f['cve']}"

    # Filtered ports must be exactly ONE observation
    filtered_findings = [f for f in findings if "filtered" in f["title"].lower()]
    assert len(filtered_findings) == 1
    assert "65533" in str(filtered_findings[0]["evidence"])

    # Score calculation must yield 100 with 0 deductions!
    score_result = compute_scan_risk(findings)
    assert score_result["score"] == 100
    assert score_result["total_deductions"] == 0.0
    assert score_result["rating"].upper() == "LOW"
    assert score_result["counts"]["confirmed"] == 0
    assert score_result["counts"]["potential"] == 0
    assert score_result["counts"]["informational"] == len(findings)


def test_reference_nmap_html_report_parsing():
    parsed = parse_nmap_full(REFERENCE_NMAP_HTML, "laudea.acetcbe.edu.in")
    assert parsed["ip"] == "13.233.180.106"
    assert parsed["target"] == "laudea.acetcbe.edu.in"
    assert len(parsed["ports"]) == 2
    assert parsed["filtered_ports_count"] == 65533
    assert parsed["os_detection"]["status"] == "uncertain"

    findings = parse_nmap(
        REFERENCE_NMAP_HTML,
        scan_id="scan-laudea-html",
        target="laudea.acetcbe.edu.in",
        owner_id="owner-1",
        asset_id="asset-1",
    )
    for f in findings:
        assert f["severity"].upper() == "INFO"

    score_result = compute_scan_risk(findings)
    assert score_result["score"] == 100
    assert score_result["total_deductions"] == 0.0


def test_nmap_deterministic_output():
    run1 = parse_nmap(REFERENCE_NMAP_TEXT, "s1", "laudea.acetcbe.edu.in", "o1", "a1")
    run2 = parse_nmap(REFERENCE_NMAP_TEXT, "s1", "laudea.acetcbe.edu.in", "o1", "a1")

    assert len(run1) == len(run2)
    for f1, f2 in zip(run1, run2):
        assert f1["title"] == f2["title"]
        assert f1["severity"] == f2["severity"]
        assert f1["status"] == f2["status"]
        assert f1["confidence"] == f2["confidence"]
