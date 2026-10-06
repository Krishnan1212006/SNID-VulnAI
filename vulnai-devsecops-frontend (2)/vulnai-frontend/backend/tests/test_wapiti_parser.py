from app.parsers.wapiti_parser import parse_wapiti
from app.services.kali_scanner import normalize_wapiti_findings


WAPITI_3_SAMPLE_REPORT = """
********************************************************************************
                   Wapiti 3.2.10 - wapiti-scanner.github.io
                        Report for http://example.com/
              Date of the scan : Mon, 05 Oct 2026 06:04:20 +0000
                               Crawled pages : 1
                           Scope of the scan : page
********************************************************************************

Summary of vulnerabilities :
----------------------------
                                                              Backup file :   0
                                         Cleartext Submission of Password :   0
                                                         Weak credentials :   0
                                                           CRLF Injection :   0
                                    Content Security Policy Configuration :   1
                                               Cross Site Request Forgery :   0
                                                  Clickjacking Protection :   1
                                                      MIME Type Confusion :   1
                                                     Unencrypted Channels :   1
                                                            SQL Injection :   0

********************************************************************************
Content Security Policy Configuration
-------------------------------------
CSP is not set for URL: http://example.com/
WSTG code: ['WSTG-CONF-12', 'OSHP-Content-Security-Policy']
Evil request:
    GET / HTTP/1.1
    host: example.com
    connection: keep-alive
    user-agent: Mozilla/5.0
cURL command PoC : "curl \"http://example.com/\""
                                  *   *   *
CSP directive missing default-src
for URL: http://example.com/profile
cURL command PoC : "curl \"http://example.com/profile\""
********************************************************************************
Clickjacking Protection
-----------------------
X-Frame-Options is not set
WSTG code: ['OSHP-X-Frame-Options']
Evil request:
    GET / HTTP/1.1
    host: example.com
cURL command PoC : "curl \"http://example.com/\""
********************************************************************************
MIME Type Confusion
-------------------
X-Content-Type-Options is not set
WSTG code: ['OSHP-X-Content-Type-Options']
Evil request:
    GET / HTTP/1.1
    host: example.com
cURL command PoC : "curl \"http://example.com/\""
********************************************************************************
Unencrypted Channels
--------------------
No HTTPS redirection for this host. All HTTP requests are served in clear text.
WSTG code: ['WSTG-CRYP-03']
Evil request:
    GET / HTTP/1.1
    host: example.com
cURL command PoC : "curl \"http://example.com/\""
"""


def test_parse_wapiti_w3_sections():
    findings = parse_wapiti(
        raw_output=WAPITI_3_SAMPLE_REPORT,
        scan_id="scan-001",
        target="http://example.com/",
        owner_id="user-123",
        asset_id="asset-456",
    )

    # 2 CSP sub-items + 1 Clickjacking + 1 MIME Type + 1 Unencrypted Channels = 5 findings
    assert len(findings) == 5

    titles = [f["title"] for f in findings]
    assert any("Content Security Policy" in t for t in titles)
    assert any("Clickjacking" in t for t in titles)
    assert any("MIME Type Confusion" in t for t in titles)
    assert any("Unencrypted Channels" in t for t in titles)

    csp_findings = [f for f in findings if "Content Security Policy" in f["title"]]
    assert len(csp_findings) == 2
    assert csp_findings[0]["target_url"] == "http://example.com/"
    assert csp_findings[1]["target_url"] == "http://example.com/profile"
    assert csp_findings[0]["owasp_id"] == "A05:2021"
    assert csp_findings[0]["cwe_id"] == "CWE-693"


def test_parse_wapiti_parameter_extraction():
    sample_with_param = """
********************************************************************************
Cross Site Scripting
--------------------
Reflected XSS found in parameter query
Parameter: query
Evil request:
    GET /search?query=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
    host: example.com
cURL command PoC : "curl \"http://example.com/search?query=%3Cscript%3Ealert(1)%3C/script%3E\""
"""
    findings = parse_wapiti(
        raw_output=sample_with_param,
        scan_id="scan-002",
        target="http://example.com/",
        owner_id="user-123",
        asset_id="asset-456",
    )

    assert len(findings) == 1
    f = findings[0]
    assert "query" in f["title"]
    assert f["evidence"]["parameter"] == "query"
    assert f["severity"] == "high"
    assert f["category"] == "Injection"
    assert f["owasp_id"] == "A03:2021"
    assert f["cwe_id"] == "CWE-79"


def test_parse_wapiti_legacy_block_format():
    legacy_sample = """
Vulnerability SQL Injection:
Url: http://example.com/item.php
Parameter: id
Payload: 1' OR '1'='1
Impact: Database leak
"""
    findings = parse_wapiti(
        raw_output=legacy_sample,
        scan_id="scan-legacy",
        target="http://example.com/",
        owner_id="user-123",
        asset_id="asset-456",
    )

    assert len(findings) == 1
    f = findings[0]
    assert "SQL Injection via 'id'" in f["title"]
    assert f["target_url"] == "http://example.com/item.php"
    assert f["severity"] == "high"
    assert f["owasp_id"] == "A03:2021"
    assert f["cwe_id"] == "CWE-89"


def test_parse_wapiti_empty_input():
    assert parse_wapiti("", "s", "t", "o", "a") == []
    assert parse_wapiti("   \n\n  ", "s", "t", "o", "a") == []


def test_normalize_wapiti_findings_dict_format():
    w3_json_payload = {
        "classifications": {},
        "vulnerabilities": {
            "Content Security Policy Configuration": [
                {
                    "method": "GET",
                    "path": "/",
                    "info": "CSP is not set for URL: http://example.com/",
                    "level": 1,
                    "parameter": None,
                    "referer": "",
                    "module": "csp",
                    "curl_command": 'curl "http://example.com/"',
                    "wstg": ["WSTG-CONF-12", "OSHP-Content-Security-Policy"]
                }
            ],
            "SQL Injection": [
                {
                    "method": "GET",
                    "path": "/products",
                    "info": "Error based SQL injection in parameter cat",
                    "level": 3,
                    "parameter": "cat",
                    "module": "sql",
                    "curl_command": 'curl "http://example.com/products?cat=1\'"'
                }
            ]
        },
        "anomalies": {
            "Internal Server Error": [
                {
                    "method": "POST",
                    "path": "/api/upload",
                    "info": "HTTP 500 returned on large payload",
                    "level": 1,
                    "parameter": "file",
                    "module": "crash"
                }
            ]
        }
    }

    findings = normalize_wapiti_findings(
        payload=w3_json_payload,
        scan_id="scan-json-1",
        target="http://example.com",
        owner_id="u1",
        asset_id="a1"
    )

    assert len(findings) == 3
    titles = [f["title"] for f in findings]
    assert any("Content Security Policy" in t for t in titles)
    assert any("SQL Injection via 'cat'" in t for t in titles)
    assert any("Internal Server Error" in t for t in titles)

    sql_finding = next(f for f in findings if "SQL Injection" in f["title"])
    assert sql_finding["severity"] == "high"
    assert sql_finding["category"] == "Injection"
    assert sql_finding["owasp_id"] == "A03:2021"
    assert sql_finding["cwe_id"] == "CWE-89"
    assert sql_finding["target_url"] == "http://example.com/products"
    assert sql_finding["evidence"]["parameter"] == "cat"


def test_normalize_wapiti_findings_empty_payload():
    assert normalize_wapiti_findings(None, "s", "t", "o", "a") == []
    assert normalize_wapiti_findings({}, "s", "t", "o", "a") == []
    assert normalize_wapiti_findings({"vulnerabilities": {}}, "s", "t", "o", "a") == []
