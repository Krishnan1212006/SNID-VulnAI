import json
from datetime import datetime, timezone
from app.services.finding_correlation import correlate_and_deduplicate_findings
from app.services.risk_scoring import compute_scan_risk, ProjectRiskScoreEngine
from app.services.assessment_coverage import get_assessment_coverage, get_owasp_coverage_matrix
from app.services.reports import generate_pdf, generate_json, generate_csv
from app.parsers.sqlmap_parser import extract_sqlmap_assessment
from app.parsers.nmap_parser import extract_nmap_host_discovery


def test_nikto_and_wapiti_clickjacking_deduplication():
    raw_findings = {
        "nikto": [
            {
                "id": "nikto-1",
                "title": "Anti-clickjacking X-Frame-Options header is not present",
                "description": "The anti-clickjacking X-Frame-Options header is not present in the HTTP response.",
                "severity": "low",
                "confidence": "potential",
                "raw_output_file": "scan-results/scan-1/nikto.txt",
                "url": "https://target.example.com/",
            }
        ],
        "wapiti": [
            {
                "id": "wapiti-1",
                "title": "X-Frame-Options is not set",
                "description": "X-Frame-Options header is not set.",
                "severity": "low",
                "confidence": "potential",
                "evidence": {"response_header": "Missing"},
                "url": "https://target.example.com/",
            }
        ],
    }

    unified = correlate_and_deduplicate_findings(
        raw_findings,
        scan_id="scan-1",
        target="https://target.example.com/",
    )

    # Should be deduplicated into EXACTLY ONE finding
    assert len(unified) == 1
    item = unified[0]
    assert "Clickjacking" in item.title
    assert "Nikto" in item.detected_by
    assert "Wapiti" in item.detected_by
    # Elevated confidence due to cross-scanner consensus
    assert item.confidence == "HIGH"
    assert item.verification_status == "POTENTIAL"
    assert item.owasp_category == "A05:2021 - Security Misconfiguration"
    assert item.cwe == "CWE-1021"


def test_four_missing_headers_score_not_100():
    # Test bug fix: 0 confirmed vulnerabilities + 4 potential missing headers MUST NOT yield 100/100
    potential_findings = [
        {"title": "Missing Content-Security-Policy Header", "severity": "low", "verification_status": "POTENTIAL"},
        {"title": "Missing Clickjacking Protection", "severity": "low", "verification_status": "POTENTIAL"},
        {"title": "Missing HTTP Strict Transport Security", "severity": "low", "verification_status": "POTENTIAL"},
        {"title": "Missing X-Content-Type-Options Header", "severity": "low", "verification_status": "POTENTIAL"},
    ]

    scanner_status = {
        "nmap": "completed",
        "nikto": "completed",
        "wapiti": "completed",
        "sqlmap": "completed",
        "gobuster": "completed",
        "wappalyzer": "completed",
    }

    result = compute_scan_risk(potential_findings, scanner_status=scanner_status)
    assert result["score"] < 100
    assert result["score"] == 94  # Base 100 - (4 * 1.5) = 94
    assert result["total_deductions"] == 6.0
    assert len(result["explanation"]) == 4
    assert result["counts"]["confirmed"] == 0
    assert result["counts"]["potential"] == 4


def test_sqlmap_negative_result_handling():
    # If SQLMap says parameter is not injectable, no fake vulnerability should be created
    raw_output = """
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] all tested parameters do not appear to be injectable.
[WARNING] HTTP error codes detected during run: 404
[INFO] fetched data logged to text files
"""
    assessment = extract_sqlmap_assessment(raw_output)
    assert assessment["injection_confirmed"] is False
    assert "No confirmed SQL injection" in assessment["status"]
    assert "no confirmed sql injection" in assessment["summary"].lower()


def test_nmap_host_discovery_parsing():
    raw_output = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-06 05:49 UTC
Nmap scan report for acetcbe.edu.in (142.91.100.200)
Host is up (0.045s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http nginx 1.18.0
80/tcp  open  http     nginx 1.18.0

Nmap done: 1 IP address (1 host up) scanned in 2.30 seconds
"""
    discovery = extract_nmap_host_discovery(raw_output, "https://acetcbe.edu.in/")
    assert discovery["resolved_ip"] == "142.91.100.200"
    assert discovery["host_state"] == "UP"
    assert len(discovery["open_ports"]) == 2
    assert "443" in str(discovery["open_ports"][0]["port"])
    assert discovery["open_ports"][0]["service"] == "ssl/http"


def test_assessment_coverage_and_owasp_matrix():
    scanner_status = {
        "nmap": "completed",
        "nikto": "completed",
        "wapiti": "completed",
        "sqlmap": "completed",
        "gobuster": "completed",
        "wappalyzer": "completed",
    }
    coverage = get_assessment_coverage(scanner_status)
    assert len(coverage) > 5
    # Verification of unassessed boundary controls
    auth_item = next(item for item in coverage if "Authentication" in item["area"])
    assert auth_item["status"] == "NOT ASSESSED"

    owasp = get_owasp_coverage_matrix([], scanner_status)
    assert len(owasp) == 10
    a05 = next(item for item in owasp if item["id"] == "A05:2021")
    assert "Assessed" in a05["status"]


def test_generate_pdf_with_rich_assessment_data():
    scan_data = {
        "_id": "6cf35b29a9cb04796843234",
        "target_url": "https://acetcbe.edu.in/",
        "started_at": datetime(2026, 10, 6, 5, 49, 29, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 10, 6, 6, 13, 28, tzinfo=timezone.utc),
        "duration": 1439.4,
        "status": "completed",
        "risk_score": {
            "score": 94,
            "rating": "Low",
            "model": "VulnAI Project Risk Score (Project-Defined)",
            "deductions": [
                {"finding": "Missing CSP", "verification_status": "POTENTIAL", "severity": "LOW", "deduction": 1.5},
                {"finding": "Missing Clickjacking", "verification_status": "POTENTIAL", "severity": "LOW", "deduction": 1.5},
            ]
        },
        "combined_results": {
            "confirmed": [],
            "potential": [
                {
                    "id": "VULNAI-001",
                    "title": "Missing Content-Security-Policy Header",
                    "severity": "low",
                    "verification_status": "POTENTIAL",
                    "confidence": "HIGH",
                    "detected_by": ["Nikto", "Wapiti"],
                    "endpoint": "/",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "cwe": "CWE-693",
                    "wstg": "WSTG-CONF-07",
                    "evidence": {"header": "Content-Security-Policy not set"},
                    "impact": "Increases susceptibility to Cross-Site Scripting (XSS).",
                    "recommendation": "Deploy a strict Content-Security-Policy.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    "raw_evidence_files": ["scan-results/scan-1/wapiti.txt", "scan-results/scan-1/nikto.txt"],
                }
            ],
            "informational": [
                {
                    "id": "gobuster-1",
                    "scanner": "gobuster",
                    "path": "/admin",
                    "detected_by": ["Gobuster"],
                    "status_code": 200,
                    "response_size": 1200,
                }
            ],
            "incomplete": [],
            "host_discovery": {
                "hostname": "acetcbe.edu.in",
                "resolved_ip": "142.91.100.200",
                "host_state": "UP",
                "open_ports": [{"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.18.0"}]
            },
            "technology_detection": {
                "technologies": [
                    {"name": "Nginx", "category": "Web Server", "version": "1.18.0", "confidence": 100}
                ]
            },
            "sql_assessment": {
                "injection_confirmed": False,
                "status": "completed",
                "summary": "No confirmed SQL injection identified."
            },
            "assessment_coverage": [
                {"area": "Network Discovery", "tool": "Nmap", "status": "ASSESSED", "note": "Port scanning performed."},
                {"area": "Authentication Testing", "tool": "—", "status": "NOT ASSESSED", "note": "Requires credentialed access."}
            ],
            "owasp_coverage": [
                {"id": "A05:2021", "name": "Security Misconfiguration", "status": "Findings Present", "findings_count": 1, "notes": "Missing headers."}
            ],
            "tool_summaries": {
                "nmap": {"status": "completed", "duration": 12.0, "findings_count": 0},
                "nikto": {"status": "completed", "duration": 45.0, "findings_count": 1},
                "wapiti": {"status": "completed", "duration": 60.0, "findings_count": 1},
                "sqlmap": {"status": "completed", "duration": 30.0, "findings_count": 0},
                "gobuster": {"status": "completed", "duration": 15.0, "findings_count": 1},
                "wappalyzer": {"status": "completed", "duration": 5.0, "findings_count": 1},
            }
        }
    }
    vulns_data = scan_data["combined_results"]["potential"]

    pdf_buf = generate_pdf(scan_data, vulns_data)
    assert pdf_buf is not None
    content = pdf_buf.getvalue()
    assert content.startswith(b"%PDF")
    assert len(content) > 5000  # Multi-section comprehensive document

    json_buf = generate_json(scan_data, vulns_data)
    json_data = json.loads(json_buf.getvalue())
    assert "combined_results" in json_data
    assert json_data["scan_data"]["risk_score"]["score"] == 94

    csv_buf = generate_csv(vulns_data, scan_data)
    csv_data = csv_buf.getvalue()
    assert "Missing Content-Security-Policy Header" in csv_data
    assert "Nikto, Wapiti" in csv_data
