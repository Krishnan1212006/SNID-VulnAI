import json
from datetime import datetime, timezone
from app.services.reports import generate_pdf, generate_csv, generate_json

def test_generate_pdf_with_timing_metadata():
    scan_data = {
        "_id": "6cf35b29a9cb04796843234",
        "target_url": "https://acetcbe.edu.in/",
        "started_at": datetime(2026, 10, 6, 5, 49, 29, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 10, 6, 6, 13, 28, tzinfo=timezone.utc),
        "duration": 1439.4,
        "risk_score": {"score": 100, "rating": "Low", "explanation": []},
    }
    vulns_data = []
    
    pdf_buf = generate_pdf(scan_data, vulns_data)
    assert pdf_buf is not None
    content = pdf_buf.getvalue()
    assert len(content) > 0
    # PDF magic bytes
    assert content.startswith(b"%PDF")

def test_generate_json_with_timing_metadata():
    scan_data = {
        "_id": "6cf35b29a9cb04796843234",
        "target_urls": ["https://acetcbe.edu.in/"],
        "started_at": datetime(2026, 10, 6, 5, 49, 29, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 10, 6, 6, 13, 28, tzinfo=timezone.utc),
        "duration": 1439.4,
        "risk_score": {"score": 100, "rating": "Low"},
    }
    vulns_data = []

    json_buf = generate_json(scan_data, vulns_data)
    assert json_buf is not None
    payload = json.loads(json_buf.getvalue())
    assert "report_metadata" in payload
    assert "report_generated_at" in payload["report_metadata"]
    assert payload["report_metadata"]["duration_seconds"] == 1439.4
    assert "23m 59s" in payload["report_metadata"]["duration_formatted"]
    assert "report_generated_at" in payload["scan_data"]

def test_generate_csv_with_timing_metadata():
    scan_data = {
        "_id": "6cf35b29a9cb04796843234",
        "target_url": "https://acetcbe.edu.in/",
        "started_at": datetime(2026, 10, 6, 5, 49, 29, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 10, 6, 6, 13, 28, tzinfo=timezone.utc),
        "duration": 1439.4,
    }
    vulns_data = [{
        "title": "Directory Listing Detected",
        "severity": "low",
        "target_url": "https://acetcbe.edu.in/test",
        "status": "open",
        "confidence": 0.9,
        "owasp_id": "A05:2021",
        "cwe_id": "CWE-548",
        "description": "Index of directory found",
        "ai_analysis": {"recommendation": "Disable directory browsing."}
    }]

    csv_buf = generate_csv(vulns_data, scan_data)
    assert csv_buf is not None
    content = csv_buf.getvalue()
    assert "# Report Generated At" in content
    assert "# Total Execution Duration" in content
    assert "Directory Listing Detected" in content
