"""
Tests for Wappalyzer Technology Detection Engine.

Covers:
- Valid domain normalization
- Successful technology detection (CMS, server, JS frameworks, libraries, analytics, CDN)
- HTTP redirect handling and tracking
- HTTPS / SSL error handling and graceful unverified fallback
- Request timeout handling
- Unavailable / unreachable target handling
- Configurable CLI integration (WAPPALYZER_PATH) and fallback
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from app.scanners.wappalyzer_scanner import WappalyzerScanner


class FakeCookie:
    def __init__(self, name: str, value: str = "1"):
        self.name = name
        self.value = value


def test_wappalyzer_domain_normalization():
    scanner1 = WappalyzerScanner("acetcbe.edu.in")
    assert scanner1.target_url == "https://acetcbe.edu.in"

    scanner2 = WappalyzerScanner("http://example.com")
    assert scanner2.target_url == "http://example.com"

    scanner3 = WappalyzerScanner("https://example.com/portal")
    assert scanner3.target_url == "https://example.com/portal"


def test_wappalyzer_successful_technology_detection():
    html_sample = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="generator" content="WordPress 6.4.2" />
        <title>Campus Portal</title>
        <link rel="stylesheet" href="/wp-content/themes/custom/bootstrap-5.3.0.min.css" />
        <script src="/wp-includes/js/jquery/jquery-3.6.0.min.js"></script>
        <script src="https://www.googletagmanager.com/gtag/js?id=G-123456"></script>
    </head>
    <body class="bg-gray-100 flex flex-col p-4">
        <div id="root" data-reactroot=""></div>
        <script>
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
        </script>
    </body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://acetcbe.edu.in/"
    mock_resp.history = []
    mock_resp.text = html_sample
    mock_resp.headers = {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.2.10",
        "CF-Ray": "85a123bcdef-BOM",
        "CF-Cache-Status": "HIT",
        "Content-Type": "text/html; charset=UTF-8",
    }
    mock_resp.cookies = [FakeCookie("wordpress_logged_in"), FakeCookie("phpsessid")]

    with patch("requests.get", return_value=mock_resp):
        scanner = WappalyzerScanner("https://acetcbe.edu.in")
        res = scanner.scan()

    assert res["status"] == "completed"
    assert res["target"] == "https://acetcbe.edu.in"
    assert res["technology_count"] > 0
    assert res["error"] is None

    tech_names = {t["name"] for t in res["technologies"]}
    assert "WordPress" in tech_names
    assert "Nginx" in tech_names
    assert "PHP" in tech_names
    assert "Cloudflare" in tech_names
    assert "Bootstrap" in tech_names
    assert "jQuery" in tech_names
    assert "Google Analytics" in tech_names
    assert "React" in tech_names

    # Check version detection
    wp = next(t for t in res["technologies"] if t["name"] == "WordPress")
    assert wp["category"] == "CMS"
    assert wp["version"] == "6.4.2"

    nginx = next(t for t in res["technologies"] if t["name"] == "Nginx")
    assert nginx["category"] == "Web Server"
    assert nginx["version"] == "1.24.0"

    jquery = next(t for t in res["technologies"] if t["name"] == "jQuery")
    assert jquery["version"] == "3.6.0"


def test_wappalyzer_redirect_handling():
    mock_initial = MagicMock()
    mock_initial.url = "http://acetcbe.edu.in"

    mock_final = MagicMock()
    mock_final.status_code = 200
    mock_final.url = "https://acetcbe.edu.in/"
    mock_final.history = [mock_initial]
    mock_final.text = "<html><head><title>Home</title></head><body><h1>Welcome</h1></body></html>"
    mock_final.headers = {"Server": "Apache/2.4.52 (Ubuntu)", "Content-Type": "text/html"}
    mock_final.cookies = []

    with patch("requests.get", return_value=mock_final):
        scanner = WappalyzerScanner("http://acetcbe.edu.in")
        res = scanner.scan()

    assert res["status"] == "completed"
    assert res["http"]["redirected"] is True
    assert res["http"]["redirect_count"] == 1
    assert res["http"]["final_url"] == "https://acetcbe.edu.in/"
    assert "Apache" in {t["name"] for t in res["technologies"]}


def test_wappalyzer_https_ssl_error_fallback():
    mock_success = MagicMock()
    mock_success.status_code = 200
    mock_success.url = "https://self-signed.local"
    mock_success.history = []
    mock_success.text = "<html><head><title>Admin</title></head><body>Secure Admin</body></html>"
    mock_success.headers = {"Server": "LiteSpeed"}
    mock_success.cookies = []

    # First call fails with SSLError, second call (verify=False) succeeds
    with patch("requests.get", side_effect=[requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED"), mock_success]) as mock_get:
        scanner = WappalyzerScanner("https://self-signed.local")
        res = scanner.scan()

    assert mock_get.call_count == 2
    assert res["status"] == "completed"
    assert res["http"]["ssl_verified"] is False
    assert "LiteSpeed" in {t["name"] for t in res["technologies"]}


def test_wappalyzer_timeout_handling():
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out")):
        scanner = WappalyzerScanner("https://slow-target.example.com", timeout=5)
        res = scanner.scan()

    assert res["status"] == "timed_out"
    assert res["technologies"] == []
    assert res["technology_count"] == 0
    assert "timed out" in res["error"].lower()


def test_wappalyzer_unavailable_target():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Failed to resolve 'unknown-domain.xyz'")):
        scanner = WappalyzerScanner("https://unknown-domain.xyz")
        res = scanner.scan()

    assert res["status"] == "unavailable"
    assert res["technologies"] == []
    assert res["technology_count"] == 0
    assert "unavailable" in res["error"].lower() or "connection refused" in res["error"].lower()


def test_wappalyzer_cli_configurable_via_env(monkeypatch):
    monkeypatch.setenv("WAPPALYZER_PATH", "/usr/local/bin/wappalyzer")

    cli_output = {
        "technologies": [
            {
                "name": "Next.js",
                "categories": [{"name": "Web Framework"}],
                "confidence": 100,
                "version": "14.1.0",
            },
            {
                "name": "React",
                "categories": [{"name": "JavaScript Framework"}],
                "confidence": 100,
                "version": "18.2.0",
            },
        ]
    }
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(cli_output)
    mock_proc.stderr = ""

    with patch("shutil.which", return_value="/usr/local/bin/wappalyzer"), patch("subprocess.run", return_value=mock_proc):
        scanner = WappalyzerScanner("https://acetcbe.edu.in")
        res = scanner.scan()

    assert res["status"] == "completed"
    names = {t["name"] for t in res["technologies"]}
    assert "Next.js" in names
    assert "React" in names
    next_tech = next(t for t in res["technologies"] if t["name"] == "Next.js")
    assert next_tech["version"] == "14.1.0"


def test_wappalyzer_cli_fallback_to_python_on_cli_failure(monkeypatch):
    monkeypatch.setenv("WAPPALYZER_PATH", "/usr/local/bin/wappalyzer")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://fallback.example.com"
    mock_resp.history = []
    mock_resp.text = "<html><head><meta name=\"generator\" content=\"Drupal 10\"></head><body></body></html>"
    mock_resp.headers = {"Server": "Apache"}
    mock_resp.cookies = []

    # Subprocess fails
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "CLI error"

    with patch("shutil.which", return_value="/usr/local/bin/wappalyzer"), \
         patch("subprocess.run", return_value=mock_proc), \
         patch("requests.get", return_value=mock_resp):
        scanner = WappalyzerScanner("https://fallback.example.com")
        res = scanner.scan()

    assert res["status"] == "completed"
    names = {t["name"] for t in res["technologies"]}
    assert "Drupal" in names
    assert "Apache" in names
