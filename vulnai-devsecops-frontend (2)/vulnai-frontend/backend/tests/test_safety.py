import pytest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from app.services.scanner import validate_url_for_ssrf, SSRFProtectionError

def test_validate_target_url_safe():
    # Should not raise exception
    validate_url_for_ssrf("http://example.com")
    validate_url_for_ssrf("https://google.com")

def test_validate_target_url_unsafe_localhost():
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("http://localhost")
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("http://127.0.0.1")

def test_validate_target_url_unsafe_metadata():
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("http://169.254.169.254/latest/meta-data/")

def test_validate_target_url_invalid_scheme():
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("ftp://example.com")
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("file:///etc/passwd")

def test_validate_target_url_private_ip():
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("http://10.0.0.1")
    with pytest.raises(SSRFProtectionError):
        validate_url_for_ssrf("http://192.168.1.100")
