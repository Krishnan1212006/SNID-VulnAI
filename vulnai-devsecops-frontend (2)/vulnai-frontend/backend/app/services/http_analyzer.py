"""
Common HTTP Response Analysis Layer.

Captures target baseline HTTP behavior:
- status code
- redirect chain
- response headers
- content type
- server header
- response length

Detects wildcard/catch-all redirect behavior across non-existent paths
to prevent automated directory enumeration false positives.
"""

import logging
import secrets
from typing import Dict, Any, List, Optional
from urllib.parse import urlsplit
import httpx

logger = logging.getLogger(__name__)


async def analyze_target_http(target: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Performs baseline HTTP interrogation and wildcard routing detection.
    """
    result: Dict[str, Any] = {
        "target": target,
        "status_code": None,
        "redirect_chain": [],
        "response_headers": {},
        "content_type": None,
        "server_header": None,
        "response_length": 0,
        "wildcard_detected": False,
        "wildcard_status_code": None,
        "wildcard_length": None,
        "wildcard_behavior_note": "",
    }

    parsed = urlsplit(target)
    if not parsed.scheme:
        target = f"https://{target}"
        parsed = urlsplit(target)

    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            # 1. Baseline root request
            try:
                resp = await client.get(target)
                result["status_code"] = resp.status_code
                result["response_length"] = len(resp.content)
                result["content_type"] = resp.headers.get("content-type")
                result["server_header"] = resp.headers.get("server")
                result["response_headers"] = dict(resp.headers)
                if resp.history:
                    result["redirect_chain"] = [str(r.url) for r in resp.history] + [str(resp.url)]
            except httpx.HTTPError as exc:
                logger.debug("Baseline request failed: %s", exc)

            # 2. Probe two distinct non-existent paths to detect wildcard / catch-all routing
            probe_path_1 = f"{base_url}/.vulnai-probe-{secrets.token_hex(6)}"
            probe_path_2 = f"{base_url}/.vulnai-probe-{secrets.token_hex(6)}"

            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as no_redirect_client:
                    r1 = await no_redirect_client.get(probe_path_1)
                    r2 = await no_redirect_client.get(probe_path_2)

                    # If both non-existent paths return non-404 status with same status code and similar response size
                    if r1.status_code != 404 and r1.status_code == r2.status_code:
                        size_diff = abs(len(r1.content) - len(r2.content))
                        if size_diff < 50:
                            result["wildcard_detected"] = True
                            result["wildcard_status_code"] = r1.status_code
                            result["wildcard_length"] = len(r1.content)
                            result["wildcard_behavior_note"] = (
                                f"Potential wildcard/redirect behavior: non-existent paths returned HTTP {r1.status_code} "
                                f"({len(r1.content)} bytes). Directory enumeration observations require manual validation "
                                f"to avoid treating catch-all responses as valid endpoints."
                            )
            except Exception as probe_exc:
                logger.debug("Wildcard probe failed: %s", probe_exc)

    except Exception as exc:
        logger.debug("HTTP analysis encounter exception: %s", exc)

    return result
