"""
Technology Fingerprinting Engine

Detects common web technologies from:
- HTTP response headers
- Cookies
- HTML content
- Script references
- Meta tags
- Common technology fingerprints

This module performs technology detection only.
It does not perform vulnerability exploitation.
"""

from __future__ import annotations

import re
from typing import Any

import requests


class WappalyzerScanner:
    """Wappalyzer-style technology fingerprinting."""

    def __init__(self, target_url: str, timeout: int = 15):
        self.target_url = target_url
        self.timeout = timeout

    def scan(self) -> dict[str, Any]:
        """Analyze the target website and return detected technologies."""

        result: dict[str, Any] = {
            "tool": "Technology Fingerprinting",
            "type": "technology_detection",
            "target": self.target_url,
            "status": "not_run",
            "technologies": [],
            "error": None,
        }

        try:
            response = requests.get(
                self.target_url,
                timeout=self.timeout,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "(Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 "
                        "Chrome/130.0 Safari/537.36"
                    )
                },
                allow_redirects=True,
            )

            html = response.text
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            cookies = response.cookies

            technologies: list[dict[str, Any]] = []

            self._detect_server(
                headers,
                technologies,
            )

            self._detect_powered_by(
                headers,
                technologies,
            )

            self._detect_cms(
                html,
                technologies,
            )

            self._detect_javascript_frameworks(
                html,
                technologies,
            )

            self._detect_css_frameworks(
                html,
                technologies,
            )

            self._detect_libraries(
                html,
                technologies,
            )

            self._detect_analytics(
                html,
                technologies,
            )

            self._detect_cloud_services(
                headers,
                technologies,
            )

            self._detect_cookies(
                cookies,
                technologies,
            )

            technologies = self._remove_duplicates(technologies)

            result["status"] = "completed"
            result["technologies"] = technologies
            result["technology_count"] = len(technologies)

            result["http"] = {
                "status_code": response.status_code,
                "final_url": response.url,
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
            }

        except requests.exceptions.Timeout:
            result["status"] = "error"
            result["error"] = "Request timed out."

        except requests.exceptions.RequestException as exc:
            result["status"] = "error"
            result["error"] = str(exc)

        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)

        return result

    # ---------------------------------------------------------
    # WEB SERVER
    # ---------------------------------------------------------

    def _detect_server(
        self,
        headers: dict[str, str],
        technologies: list[dict[str, Any]],
    ) -> None:

        server = headers.get("server", "")

        if not server:
            return

        server_lower = server.lower()

        fingerprints = {
            "nginx": ("Nginx", "Web Server", 95),
            "apache": ("Apache", "Web Server", 95),
            "microsoft-iis": ("Microsoft IIS", "Web Server", 95),
            "cloudflare": ("Cloudflare", "CDN / Security", 90),
            "litespeed": ("LiteSpeed", "Web Server", 95),
        }

        for fingerprint, data in fingerprints.items():

            if fingerprint in server_lower:

                name, category, confidence = data

                technologies.append(
                    self._technology(
                        name=name,
                        category=category,
                        confidence=confidence,
                        evidence=f"Server header: {server}",
                    )
                )

    # ---------------------------------------------------------
    # X-POWERED-BY
    # ---------------------------------------------------------

    def _detect_powered_by(
        self,
        headers: dict[str, str],
        technologies: list[dict[str, Any]],
    ) -> None:

        powered_by = headers.get("x-powered-by", "")

        if not powered_by:
            return

        value = powered_by.lower()

        if "php" in value:
            technologies.append(
                self._technology(
                    "PHP",
                    "Programming Language",
                    95,
                    f"X-Powered-By: {powered_by}",
                )
            )

        if "asp.net" in value:
            technologies.append(
                self._technology(
                    "ASP.NET",
                    "Web Framework",
                    95,
                    f"X-Powered-By: {powered_by}",
                )
            )

        if "express" in value:
            technologies.append(
                self._technology(
                    "Express",
                    "Web Framework",
                    90,
                    f"X-Powered-By: {powered_by}",
                )
            )

    # ---------------------------------------------------------
    # CMS
    # ---------------------------------------------------------

    def _detect_cms(
        self,
        html: str,
        technologies: list[dict[str, Any]],
    ) -> None:

        html_lower = html.lower()

        if "wp-content" in html_lower or "wp-includes" in html_lower:

            technologies.append(
                self._technology(
                    "WordPress",
                    "CMS",
                    95,
                    "Detected WordPress paths such as wp-content/wp-includes.",
                )
            )

        if "drupal-settings-json" in html_lower:

            technologies.append(
                self._technology(
                    "Drupal",
                    "CMS",
                    90,
                    "Detected Drupal settings fingerprint.",
                )
            )

        if "joomla" in html_lower:

            technologies.append(
                self._technology(
                    "Joomla",
                    "CMS",
                    80,
                    "Detected Joomla-related HTML content.",
                )
            )

    # ---------------------------------------------------------
    # JAVASCRIPT FRAMEWORKS
    # ---------------------------------------------------------

    def _detect_javascript_frameworks(
        self,
        html: str,
        technologies: list[dict[str, Any]],
    ) -> None:

        html_lower = html.lower()

        if (
            "react" in html_lower
            or "__next_data__" in html_lower
            or "_next/static" in html_lower
        ):

            technologies.append(
                self._technology(
                    "React",
                    "JavaScript Framework",
                    85,
                    "Detected React/Next.js related HTML or script fingerprint.",
                )
            )

        if (
            "ng-version" in html_lower
            or "angular" in html_lower
        ):

            technologies.append(
                self._technology(
                    "Angular",
                    "JavaScript Framework",
                    80,
                    "Detected Angular-related HTML fingerprint.",
                )
            )

        if (
            "__vue__" in html_lower
            or "vue" in html_lower
        ):

            technologies.append(
                self._technology(
                    "Vue.js",
                    "JavaScript Framework",
                    75,
                    "Detected Vue.js-related HTML fingerprint.",
                )
            )

    # ---------------------------------------------------------
    # CSS FRAMEWORKS
    # ---------------------------------------------------------

    def _detect_css_frameworks(
        self,
        html: str,
        technologies: list[dict[str, Any]],
    ) -> None:

        html_lower = html.lower()

        if "bootstrap" in html_lower:

            technologies.append(
                self._technology(
                    "Bootstrap",
                    "CSS Framework",
                    85,
                    "Detected Bootstrap-related CSS/HTML reference.",
                )
            )

        if "tailwind" in html_lower:

            technologies.append(
                self._technology(
                    "Tailwind CSS",
                    "CSS Framework",
                    75,
                    "Detected Tailwind-related CSS/HTML fingerprint.",
                )
            )

    # ---------------------------------------------------------
    # JAVASCRIPT LIBRARIES
    # ---------------------------------------------------------

    def _detect_libraries(
        self,
        html: str,
        technologies: list[dict[str, Any]],
    ) -> None:

        html_lower = html.lower()

        if (
            "jquery" in html_lower
            or re.search(r"jquery[.-][0-9]", html_lower)
        ):

            technologies.append(
                self._technology(
                    "jQuery",
                    "JavaScript Library",
                    90,
                    "Detected jQuery script reference.",
                )
            )

    # ---------------------------------------------------------
    # ANALYTICS
    # ---------------------------------------------------------

    def _detect_analytics(
        self,
        html: str,
        technologies: list[dict[str, Any]],
    ) -> None:

        html_lower = html.lower()

        if (
            "google-analytics.com" in html_lower
            or "googletagmanager.com" in html_lower
            or "gtag(" in html_lower
        ):

            technologies.append(
                self._technology(
                    "Google Analytics",
                    "Analytics",
                    90,
                    "Detected Google Analytics / Google Tag Manager reference.",
                )
            )

    # ---------------------------------------------------------
    # CLOUD / CDN
    # ---------------------------------------------------------

    def _detect_cloud_services(
        self,
        headers: dict[str, str],
        technologies: list[dict[str, Any]],
    ) -> None:

        cloudflare_headers = [
            "cf-ray",
            "cf-cache-status",
        ]

        if any(header in headers for header in cloudflare_headers):

            technologies.append(
                self._technology(
                    "Cloudflare",
                    "CDN / Security",
                    95,
                    "Detected Cloudflare response headers.",
                )
            )

        if "x-amz-cf-id" in headers:

            technologies.append(
                self._technology(
                    "Amazon CloudFront",
                    "CDN",
                    95,
                    "Detected Amazon CloudFront response header.",
                )
            )

    # ---------------------------------------------------------
    # COOKIES
    # ---------------------------------------------------------

    def _detect_cookies(
        self,
        cookies: Any,
        technologies: list[dict[str, Any]],
    ) -> None:

        cookie_names = {
            cookie.name.lower()
            for cookie in cookies
        }

        if any(
            name in cookie_names
            for name in ["wordpress_logged_in", "wp-settings"]
        ):

            technologies.append(
                self._technology(
                    "WordPress",
                    "CMS",
                    95,
                    "Detected WordPress cookie.",
                )
            )

    # ---------------------------------------------------------
    # NORMALIZED TECHNOLOGY OBJECT
    # ---------------------------------------------------------

    @staticmethod
    def _technology(
        name: str,
        category: str,
        confidence: int,
        evidence: str,
    ) -> dict[str, Any]:

        return {
            "name": name,
            "category": category,
            "confidence": confidence,
            "evidence": evidence,
        }

    # ---------------------------------------------------------
    # REMOVE DUPLICATES
    # ---------------------------------------------------------

    @staticmethod
    def _remove_duplicates(
        technologies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        unique: dict[str, dict[str, Any]] = {}

        for technology in technologies:

            name = technology["name"]

            if name not in unique:

                unique[name] = technology

            elif (
                technology["confidence"]
                > unique[name]["confidence"]
            ):

                unique[name] = technology

        return list(unique.values())