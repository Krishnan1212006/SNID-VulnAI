"""
Technology Fingerprinting Engine

Detects common web technologies from:
- HTTP response headers
- Cookies
- HTML content
- Script references
- Meta tags
- Common technology fingerprints
- Optional external Wappalyzer CLI (configured via WAPPALYZER_PATH)

This module performs passive technology detection only.
It does not perform vulnerability exploitation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class WappalyzerScanner:
    """Wappalyzer-style technology fingerprinting with Python engine and CLI fallback."""

    def __init__(
        self,
        target_url: str,
        timeout: int = 15,
        wappalyzer_path: Optional[str] = None,
    ):
        raw = (target_url or "").strip()
        if raw and not (raw.startswith("http://") or raw.startswith("https://")):
            self.target_url = f"https://{raw}"
        else:
            self.target_url = raw
        self.timeout = max(1, timeout)
        self.wappalyzer_path = wappalyzer_path or os.environ.get("WAPPALYZER_PATH")
        if not self.wappalyzer_path:
            try:
                from app.core.config import settings

                self.wappalyzer_path = settings.wappalyzer_path
            except Exception:
                pass

    def scan(self) -> dict[str, Any]:
        """Analyze the target website and return structured technology detection JSON.

        Never raises unhandled exceptions to ensure callers are never crashed.
        """
        if not self.target_url:
            return {
                "tool": "Technology Fingerprinting",
                "type": "technology_detection",
                "target": self.target_url,
                "status": "error",
                "technologies": [],
                "technology_count": 0,
                "error": "Target URL is required.",
            }

        # If a CLI path is specified and accessible, try it first
        if self.wappalyzer_path:
            cli_result = self._scan_cli()
            if cli_result is not None:
                return cli_result

        return self._scan_python()

    # ---------------------------------------------------------
    # CLI SCANNER INTEGRATION
    # ---------------------------------------------------------

    def _scan_cli(self) -> Optional[dict[str, Any]]:
        """Attempt to execute an external Wappalyzer CLI executable if configured."""
        executable = self.wappalyzer_path
        if not executable:
            return None

        resolved = shutil.which(executable) or (executable if os.path.isfile(executable) else None)
        if not resolved:
            logger.warning("Configured WAPPALYZER_PATH '%s' was not found or is not executable.", executable)
            return None

        try:
            cmd = [resolved, self.target_url]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            raw_stdout = proc.stdout.strip()
            if proc.returncode == 0 and raw_stdout:
                parsed = json.loads(raw_stdout)
                return self._normalize_cli_output(parsed)
            logger.warning(
                "Wappalyzer CLI exited with code %d: stderr=%s",
                proc.returncode,
                proc.stderr.strip()[:200],
            )
        except subprocess.TimeoutExpired:
            logger.warning("Wappalyzer CLI execution timed out after %ds; falling back to Python.", self.timeout)
        except Exception as exc:
            logger.warning("Wappalyzer CLI failed (%s); falling back to Python.", exc)

        return None

    def _normalize_cli_output(self, data: Any) -> dict[str, Any]:
        """Normalize JSON output from an external Wappalyzer CLI."""
        technologies: list[dict[str, Any]] = []

        if isinstance(data, dict):
            # Format: {"technologies": [{"name": ..., "categories": [...], "confidence": ...}]}
            raw_list = data.get("technologies") or data.get("results") or []
            if isinstance(raw_list, list):
                for item in raw_list:
                    if isinstance(item, dict) and item.get("name"):
                        cats = item.get("categories") or []
                        category = cats[0]["name"] if (cats and isinstance(cats[0], dict)) else (cats[0] if cats else "Technology")
                        technologies.append(
                            self._technology(
                                name=str(item["name"]),
                                category=str(category),
                                confidence=int(item.get("confidence", 100)),
                                evidence=f"Wappalyzer CLI: {item.get('version') or 'detected'}",
                                version=str(item["version"]) if item.get("version") else None,
                            )
                        )
            elif isinstance(data, dict):
                # Format: {"jQuery": {"version": "3.5.1", ...}}
                for name, details in data.items():
                    if isinstance(details, dict):
                        technologies.append(
                            self._technology(
                                name=name,
                                category=details.get("category", "Technology"),
                                confidence=int(details.get("confidence", 100)),
                                evidence="Wappalyzer CLI",
                                version=str(details["version"]) if details.get("version") else None,
                            )
                        )

        technologies = self._remove_duplicates(technologies)
        return {
            "tool": "Technology Fingerprinting",
            "type": "technology_detection",
            "target": self.target_url,
            "status": "completed",
            "technologies": technologies,
            "technology_count": len(technologies),
            "http": {"cli_source": self.wappalyzer_path},
            "error": None,
        }

    # ---------------------------------------------------------
    # PURE PYTHON FINGERPRINTING ENGINE
    # ---------------------------------------------------------

    def _scan_python(self) -> dict[str, Any]:
        """Passive technology fingerprinting using HTTP inspection."""
        result: dict[str, Any] = {
            "tool": "Technology Fingerprinting",
            "type": "technology_detection",
            "target": self.target_url,
            "status": "not_run",
            "technologies": [],
            "technology_count": 0,
            "error": None,
        }

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/130.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        ssl_fallback = False
        try:
            try:
                response = requests.get(
                    self.target_url,
                    timeout=self.timeout,
                    headers=headers,
                    allow_redirects=True,
                    verify=True,
                )
            except requests.exceptions.SSLError:
                # Fallback on SSL verification failures (e.g. self-signed, invalid cert chain)
                ssl_fallback = True
                try:
                    import urllib3

                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                except Exception:
                    pass
                response = requests.get(
                    self.target_url,
                    timeout=self.timeout,
                    headers=headers,
                    allow_redirects=True,
                    verify=False,
                )

            html = response.text or ""
            resp_headers = {key.lower(): value for key, value in response.headers.items()}
            cookies = response.cookies

            technologies: list[dict[str, Any]] = []

            self._detect_meta_tags(html, technologies)
            self._detect_server(resp_headers, technologies)
            self._detect_powered_by(resp_headers, technologies)
            self._detect_cms(html, resp_headers, cookies, technologies)
            self._detect_javascript_frameworks(html, resp_headers, technologies)
            self._detect_css_frameworks(html, technologies)
            self._detect_libraries(html, technologies)
            self._detect_analytics(html, technologies)
            self._detect_cloud_services(resp_headers, technologies)
            self._detect_cookies(cookies, technologies)

            technologies = self._remove_duplicates(technologies)

            redirects = [r.url for r in response.history]
            result["status"] = "completed"
            result["technologies"] = technologies
            result["technology_count"] = len(technologies)
            result["http"] = {
                "status_code": response.status_code,
                "final_url": response.url,
                "redirected": len(redirects) > 0,
                "redirect_count": len(redirects),
                "redirects": redirects,
                "server": resp_headers.get("server"),
                "content_type": resp_headers.get("content-type"),
                "ssl_verified": not ssl_fallback,
            }

        except requests.exceptions.Timeout:
            result["status"] = "timed_out"
            result["error"] = f"Request timed out after {self.timeout} seconds."

        except requests.exceptions.ConnectionError as exc:
            result["status"] = "unavailable"
            result["error"] = f"Target host unavailable or connection refused: {exc}"

        except requests.exceptions.RequestException as exc:
            result["status"] = "error"
            result["error"] = f"HTTP request failed: {exc}"

        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)

        return result

    # ---------------------------------------------------------
    # META TAG DETECTION
    # ---------------------------------------------------------

    def _detect_meta_tags(self, html: str, technologies: list[dict[str, Any]]) -> None:
        """Inspect HTML meta tags such as generator and application-name."""
        generators = re.findall(
            r"""<meta[^>]+(?:name=["']generator["'][^>]+content=["']([^"']+)["']|content=["']([^"']+)["'][^>]+name=["']generator["'])""",
            html,
            re.IGNORECASE,
        )
        for gen_tuple in generators:
            content = (gen_tuple[0] or gen_tuple[1] or "").strip()
            if not content:
                continue

            content_lower = content.lower()
            version_match = re.search(r"([0-9]+(?:\.[0-9]+)+(?:-[a-z0-9.]+)?)", content, re.IGNORECASE)
            version = version_match.group(1) if version_match else None

            if "wordpress" in content_lower:
                technologies.append(self._technology("WordPress", "CMS", 100, f"Meta generator: {content}", version))
            elif "drupal" in content_lower:
                technologies.append(self._technology("Drupal", "CMS", 100, f"Meta generator: {content}", version))
            elif "joomla" in content_lower:
                technologies.append(self._technology("Joomla", "CMS", 100, f"Meta generator: {content}", version))
            elif "ghost" in content_lower:
                technologies.append(self._technology("Ghost", "CMS", 100, f"Meta generator: {content}", version))
            elif "gatsby" in content_lower:
                technologies.append(self._technology("Gatsby", "Static Site Generator", 100, f"Meta generator: {content}", version))
            elif "hugo" in content_lower:
                technologies.append(self._technology("Hugo", "Static Site Generator", 100, f"Meta generator: {content}", version))
            elif "hexo" in content_lower:
                technologies.append(self._technology("Hexo", "Static Site Generator", 100, f"Meta generator: {content}", version))
            elif "docusaurus" in content_lower:
                technologies.append(self._technology("Docusaurus", "Documentation Tool", 100, f"Meta generator: {content}", version))
            elif "next.js" in content_lower:
                technologies.append(self._technology("Next.js", "Web Framework", 100, f"Meta generator: {content}", version))
            elif "webflow" in content_lower:
                technologies.append(self._technology("Webflow", "CMS / Website Builder", 100, f"Meta generator: {content}"))
            elif "shopify" in content_lower:
                technologies.append(self._technology("Shopify", "Ecommerce", 100, f"Meta generator: {content}"))
            elif "typo3" in content_lower:
                technologies.append(self._technology("TYPO3", "CMS", 100, f"Meta generator: {content}", version))

    # ---------------------------------------------------------
    # WEB SERVER
    # ---------------------------------------------------------

    def _detect_server(self, headers: dict[str, str], technologies: list[dict[str, Any]]) -> None:
        server = headers.get("server", "")
        if not server:
            return

        server_lower = server.lower()
        version_match = re.search(r"/([0-9]+(?:\.[0-9]+)+)", server)
        version = version_match.group(1) if version_match else None

        fingerprints = {
            "nginx": ("Nginx", "Web Server", 95),
            "apache": ("Apache", "Web Server", 95),
            "microsoft-iis": ("Microsoft IIS", "Web Server", 95),
            "cloudflare": ("Cloudflare", "CDN / Security", 90),
            "litespeed": ("LiteSpeed", "Web Server", 95),
            "caddy": ("Caddy", "Web Server", 95),
            "openresty": ("OpenResty", "Web Server", 95),
            "gunicorn": ("Gunicorn", "WSGI Server", 90),
            "uvicorn": ("Uvicorn", "ASGI Server", 90),
            "werkzeug": ("Werkzeug", "WSGI Server", 90),
            "envoy": ("Envoy", "Proxy / Web Server", 90),
        }

        for fingerprint, (name, category, confidence) in fingerprints.items():
            if fingerprint in server_lower:
                technologies.append(
                    self._technology(
                        name=name,
                        category=category,
                        confidence=confidence,
                        evidence=f"Server header: {server}",
                        version=version if name.lower() in server_lower else None,
                    )
                )

    # ---------------------------------------------------------
    # X-POWERED-BY & FRAMEWORK HEADERS
    # ---------------------------------------------------------

    def _detect_powered_by(self, headers: dict[str, str], technologies: list[dict[str, Any]]) -> None:
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            value = powered_by.lower()
            version_match = re.search(r"([0-9]+(?:\.[0-9]+)+)", powered_by)
            version = version_match.group(1) if version_match else None

            if "php" in value:
                technologies.append(self._technology("PHP", "Programming Language", 95, f"X-Powered-By: {powered_by}", version))
            if "asp.net" in value:
                technologies.append(self._technology("ASP.NET", "Web Framework", 95, f"X-Powered-By: {powered_by}", version))
            if "express" in value:
                technologies.append(self._technology("Express", "Web Framework", 95, f"X-Powered-By: {powered_by}"))
            if "next.js" in value:
                technologies.append(self._technology("Next.js", "Web Framework", 95, f"X-Powered-By: {powered_by}", version))

        if "x-aspnet-version" in headers:
            technologies.append(self._technology("ASP.NET", "Web Framework", 95, f"X-AspNet-Version: {headers['x-aspnet-version']}", headers["x-aspnet-version"]))
        if "x-generator" in headers:
            technologies.append(self._technology(headers["x-generator"].split("/")[0], "Framework", 85, f"X-Generator: {headers['x-generator']}"))

    # ---------------------------------------------------------
    # CMS DETECTION
    # ---------------------------------------------------------

    def _detect_cms(
        self,
        html: str,
        headers: dict[str, str],
        cookies: Any,
        technologies: list[dict[str, Any]],
    ) -> None:
        html_lower = html.lower()

        # WordPress
        if "wp-content" in html_lower or "wp-includes" in html_lower or "/wp-json/" in html_lower:
            ver_match = re.search(r"wp-emoji-release\.min\.js\?ver=([0-9.]+)", html_lower) or re.search(r"ver=([0-9]+(?:\.[0-9]+)+)", html_lower)
            technologies.append(
                self._technology(
                    "WordPress",
                    "CMS",
                    95,
                    "Detected WordPress assets (wp-content / wp-includes / wp-json).",
                    version=ver_match.group(1) if ver_match else None,
                )
            )

        # Drupal
        if "drupal-settings-json" in html_lower or "drupal.js" in html_lower or "drupal.min.js" in html_lower:
            technologies.append(self._technology("Drupal", "CMS", 95, "Detected Drupal JavaScript/settings fingerprint."))

        # Joomla
        if "joomla" in html_lower and ("/media/jui/" in html_lower or "/media/system/js/" in html_lower or "content=\"joomla" in html_lower):
            technologies.append(self._technology("Joomla", "CMS", 90, "Detected Joomla system scripts and structure."))

        # Ghost
        if "ghost-root" in html_lower or "content=\"ghost" in html_lower:
            technologies.append(self._technology("Ghost", "CMS", 90, "Detected Ghost blogging platform structure."))

        # Shopify
        if "cdn.shopify.com" in html_lower or "shopify.theme" in html_lower or "myshopify.com" in html_lower:
            technologies.append(self._technology("Shopify", "Ecommerce", 95, "Detected Shopify CDN references."))

        # Wix
        if "wix.com" in html_lower or "wixsite.com" in html_lower or "static.parastorage.com" in html_lower:
            technologies.append(self._technology("Wix", "Website Builder", 95, "Detected Wix hosting and storage references."))

        # Squarespace
        if "static1.squarespace.com" in html_lower or "squarespace-headers" in html_lower:
            technologies.append(self._technology("Squarespace", "Website Builder", 95, "Detected Squarespace static assets."))

        # Magento
        if "mage/cookies.js" in html_lower or "skin/frontend" in html_lower or "varien/js" in html_lower:
            technologies.append(self._technology("Magento", "Ecommerce", 95, "Detected Magento frontend assets."))

    # ---------------------------------------------------------
    # JAVASCRIPT FRAMEWORKS
    # ---------------------------------------------------------

    def _detect_javascript_frameworks(
        self,
        html: str,
        headers: dict[str, str],
        technologies: list[dict[str, Any]],
    ) -> None:
        html_lower = html.lower()

        # React / Next.js
        if "__next_data__" in html_lower or "_next/static" in html_lower:
            technologies.append(self._technology("Next.js", "Web Framework", 95, "Detected Next.js data scripts (__NEXT_DATA__)."))
            technologies.append(self._technology("React", "JavaScript Framework", 95, "Next.js relies on React."))
        elif "react" in html_lower and ("data-reactroot" in html_lower or "react-dom" in html_lower or "_reactlistening" in html_lower):
            technologies.append(self._technology("React", "JavaScript Framework", 90, "Detected React DOM attributes."))

        # Angular
        if "ng-version" in html_lower:
            ver_match = re.search(r'ng-version=["\']([^"\']+)["\']', html)
            ver = ver_match.group(1) if ver_match else None
            technologies.append(self._technology("Angular", "JavaScript Framework", 95, "Detected ng-version attribute.", ver))
        elif "ng-app" in html_lower or "angular.min.js" in html_lower:
            technologies.append(self._technology("AngularJS", "JavaScript Framework", 90, "Detected AngularJS app directive."))

        # Vue.js / Nuxt
        if "__nuxt__" in html_lower or "_nuxt/" in html_lower:
            technologies.append(self._technology("Nuxt.js", "Web Framework", 95, "Detected Nuxt.js hydration bundle."))
            technologies.append(self._technology("Vue.js", "JavaScript Framework", 95, "Nuxt.js relies on Vue.js."))
        elif "__vue__" in html_lower or "data-v-" in html_lower or "vue.global" in html_lower:
            technologies.append(self._technology("Vue.js", "JavaScript Framework", 85, "Detected Vue scoped styles or runtime."))

        # Svelte
        if "svelte" in html_lower and ("__svelte" in html_lower or "svelte-" in html_lower):
            technologies.append(self._technology("Svelte", "JavaScript Framework", 85, "Detected Svelte class or element tokens."))

    # ---------------------------------------------------------
    # CSS FRAMEWORKS
    # ---------------------------------------------------------

    def _detect_css_frameworks(self, html: str, technologies: list[dict[str, Any]]) -> None:
        html_lower = html.lower()

        # Bootstrap
        if "bootstrap" in html_lower and (
            re.search(r"bootstrap[a-z0-9_.-]*\.css", html_lower)
            or "bootstrap.bundle" in html_lower
            or "data-bs-" in html_lower
            or "bs-" in html_lower
        ):
            ver_match = re.search(r"bootstrap[/-]([0-9]+(?:\.[0-9]+)+)", html_lower)
            ver = ver_match.group(1) if ver_match else None
            technologies.append(self._technology("Bootstrap", "CSS Framework", 90, "Detected Bootstrap stylesheet or data attributes.", ver))

        # Tailwind CSS
        if "tailwind" in html_lower or re.search(r'class="[^"]*(?:bg-|text-|flex-|grid-|p-|m-)[0-9][^"]*"', html):
            technologies.append(self._technology("Tailwind CSS", "CSS Framework", 80, "Detected Tailwind utility patterns."))

        # Bulma
        if "bulma.min.css" in html_lower or "is-primary" in html_lower and "is-info" in html_lower:
            technologies.append(self._technology("Bulma", "CSS Framework", 85, "Detected Bulma CSS class names."))

    # ---------------------------------------------------------
    # JAVASCRIPT LIBRARIES
    # ---------------------------------------------------------

    def _detect_libraries(self, html: str, technologies: list[dict[str, Any]]) -> None:
        html_lower = html.lower()

        # jQuery
        if "jquery" in html_lower:
            ver_match = re.search(r"jquery[.-]([0-9]+(?:\.[0-9]+)+)", html_lower)
            ver = ver_match.group(1) if ver_match else None
            technologies.append(self._technology("jQuery", "JavaScript Library", 90, "Detected jQuery script reference.", ver))

        # HTMX
        if "htmx.org" in html_lower or "hx-get" in html_lower or "hx-post" in html_lower:
            technologies.append(self._technology("HTMX", "JavaScript Library", 95, "Detected HTMX declarative attributes."))

        # Alpine.js
        if "alpinejs" in html_lower or "x-data=" in html_lower:
            technologies.append(self._technology("Alpine.js", "JavaScript Library", 90, "Detected Alpine.js x-data attributes."))

        # Axios
        if "axios.min.js" in html_lower or "axios/dist" in html_lower:
            technologies.append(self._technology("Axios", "JavaScript Library", 85, "Detected Axios HTTP library reference."))

        # Lodash
        if "lodash.min.js" in html_lower:
            technologies.append(self._technology("Lodash", "JavaScript Library", 85, "Detected Lodash utility library."))

    # ---------------------------------------------------------
    # ANALYTICS & METRICS
    # ---------------------------------------------------------

    def _detect_analytics(self, html: str, technologies: list[dict[str, Any]]) -> None:
        html_lower = html.lower()

        if "google-analytics.com" in html_lower or "googletagmanager.com" in html_lower or "gtag(" in html_lower:
            technologies.append(self._technology("Google Analytics", "Analytics", 95, "Detected Google Analytics / Tag Manager reference."))

        if "matomo.js" in html_lower or "_paq.push" in html_lower:
            technologies.append(self._technology("Matomo", "Analytics", 95, "Detected Matomo (Piwik) tracker."))

        if "hotjar.com" in html_lower or "hjid" in html_lower:
            technologies.append(self._technology("Hotjar", "Analytics", 90, "Detected Hotjar recording script."))

    # ---------------------------------------------------------
    # CLOUD / CDN / SECURITY
    # ---------------------------------------------------------

    def _detect_cloud_services(self, headers: dict[str, str], technologies: list[dict[str, Any]]) -> None:
        if any(h in headers for h in ("cf-ray", "cf-cache-status", "cf-request-id")):
            technologies.append(self._technology("Cloudflare", "CDN / Security", 95, "Detected Cloudflare headers (CF-Ray)."))

        if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower():
            technologies.append(self._technology("Amazon CloudFront", "CDN", 95, "Detected Amazon CloudFront headers."))

        if "fastly" in headers.get("via", "").lower() or "x-fastly-request-id" in headers:
            technologies.append(self._technology("Fastly", "CDN", 95, "Detected Fastly edge headers."))

        if "x-akamai-transformed" in headers or "akamai" in headers.get("server", "").lower():
            technologies.append(self._technology("Akamai", "CDN", 95, "Detected Akamai CDN headers."))

        if "x-vercel-id" in headers:
            technologies.append(self._technology("Vercel", "Cloud Platform", 95, "Detected Vercel edge deployment header."))

        if "x-nf-request-id" in headers:
            technologies.append(self._technology("Netlify", "Cloud Platform", 95, "Detected Netlify hosting header."))

    # ---------------------------------------------------------
    # COOKIES
    # ---------------------------------------------------------

    def _detect_cookies(self, cookies: Any, technologies: list[dict[str, Any]]) -> None:
        cookie_names = {cookie.name.lower() for cookie in cookies}

        if any(name in cookie_names for name in ["wordpress_logged_in", "wp-settings"]):
            technologies.append(self._technology("WordPress", "CMS", 95, "Detected WordPress session cookie."))

        if "phpsessid" in cookie_names:
            technologies.append(self._technology("PHP", "Programming Language", 90, "Detected PHPSESSID cookie."))

        if "asp.net_sessionid" in cookie_names:
            technologies.append(self._technology("ASP.NET", "Web Framework", 90, "Detected ASP.NET_SessionId cookie."))

        if "csrftoken" in cookie_names:
            technologies.append(self._technology("Django", "Web Framework", 75, "Detected Django csrf cookie."))

        if "jsessionid" in cookie_names:
            technologies.append(self._technology("Java Servlet", "Web Framework", 85, "Detected JSESSIONID cookie."))

    # ---------------------------------------------------------
    # HELPER BUILDERS
    # ---------------------------------------------------------

    @staticmethod
    def _technology(
        name: str,
        category: str,
        confidence: int = 100,
        evidence: str = "",
        version: Optional[str] = None,
    ) -> dict[str, Any]:
        tech: dict[str, Any] = {
            "name": name,
            "category": category,
            "confidence": confidence,
            "evidence": evidence,
        }
        if version:
            tech["version"] = version
        return tech

    @staticmethod
    def _remove_duplicates(technologies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for tech in technologies:
            name = tech["name"]
            if name not in unique:
                unique[name] = tech
            else:
                existing = unique[name]
                if tech.get("version") and not existing.get("version"):
                    existing["version"] = tech["version"]
                if tech.get("confidence", 0) > existing.get("confidence", 0):
                    existing["confidence"] = tech["confidence"]
                if tech.get("evidence") and tech["evidence"] not in existing.get("evidence", ""):
                    existing["evidence"] = f"{existing.get('evidence', '')}; {tech['evidence']}".strip("; ")
        return list(unique.values())