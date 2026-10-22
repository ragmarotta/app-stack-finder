"""Web HTTP Header, Cookie, Meta-tag and Body Fingerprinting Detector."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import ScanResult, ScanTarget, TechCategory, TechItem
from app_stack_finder.detectors.base import clean_version

SERVER_PATTERNS = [
    (r"nginx(?:/([0-9\.]+))?", "Nginx", TechCategory.WEB_SERVERS, "HTTP and reverse proxy server"),
    (r"apache(?:/([0-9\.]+))?", "Apache HTTP Server", TechCategory.WEB_SERVERS, "Apache web server"),
    (r"cloudflare", "Cloudflare", TechCategory.SECURITY, "Cloudflare CDN / WAF / Reverse Proxy"),
    (r"caddy(?:/([0-9\.]+))?", "Caddy", TechCategory.WEB_SERVERS, "Caddy web server"),
    (r"microsoft-iis(?:/([0-9\.]+))?", "Microsoft IIS", TechCategory.WEB_SERVERS, "Internet Information Services"),
    (r"gunicorn(?:/([0-9\.]+))?", "Gunicorn", TechCategory.WEB_SERVERS, "Python WSGI HTTP Server"),
    (r"uvicorn", "Uvicorn", TechCategory.WEB_SERVERS, "ASGI HTTP Server"),
    (r"litespeed", "LiteSpeed", TechCategory.WEB_SERVERS, "High performance web server"),
    (r"openresty(?:/([0-9\.]+))?", "OpenResty", TechCategory.WEB_SERVERS, "Nginx-based web platform"),
    (r"envoy", "Envoy Proxy", TechCategory.WEB_SERVERS, "Cloud-native high-performance edge/service proxy"),
    (r"traefik(?:/([0-9\.]+))?", "Traefik", TechCategory.WEB_SERVERS, "Modern HTTP reverse proxy"),
]

POWERED_BY_PATTERNS = [
    (r"express", "Express", TechCategory.FRAMEWORKS, "Node.js web framework"),
    (r"next\.?js(?:/([0-9\.]+))?", "Next.js", TechCategory.FRAMEWORKS, "React Production Framework"),
    (r"php(?:/([0-9\.]+))?", "PHP", TechCategory.LANGUAGES, "PHP Hypertext Preprocessor"),
    (r"asp\.net", "ASP.NET", TechCategory.FRAMEWORKS, "Microsoft .NET Web Platform"),
    (r"servlet(?:/([0-9\.]+))?", "Java Servlet", TechCategory.FRAMEWORKS, "Java Servlet Platform"),
    (r"phusion passenger(?:/([0-9\.]+))?", "Phusion Passenger", TechCategory.WEB_SERVERS, "Web app server for Ruby/Python/Node"),
]

HEADER_SIGNATURES = [
    ("cf-ray", "Cloudflare", TechCategory.SECURITY, "Cloudflare Security & CDN"),
    ("cf-cache-status", "Cloudflare", TechCategory.SECURITY, "Cloudflare Edge Cache"),
    ("x-amz-cf-id", "AWS CloudFront", TechCategory.SECURITY, "Amazon CloudFront CDN"),
    ("x-amz-cf-pop", "AWS CloudFront", TechCategory.SECURITY, "Amazon CloudFront CDN PoP"),
    ("x-azure-ref", "Azure Front Door", TechCategory.SECURITY, "Microsoft Azure CDN / Front Door"),
    ("x-fastly-request-id", "Fastly", TechCategory.SECURITY, "Fastly Edge Cloud Platform"),
    ("x-sucuri-id", "Sucuri", TechCategory.SECURITY, "Sucuri Website Security / WAF"),
    ("x-akamai-transformed", "Akamai", TechCategory.SECURITY, "Akamai Intelligent Edge CDN"),
    ("x-vercel-id", "Vercel", TechCategory.INFRASTRUCTURE, "Vercel Edge Network"),
    ("x-nf-request-id", "Netlify", TechCategory.INFRASTRUCTURE, "Netlify Edge Cloud"),
    ("x-kong-proxy-latency", "Kong Gateway", TechCategory.INFRASTRUCTURE, "Kong API Gateway"),
    ("x-envoy-upstream-service-time", "Envoy Proxy", TechCategory.WEB_SERVERS, "Envoy Service Proxy"),
]

COOKIE_SIGNATURES = [
    ("phpsessid", "PHP", TechCategory.LANGUAGES, "PHP session cookie"),
    ("jsessionid", "Java", TechCategory.LANGUAGES, "Java EE session cookie"),
    ("csrftoken", "Django", TechCategory.FRAMEWORKS, "Django CSRF protection cookie"),
    ("sessionid", "Django", TechCategory.FRAMEWORKS, "Django user session cookie"),
    ("laravel_session", "Laravel", TechCategory.FRAMEWORKS, "Laravel web session cookie"),
    ("connect.sid", "Express", TechCategory.FRAMEWORKS, "Express.js session cookie"),
    ("asp.net_sessionid", "ASP.NET", TechCategory.FRAMEWORKS, "ASP.NET session cookie"),
    (".aspnetcore.antiforgery", "ASP.NET Core", TechCategory.FRAMEWORKS, "ASP.NET Core antiforgery"),
    ("cf_clearance", "Cloudflare", TechCategory.SECURITY, "Cloudflare bot management clearance"),
]

BODY_META_PATTERNS = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9\.]*)["\']', "WordPress", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Hugo\s*([0-9\.]*)["\']', "Hugo", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Gatsby\s*([0-9\.]*)["\']', "Gatsby", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Jekyll\s*v?([0-9\.]*)["\']', "Jekyll", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([0-9\.]*)["\']', "Drupal", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost\s*([0-9\.]*)["\']', "Ghost", TechCategory.FRAMEWORKS),
]

BODY_CONTENT_PATTERNS = [
    (r'/_next/static/', "Next.js", TechCategory.FRAMEWORKS, "React Production Framework"),
    (r'/_nuxt/', "Nuxt", TechCategory.FRAMEWORKS, "Vue.js Framework"),
    (r'id="__next"', "Next.js", TechCategory.FRAMEWORKS, "React Production Framework"),
    (r'id="__nuxt"', "Nuxt", TechCategory.FRAMEWORKS, "Vue.js Framework"),
    (r'ng-version=["\']([0-9\.]+)["\']', "Angular", TechCategory.FRAMEWORKS, "Angular Web Framework"),
    (r'wp-content/|wp-includes/', "WordPress", TechCategory.FRAMEWORKS, "WordPress CMS"),
    (r'data-v-[a-f0-9]+', "Vue.js", TechCategory.FRAMEWORKS, "Vue.js Reactive Frontend"),
    (r'react\.production\.min\.js|data-reactroot', "React", TechCategory.FRAMEWORKS, "React UI Library"),
    (r'bootstrap(?:\.min)?\.(?:css|js)', "Bootstrap", TechCategory.FRAMEWORKS, "Bootstrap CSS Library"),
    (r'tailwindcss', "Tailwind CSS", TechCategory.FRAMEWORKS, "Tailwind CSS Utility Framework"),
]


class HeaderDetector(BaseDetector):
    """Detector de tecnologias em servidores web e endpoints HTTP."""

    @property
    def name(self) -> str:
        return "HeaderDetector"

    @property
    def supports_filesystem(self) -> bool:
        return False

    @property
    def supports_url(self) -> bool:
        return True

    async def detect_url(self, url: str, response_data: Dict[str, Any]) -> List[TechItem]:
        items: List[TechItem] = []
        headers: Dict[str, str] = {k.lower(): str(v) for k, v in response_data.get("headers", {}).items()}
        cookies: Dict[str, str] = {k.lower(): str(v) for k, v in response_data.get("cookies", {}).items()}
        body: str = response_data.get("body", "")

        # 1. Analisa Header "Server"
        server_val = headers.get("server", "")
        if server_val:
            detected_server = False
            for pattern, name, cat, desc in SERVER_PATTERNS:
                m = re.search(pattern, server_val, re.IGNORECASE)
                if m:
                    version = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=name,
                            category=cat,
                            version=version,
                            source=f"HTTP Header: Server ({server_val})",
                            confidence=0.98,
                            description=desc,
                        )
                    )
                    detected_server = True

            # Detecta SO no header Server (ex: "Apache/2.4.52 (Ubuntu)")
            if "ubuntu" in server_val.lower():
                items.append(
                    TechItem(
                        name="Ubuntu Linux",
                        category=TechCategory.INFRASTRUCTURE,
                        source=f"HTTP Header: Server ({server_val})",
                        confidence=0.9,
                    )
                )
            elif "debian" in server_val.lower():
                items.append(
                    TechItem(
                        name="Debian Linux",
                        category=TechCategory.INFRASTRUCTURE,
                        source=f"HTTP Header: Server ({server_val})",
                        confidence=0.9,
                    )
                )

            if not detected_server and server_val:
                items.append(
                    TechItem(
                        name=server_val.split("/")[0],
                        category=TechCategory.WEB_SERVERS,
                        version=clean_version(server_val.split("/")[1]) if "/" in server_val else None,
                        source=f"HTTP Header: Server ({server_val})",
                        confidence=0.8,
                    )
                )

        # 2. Analisa Header "X-Powered-By"
        powered_val = headers.get("x-powered-by", "")
        if powered_val:
            for pattern, name, cat, desc in POWERED_BY_PATTERNS:
                m = re.search(pattern, powered_val, re.IGNORECASE)
                if m:
                    version = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=name,
                            category=cat,
                            version=version,
                            source=f"HTTP Header: X-Powered-By ({powered_val})",
                            confidence=1.0,
                            description=desc,
                        )
                    )

        # 3. Analisa Headers de WAF / CDN / Gateway
        for hdr_name, tech_name, cat, desc in HEADER_SIGNATURES:
            if hdr_name in headers:
                items.append(
                    TechItem(
                        name=tech_name,
                        category=cat,
                        source=f"HTTP Header: {hdr_name}",
                        confidence=0.95,
                        description=desc,
                    )
                )

        # 4. Analisa Cookies
        for cookie_name, tech_name, cat, desc in COOKIE_SIGNATURES:
            if cookie_name in cookies:
                items.append(
                    TechItem(
                        name=tech_name,
                        category=cat,
                        source=f"HTTP Cookie: {cookie_name}",
                        confidence=0.9,
                        description=desc,
                    )
                )

        # 5. Analisa HTML Body / Meta Tags / Scripts
        if body:
            # Meta tags de Generator
            for pattern, tech_name, cat in BODY_META_PATTERNS:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    ver = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=tech_name,
                            category=cat,
                            version=ver,
                            source="HTML Meta Generator Tag",
                            confidence=1.0,
                            description=f"{tech_name} detected via meta generator",
                        )
                    )

            # Patterns no código HTML / Scripts
            for pattern, tech_name, cat, desc in BODY_CONTENT_PATTERNS:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    ver = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=tech_name,
                            category=cat,
                            version=ver,
                            source="HTML Body DOM / Script Signature",
                            confidence=0.85,
                            description=desc,
                        )
                    )

        res = ScanResult(target=ScanTarget("url", url), items=items)
        res.deduplicate_and_merge()
        return res.items
