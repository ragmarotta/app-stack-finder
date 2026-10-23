"""Tests for HeaderDetector covering HTTP headers, cookies, WAF/CDN, and DOM inspection."""

import pytest

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.header_detector import HeaderDetector


@pytest.mark.asyncio
async def test_header_detector_server_and_waf():
    detector = HeaderDetector()
    mock_data = {
        "headers": {
            "server": "nginx/1.24.0 (Ubuntu)",
            "x-powered-by": "PHP/8.3.1",
            "cf-ray": "84a7e93739281-GRU",
            "cf-cache-status": "HIT",
        },
        "cookies": {
            "PHPSESSID": "somesessionid12345",
        },
        "body": "<html><body>Hello</body></html>",
    }

    items = await detector.detect_url("https://www.google.com", mock_data)
    names = {item.name: item for item in items}

    assert "Nginx" in names
    assert names["Nginx"].version == "1.24.0"
    assert "Ubuntu Linux" in names

    assert "PHP" in names
    assert names["PHP"].version == "8.3.1"

    assert "Cloudflare" in names
    assert names["Cloudflare"].category == TechCategory.SECURITY


@pytest.mark.asyncio
async def test_header_detector_dom_and_meta():
    detector = HeaderDetector()
    mock_data = {
        "headers": {
            "server": "cloudflare",
        },
        "cookies": {},
        "body": """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="WordPress 6.4.2" />
        </head>
        <body>
            <div id="__next">
                <script src="/_next/static/chunks/main.js"></script>
            </div>
        </body>
        </html>
        """,
    }

    items = await detector.detect_url("https://www.google.com", mock_data)
    names = {item.name: item for item in items}

    assert "WordPress" in names
    assert names["WordPress"].version == "6.4.2"
    assert "Next.js" in names


@pytest.mark.asyncio
async def test_header_detector_webpack_and_assets():
    detector = HeaderDetector()
    mock_data = {
        "headers": {},
        "cookies": {},
        "body": """
        <html>
        <head>
            <script src="/static/js/dist/runtime.29e3254c61c00a76ae7c.js"></script>
            <script src="/static/js/dist/npm.jstree.f1bc0f58dfe777fe3bbd.js"></script>
        </head>
        <body>
            <script>self.webpackChunkApp = [];</script>
        </body>
        </html>
        """,
    }

    class MockClient:
        async def get(self, url, headers=None, timeout=None):
            class MockResp:
                def __init__(self, text):
                    self.text = text
            if "runtime" in url:
                return MockResp('self.webpackChunkApp = [];')
            elif "jstree" in url:
                return MockResp('e.jstree={version:"3.3.15",defaults:{plugins:[]}};')
            return MockResp("")

    items = await detector.detect_url("https://github.com", mock_data, client=MockClient())
    names = {item.name: item for item in items}

    assert "Webpack" in names
    assert names["Webpack"].version == "5"

    assert "jsTree" in names
    assert names["jsTree"].version == "3.3.15"


@pytest.mark.asyncio
async def test_header_detector_jboss_eap_undertow_jsf_keycloak():
    detector = HeaderDetector()
    mock_data = {
        "headers": {
            "server": "JBoss-EAP/7",
            "x-powered-by": "Undertow/1",
        },
        "cookies": {
            "JSESSIONID": "xyz123",
            "AUTH_SESSION_ID": "fb6ff8bc.keycloak-7",
            "AWSALB": "somealbcookie",
        },
        "body": """
        <html>
        <head>
            <meta http-equiv="Refresh" content="0; URL=login.seam">
            <script src="/auth/resources/login/js/pjeOffice.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"></script>
        </head>
        <body></body>
        </html>
        """,
        "probe_404_headers": {
            "server": "JBoss-EAP/7",
            "x-powered-by": "Undertow/1, JSF/1.2",
        },
        "probe_404_body": """
        <html>
        <head>
            <link rel="stylesheet" href="/assets/estilos/font-awesome/v5.11.2/css/all.min.css" />
        </head>
        <body>404 Not Found</body>
        </html>
        """,
    }

    items = await detector.detect_url("https://web.whatsapp.com", mock_data)
    names = {item.name: item for item in items}

    # JBoss EAP deve ter versão 7 e NÃO gerar falso positivo como JBoss Web ou JBoss Application Server
    assert "JBoss EAP" in names
    assert names["JBoss EAP"].version == "7"
    assert "JBoss Web" not in names
    assert "JBoss Application Server" not in names

    # Undertow com versão 1
    assert "Undertow" in names
    assert names["Undertow"].version == "1"

    # JSF com versão 1.2
    assert "JavaServer Faces (JSF)" in names
    assert names["JavaServer Faces (JSF)"].version == "1.2"

    # Font Awesome com versão 5.11.2
    assert "Font Awesome" in names
    assert names["Font Awesome"].version == "5.11.2"

    # Bootstrap com versão 5.3.3
    assert "Bootstrap" in names
    assert names["Bootstrap"].version == "5.3.3"

    # Demais tecnologias identificadas dinamicamente
    assert "JBoss Seam" in names
    assert "Keycloak" in names
    assert "PJeOffice" in names
    assert "Java" in names
    assert "AWS Application Load Balancer (ALB)" in names

