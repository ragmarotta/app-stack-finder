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

    items = await detector.detect_url("https://example.com", mock_data)
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

    items = await detector.detect_url("https://example.com", mock_data)
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
            <script src="/eproc/js/dist/runtime.29e3254c61c00a76ae7c.js"></script>
            <script src="/eproc/js/dist/npm.jstree.f1bc0f58dfe777fe3bbd.js"></script>
        </head>
        <body>
            <script>self.webpackChunkeproc = [];</script>
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
                return MockResp('self.webpackChunkeproc = [];')
            elif "jstree" in url:
                return MockResp('e.jstree={version:"3.3.15",defaults:{plugins:[]}};')
            return MockResp("")

    items = await detector.detect_url("https://example.com/eproc/", mock_data, client=MockClient())
    names = {item.name: item for item in items}

    assert "Webpack" in names
    assert names["Webpack"].version == "5"

    assert "jsTree" in names
    assert names["jsTree"].version == "3.3.15"
