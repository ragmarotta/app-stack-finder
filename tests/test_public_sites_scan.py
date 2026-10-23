"""Tests for scanning public websites (google.com, github.com, web.whatsapp.com)."""

import pytest

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.header_detector import HeaderDetector
from app_stack_finder.services.scanner_service import ScannerService


@pytest.mark.asyncio
async def test_detect_google():
    detector = HeaderDetector()
    google_data = {
        "headers": {
            "server": "gws",
            "content-type": "text/html; charset=ISO-8859-1",
            "x-xss-protection": "0",
            "set-cookie": "AEC=Ackid1234; expires=Wed, 21-Apr-2027 20:30:00 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax",
        },
        "cookies": {
            "AEC": "Ackid1234",
            "NID": "520=abcde",
        },
        "body": """
        <!doctype html>
        <html itemscope="" itemtype="http://schema.org/WebPage" lang="pt-BR">
        <head>
            <title>Google</title>
        </head>
        <body class="hp">
            <div id="viewport">Google Search</div>
        </body>
        </html>
        """,
    }

    items = await detector.detect_url("https://www.google.com", google_data)
    names = {it.name: it for it in items}

    # Servidor Google Web Server (gws)
    assert "gws" in names
    assert names["gws"].category == TechCategory.WEB_SERVERS


@pytest.mark.asyncio
async def test_detect_github():
    detector = HeaderDetector()
    github_data = {
        "headers": {
            "server": "github.com",
            "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000; includeSubdomains; preload",
            "x-github-request-id": "A1B2:C3D4:E5F6:7890",
            "set-cookie": "_gh_sess=xyz; path=/; secure; HttpOnly; SameSite=Lax",
        },
        "cookies": {
            "_gh_sess": "xyz",
            "logged_in": "no",
        },
        "body": """
        <!DOCTYPE html>
        <html lang="en" data-color-mode="auto" data-light-theme="light" data-dark-theme="dark">
        <head>
            <title>GitHub: Let's build from here</title>
            <script crossorigin="anonymous" src="https://github.githubassets.com/assets/wp-runtime-57d622f98f45.js"></script>
            <script crossorigin="anonymous" src="https://github.githubassets.com/assets/vendors-node_modules_primer_react_lib-esm_Button_Button_js-node_modules_primer_react_lib-esm_Box_Box_js-485a2105e197.js"></script>
        </head>
        <body>
            <div class="application-main">
                <main id="js-pjax-container">GitHub</main>
            </div>
        </body>
        </html>
        """,
    }

    items = await detector.detect_url("https://github.com", github_data)
    names = {it.name: it for it in items}

    # GitHub Server header
    assert "github.com" in names
    assert names["github.com"].category == TechCategory.WEB_SERVERS


@pytest.mark.asyncio
async def test_detect_whatsapp_web():
    detector = HeaderDetector()
    whatsapp_data = {
        "headers": {
            "server": "proxygen-bolt",
            "content-type": "text/html; charset=UTF-8",
            "strict-transport-security": "max-age=31536000; preload; includeSubDomains",
            "set-cookie": "wa_lang_pref=pt_BR; expires=Mon, 23-Oct-2028 20:30:00 GMT; Max-Age=63072000; path=/; domain=.whatsapp.com; secure",
        },
        "cookies": {
            "wa_lang_pref": "pt_BR",
        },
        "body": """
        <!DOCTYPE html>
        <html class="no-js" dir="ltr" lang="pt-BR">
        <head>
            <title>WhatsApp Web</title>
            <link rel="stylesheet" href="https://web.whatsapp.com/dist/css/app.bundle.css">
        </head>
        <body>
            <div id="app">
                <div class="app-wrapper app-wrapper-web">WhatsApp Web</div>
            </div>
        </body>
        </html>
        """,
    }

    items = await detector.detect_url("https://web.whatsapp.com", whatsapp_data)
    names = {it.name: it for it in items}

    # Servidor Proxygen (Facebook / WhatsApp)
    assert "proxygen-bolt" in names
    assert names["proxygen-bolt"].category == TechCategory.WEB_SERVERS
