"""Tests for F5 BIG-IP, F5 ASM (WAF), JBoss Web, and RichFaces 3.x detection."""

import pytest

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.header_detector import HeaderDetector


@pytest.mark.asyncio
async def test_f5_and_richfaces_detection():
    detector = HeaderDetector()
    mock_data = {
        "headers": {
            "set-cookie": "f5_cspm=1234; Path=/, TS01a4c028=01c754e13f8c242768f32bbbc498e0486edbab4189cb474d22893014f5c80584f516c937ee604679f78d67adda71caefe2889e92177cc46b8ae7ea14a2047bf26271e3cf82; Path=/; Secure; HttpOnly",
            "server": "Apache",
        },
        "cookies": {
            "f5_cspm": "1234",
            "TS01a4c028": "01c754e13f8c242768f32bbbc498e0486edbab4189cb474d22893014f5c80584f516c937ee604679f78d67adda71caefe2889e92177cc46b8ae7ea14a2047bf26271e3cf82",
            "JSESSIONID": "CA4DA9155FF97C8CEC4AD69BC4B8238B.node1",
        },
        "body": """
        <html>
        <head>
            <script id="f5_cspm">(function(){var f5_cspm={};}())</script>
            <script src="/rupe/a4j/g/3_3_3.Final/org/ajax4jsf/framework.pack.js.rupe"></script>
            <script src="/rupe/a4j/g/3_3_3.Final/org/richfaces/ui.pack.js.rupe"></script>
            <script src="/rupe/geral/scripts/jquery.maskedinput-1.3.min.js"></script>
        </head>
        <body>
            <div class="rf-p">Painel</div>
        </body>
        </html>
        """,
        "probe_404_body": "<html><head><title>JBoss Web/2.1.3.GA - Error report</title></head><body><h3>JBoss Web/2.1.3.GA</h3></body></html>",
    }

    items = await detector.detect_url("https://mock-rupe.local", mock_data)
    names = {item.name: item for item in items}

    # F5 BIG-IP
    assert "F5 BIG-IP" in names
    assert names["F5 BIG-IP"].category == TechCategory.INFRASTRUCTURE

    # F5 ASM WAF
    assert "F5 BIG-IP ASM (WAF)" in names
    assert names["F5 BIG-IP ASM (WAF)"].category == TechCategory.SECURITY

    # RichFaces 3.3.3.Final
    assert "RichFaces" in names
    assert names["RichFaces"].version == "3.3.3.Final"

    # Ajax4jsf
    assert "Ajax4jsf" in names
    assert names["Ajax4jsf"].version == "3.3.3.Final"

    # jQuery Masked Input
    assert "jQuery Masked Input Plugin" in names
    assert names["jQuery Masked Input Plugin"].version == "1.3"

    # JBoss Web
    assert "JBoss Web" in names
    assert names["JBoss Web"].version == "2.1.3.GA"

    # JBoss AS
    assert "JBoss Application Server" in names
