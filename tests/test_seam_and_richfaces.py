"""Test detection of JBoss Seam, RichFaces 3.3.3, Ajax4jsf, jQuery Mask, Facebox and proxy fallback."""

import pytest

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.header_detector import HeaderDetector


@pytest.mark.asyncio
async def test_seam_and_richfaces():
    detector = HeaderDetector()
    mock_data = {
        "headers": {
            "set-cookie": "JSESSIONID=D9B8DB82414C5AFF3ACD600FDAF6C8AE; Path=/portal, BIGipServerportal-prod=rd0o0000; path=/; Httponly; Secure, TS01208839=01c754e13fe2dfba; Path=/; Secure; HttpOnly",
        },
        "cookies": {
            "JSESSIONID": "D9B8DB82414C5AFF3ACD600FDAF6C8AE",
            "BIGipServerportal-prod": "rd0o0000",
            "TS01208839": "01c754e13fe2dfba",
        },
        "body": """
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd" >
        <html xmlns="http://www.w3.org/1999/xhtml">
        <head>
            <link class="component" href="/portal/a4j/s/3_3_3.Finalorg/richfaces/renderkit/html/css/basic_classes.xcss/DATB/eAELXT5DOhSIAQ!sA18_.seam" rel="stylesheet" type="text/css" />
            <script src="/portal/a4j/g/3_3_3.Finalorg.ajax4jsf.javascript.AjaxScript.seam"></script>
            <script src="/portal/a4j/g/3_3_3.Finalorg.ajax4jsf.javascript.PrototypeScript.seam"></script>
            <script src="/portal/scripts/jquery-2.1.4.min.js"></script>
            <script src="/portal/scripts/jquery.mask.min.js"></script>
            <script src="/portal/scripts/facebox.js"></script>
        </head>
        <body>
            <form action="/portal/page/home/dashboard.seam" method="post">
                <input type="submit" value="Enviar" />
            </form>
        </body>
        </html>
        """,
        "probe_404_body": "<html><head><title>JBoss Web/2.1.3.GA - Error report</title></head><body><h1>JBoss Web/2.1.3.GA</h1></body></html>",
    }

    items = await detector.detect_url("https://www.google.com/dashboard.seam", mock_data)
    names = {it.name: it for it in items}

    assert "Java" in names
    assert names["Java"].category == TechCategory.LANGUAGES

    assert "JBoss Seam" in names
    assert names["JBoss Seam"].category == TechCategory.FRAMEWORKS

    assert "RichFaces" in names
    assert names["RichFaces"].version == "3.3.3.Final"

    assert "Ajax4jsf" in names
    assert names["Ajax4jsf"].version == "3.3.3.Final"

    assert "jQuery" in names
    assert names["jQuery"].version == "2.1.4"

    assert "jQuery Mask Plugin" in names
    assert "Facebox" in names
    assert "Prototype.js" in names

    assert "F5 BIG-IP (LTM)" in names
    assert "F5 BIG-IP ASM (WAF)" in names

    assert "JBoss Web" in names
    assert names["JBoss Web"].version == "2.1.3.GA"
    assert "JBoss Application Server" in names
