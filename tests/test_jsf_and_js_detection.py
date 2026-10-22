"""Tests for JavaScript libraries, JSF, PrimeFaces, RichFaces, and Java application servers."""

import pytest

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.header_detector import HeaderDetector


@pytest.mark.asyncio
async def test_primefaces_and_jquery_detection():
    detector = HeaderDetector()
    html_body = """
    <!DOCTYPE html>
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <link rel="stylesheet" href="/javax.faces.resource/theme.css.xhtml?ln=primefaces-aristo" />
        <script type="text/javascript" src="/javax.faces.resource/jquery/jquery.js.xhtml?ln=primefaces&amp;v=12.0.0"></script>
        <script type="text/javascript" src="/javax.faces.resource/primefaces.js.xhtml?ln=primefaces&amp;v=12.0.0"></script>
    </head>
    <body>
        <form id="j_idt5" name="j_idt5" method="post" action="/app/index.xhtml">
            <input type="hidden" name="javax.faces.ViewState" id="j_id1:javax.faces.ViewState:0" value="stateless" />
            <button id="btn" class="ui-button ui-widget">Clique Aqui</button>
        </form>
        <script type="text/javascript">
            PrimeFaces.settings.locale = 'pt_BR';
        </script>
    </body>
    </html>
    """

    mock_data = {
        "headers": {
            "server": "Apache-Coyote/1.1",
            "x-powered-by": "Servlet/3.1",
        },
        "cookies": {
            "JSESSIONID": "A1B2C3D4E5F6",
        },
        "body": html_body,
    }

    items = await detector.detect_url("https://meu-portal-legado.gov.br", mock_data)
    names = {item.name: item for item in items}

    # PrimeFaces com versão 12.0.0
    assert "PrimeFaces" in names
    assert names["PrimeFaces"].version == "12.0.0"
    assert names["PrimeFaces"].category == TechCategory.FRAMEWORKS

    # JavaServer Faces (JSF) detectado via ViewState e implicitamente
    assert "JavaServer Faces (JSF)" in names

    # Java inferido
    assert "Java" in names
    assert names["Java"].category == TechCategory.LANGUAGES

    # Servidor Apache Tomcat
    assert "Apache Tomcat" in names
    assert names["Apache Tomcat"].category == TechCategory.WEB_SERVERS

    # jQuery carregado
    assert "jQuery" in names


@pytest.mark.asyncio
async def test_richfaces_detection():
    detector = HeaderDetector()
    html_body = """
    <!DOCTYPE html>
    <html>
    <head>
        <script type="text/javascript" src="/rfRes/richfaces.js"></script>
        <script type="text/javascript" src="/rfRes/richfaces-queue.js?v=4.5.17"></script>
        <link rel="stylesheet" type="text/css" href="/rfRes/skinning.css" />
    </head>
    <body>
        <div class="rf-p">
            <div class="rf-p-hdr">Painel RichFaces</div>
            <div class="rf-p-b">Conteúdo</div>
        </div>
        <script>
            RichFaces.ajax("j_id1", null, {});
        </script>
    </body>
    </html>
    """

    mock_data = {
        "headers": {
            "server": "WildFly/24",
            "x-powered-by": "Undertow/2.2",
        },
        "cookies": {
            "JSESSIONID": "XYZ123",
        },
        "body": html_body,
    }

    items = await detector.detect_url("https://portal-richfaces.corp.local", mock_data)
    names = {item.name: item for item in items}

    assert "RichFaces" in names
    assert "JavaServer Faces (JSF)" in names
    assert "Java" in names
    assert "WildFly" in names
    assert names["WildFly"].version == "24"


@pytest.mark.asyncio
async def test_client_side_js_libraries():
    detector = HeaderDetector()
    html_body = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
        <script src="https://code.jquery.com/ui/1.13.2/jquery-ui.min.js"></script>
        <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    </head>
    <body>
        <div x-data="{ open: false }">
            <button hx-get="/items" hx-target="#result">Carregar</button>
            <div id="result"></div>
        </div>
    </body>
    </html>
    """

    mock_data = {
        "headers": {"server": "nginx/1.24.0"},
        "cookies": {},
        "body": html_body,
    }

    items = await detector.detect_url("https://modern-app.com", mock_data)
    names = {item.name: item for item in items}

    assert "jQuery" in names
    assert names["jQuery"].version == "3.7.1"

    assert "jQuery UI" in names
    assert names["jQuery UI"].version == "1.13.2"

    assert "HTMX" in names
    assert names["HTMX"].version == "1.9.10"

    assert "Alpine.js" in names
