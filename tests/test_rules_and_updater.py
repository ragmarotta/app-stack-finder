"""Unit and integration tests for UpdaterService and RuleRepository."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app_stack_finder.core.models import TechCategory
from app_stack_finder.services.rule_repository import (
    RuleRepository,
    parse_rule_pattern,
    resolve_version_template,
)
from app_stack_finder.services.updater_service import UpdaterService


def test_parse_rule_pattern():
    # Sem modificadores
    pat, ver, conf = parse_rule_pattern("nginx(?:/([0-9.]+))?")
    assert pat == "nginx(?:/([0-9.]+))?"
    assert ver is None
    assert conf == 1.0

    # Com version
    pat, ver, conf = parse_rule_pattern(r"nginx(?:/([0-9.]+))?\;version:\1")
    assert pat == "nginx(?:/([0-9.]+))?"
    assert ver == r"\1"
    assert conf == 1.0

    # Com version e confidence
    pat, ver, conf = parse_rule_pattern(r"^WordPress(?: ([0-9.]+))?\;version:\1\;confidence:80")
    assert pat == "^WordPress(?: ([0-9.]+))?"
    assert ver == r"\1"
    assert conf == 0.8

    # Vazio
    pat, ver, conf = parse_rule_pattern("")
    assert pat == ""
    assert ver is None
    assert conf == 1.0


def test_resolve_version_template():
    import re

    m1 = re.search(r"nginx(?:/([0-9.]+))?", "nginx/1.24.0")
    assert resolve_version_template(r"\1", m1) == "1.24.0"

    # Ternário
    m2 = re.search(r"(gtag/js\?id=G-)", "gtag/js?id=G-")
    assert resolve_version_template(r"\1?GA4:UA", m2) == "GA4"

    m3 = re.search(r"WordPress(?: ([0-9.]+))?", "WordPress")
    # match.group(1) é None
    assert resolve_version_template(r"\1?v\1:unknown", m3) == "unknown"


def test_rule_repository_singleton_and_lazy_loading(tmp_path: Path):
    RuleRepository.reset_instance()

    non_existent = tmp_path / "does_not_exist.json"
    repo1 = RuleRepository.get_instance(rules_path=non_existent)
    repo2 = RuleRepository.get_instance()

    assert repo1 is repo2
    # Lazy loading: não deve carregar no get_instance
    assert not repo1.is_loaded

    # Ao checar has_remote_rules, deve carregar sob demanda e retornar False
    assert repo1.has_remote_rules is False
    assert repo1.is_loaded is True

    # Matching não quebra e retorna vazio
    items = repo1.match_web_response("https://www.google.com", {"headers": {"server": "nginx"}})
    assert items == []


def test_rule_repository_with_mock_technologies(tmp_path: Path):
    RuleRepository.reset_instance()

    mock_techs = {
        "technologies": {
            "Nginx": {
                "cats": ["22"],
                "headers": {"Server": r"nginx(?:/([0-9.]+))?\;version:\1"},
                "website": "https://nginx.org",
            },
            "WordPress": {
                "cats": ["1"],
                "meta": {"generator": [r"^WordPress(?: ([0-9.]+))?\;version:\1"]},
            },
            "Vue.js": {
                "cats": ["12"],
                "scripts": [r"vue(?:\.min)?\.js"],
            },
            "Google Analytics": {
                "cats": ["10"],
                "html": [r"google-analytics\.com/analytics\.js"],
            },
        }
    }

    rules_file = tmp_path / "technologies.json"
    rules_file.write_text(json.dumps(mock_techs), encoding="utf-8")

    repo = RuleRepository.get_instance(rules_path=rules_file)
    assert repo.has_remote_rules is True
    assert repo.total_remote_technologies == 4

    response_data = {
        "headers": {"server": "nginx/1.22.1"},
        "cookies": {},
        "body": """
        <html>
            <head>
                <meta name="generator" content="WordPress 6.4.2">
                <script src="https://cdn.jsdelivr.net/npm/vue.min.js"></script>
            </head>
            <body>
                <script src="https://www.google-analytics.com/analytics.js"></script>
            </body>
        </html>
        """,
    }

    items = repo.match_web_response("https://github.com", response_data)
    names = {it.name: it for it in items}

    assert "Nginx" in names
    assert names["Nginx"].category == TechCategory.WEB_SERVERS
    assert names["Nginx"].version == "1.22.1"

    assert "WordPress" in names
    assert names["WordPress"].category == TechCategory.FRAMEWORKS
    assert names["WordPress"].version == "6.4.2"

    assert "Vue.js" in names
    assert names["Vue.js"].category == TechCategory.FRAMEWORKS

    assert "Google Analytics" in names


def test_updater_service_success(tmp_path: Path):
    target = tmp_path / "technologies.json"
    mock_json = {"technologies": {"SampleTech": {"cats": ["1"]}}}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json

    with patch("httpx.Client.get", return_value=mock_resp):
        updater = UpdaterService(target_path=target)
        success = updater.update_rules()

        assert success is True
        assert target.exists()
        saved = json.loads(target.read_text(encoding="utf-8"))
        assert "SampleTech" in saved["technologies"]


def test_updater_service_network_error(tmp_path: Path):
    target = tmp_path / "technologies.json"

    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Failed to connect")):
        updater = UpdaterService(target_path=target)
        # Não deve lançar exceção, deve tratar amigavelmente e retornar False
        success = updater.update_rules()
        assert success is False
        assert not target.exists()
