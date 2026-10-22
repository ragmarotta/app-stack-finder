"""Tests for reporter formatting (Markdown, JSON, Rich)."""

import json

from app_stack_finder.core.models import ScanResult, ScanTarget, TechCategory, TechItem
from app_stack_finder.utils.reporter import Reporter


def test_reporter_markdown_and_json():
    item = TechItem(
        name="FastAPI",
        category=TechCategory.FRAMEWORKS,
        version="0.109.0",
        confidence=0.95,
        source="requirements.txt",
        description="Fast web framework for APIs",
    )
    result = ScanResult(
        target=ScanTarget(target_type="directory", target_value="/mock/path"),
        items=[item],
        metadata={"elapsed_time_seconds": 0.12},
    )

    reporter = Reporter()

    # Markdown test
    md = reporter.to_markdown(result)
    assert "# 🔍 App Stack Finder - Relatório de Tecnologias" in md
    assert "FastAPI" in md
    assert "0.109.0" in md
    assert "requirements.txt" in md

    # JSON test
    json_str = reporter.to_json(result)
    data = json.loads(json_str)
    assert data["target"]["target_type"] == "directory"
    assert data["summary"]["total_technologies"] == 1
    assert data["technologies"][0]["name"] == "FastAPI"
    assert data["technologies"][0]["version"] == "0.109.0"
