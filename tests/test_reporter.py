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


def test_handle_output_auto_detect_json(tmp_path):
    from app_stack_finder.main import handle_output

    item = TechItem(
        name="Spring Boot",
        category=TechCategory.FRAMEWORKS,
        version="3.2.0",
        confidence=1.0,
        source="pom.xml",
    )
    result = ScanResult(
        target=ScanTarget(target_type="directory", target_value=str(tmp_path)),
        items=[item],
    )

    # 1. Test specifying -o file.json with default format "rich" (should auto-detect JSON)
    out_json = tmp_path / "resultado.json"
    handle_output(result, format_type="rich", output_path=str(out_json))
    assert out_json.exists()
    parsed = json.loads(out_json.read_text(encoding="utf-8"))
    assert parsed["technologies"][0]["name"] == "Spring Boot"

    # 2. Test specifying -o file.md with default format "rich" (should auto-detect Markdown)
    out_md = tmp_path / "resultado.md"
    handle_output(result, format_type="rich", output_path=str(out_md))
    assert out_md.exists()
    content = out_md.read_text(encoding="utf-8")
    assert "# 🔍 App Stack Finder" in content
