"""Tests for ScannerService orchestration, deduplication and merging."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import TechCategory, TechItem
from app_stack_finder.services.scanner_service import ScannerService


class CustomDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "CustomDetector"

    def detect_filesystem(self, root_path, files):
        return [
            TechItem(
                name="CustomDB",
                category=TechCategory.DATABASES,
                version="1.0.0",
                confidence=0.8,
                source="custom.cfg",
            )
        ]


def test_custom_detector_registration(tmp_path: Path):
    dummy_file = tmp_path / "custom.cfg"
    dummy_file.write_text("db=true")

    scanner = ScannerService(detectors=[])
    scanner.register_detector(CustomDetector())

    result = scanner.scan_directory(tmp_path)
    assert len(result.items) == 1
    assert result.items[0].name == "CustomDB"
    assert result.items[0].version == "1.0.0"


def test_deduplicate_and_merge():
    from app_stack_finder.core.models import ScanResult, ScanTarget

    item1 = TechItem(name="Python", category=TechCategory.LANGUAGES, version=None, confidence=0.8, source="requirements.txt")
    item2 = TechItem(name="Python", category=TechCategory.LANGUAGES, version="3.11", confidence=1.0, source="pyproject.toml")

    result = ScanResult(
        target=ScanTarget(target_type="directory", target_value="."),
        items=[item1, item2],
    )
    result.deduplicate_and_merge()

    assert len(result.items) == 1
    assert result.items[0].version == "3.11"
    assert result.items[0].confidence == 1.0
    assert "requirements.txt" in result.items[0].source
    assert "pyproject.toml" in result.items[0].source
