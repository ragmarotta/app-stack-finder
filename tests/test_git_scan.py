"""Tests for GitService and ScannerService.scan_git."""

import subprocess
from pathlib import Path

from app_stack_finder.core.models import TechCategory
from app_stack_finder.services.git_service import GitService
from app_stack_finder.services.scanner_service import ScannerService


def test_git_service_clone_and_scan(tmp_path: Path):
    # Cria um repositório git local válido para testar o fluxo de clone
    origin_repo = tmp_path / "origin_repo"
    origin_repo.mkdir()

    subprocess.run(["git", "init", str(origin_repo)], check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=origin_repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=origin_repo, check=True)

    # Cria arquivo requirements.txt no repositório
    req = origin_repo / "requirements.txt"
    req.write_text("django==5.0.2\npsycopg2-binary==2.9.9\n")

    # Cria Dockerfile
    df = origin_repo / "Dockerfile"
    df.write_text("FROM python:3.12-slim\n")

    subprocess.run(["git", "add", "."], cwd=origin_repo, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=origin_repo, check=True)

    scanner = ScannerService()
    # Executa varredura passando a URL local (file://...)
    result = scanner.scan_git(f"file://{origin_repo}")

    assert result.target.target_type == "git"
    assert result.target.target_value == f"file://{origin_repo}"

    names = {item.name: item for item in result.items}
    assert "Django" in names
    assert names["Django"].version == "5.0.2"
    assert "PostgreSQL (psycopg2)" in names
    assert "Docker" in names
    assert "Python" in names
