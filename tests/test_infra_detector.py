"""Tests for InfraDetector covering Docker, Docker Compose, K8s, Helm, Terraform, CI/CD."""

from pathlib import Path

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.infra_detector import InfraDetector


def test_detect_dockerfile(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""
FROM python:3.11-alpine AS base
WORKDIR /app
COPY . .
CMD ["python", "main.py"]
""")

    detector = InfraDetector()
    results = detector.detect_filesystem(tmp_path, [dockerfile])

    names = {item.name: item for item in results}
    assert "Docker" in names
    assert names["Docker"].category == TechCategory.INFRASTRUCTURE
    assert "Alpine Linux" in names


def test_detect_docker_compose(tmp_path: Path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("""
version: '3.8'
services:
  web:
    image: nginx:1.25-alpine
  db:
    image: postgres:16.1
  cache:
    image: redis:7.2
""")

    detector = InfraDetector()
    results = detector.detect_filesystem(tmp_path, [compose])

    names = {item.name: item for item in results}
    assert "Docker Compose" in names
    assert "Nginx" in names
    assert names["Nginx"].version == "1.25"
    assert "PostgreSQL" in names
    assert names["PostgreSQL"].version == "16.1"
    assert "Redis" in names
    assert names["Redis"].version == "7.2"


def test_detect_terraform_and_ci(tmp_path: Path):
    tf = tmp_path / "main.tf"
    tf.write_text("""
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = "us-east-1"
}
""")

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    ci_file = workflow_dir / "ci.yml"
    ci_file.write_text("""
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")

    detector = InfraDetector()
    results = detector.detect_filesystem(tmp_path, [tf, ci_file])

    names = {item.name: item for item in results}
    assert "Terraform" in names
    assert "AWS (Amazon Web Services)" in names
    assert "GitHub Actions" in names
    assert names["GitHub Actions"].category == TechCategory.CICD
