"""Tests for ManifestDetector covering package.json, requirements, pom.xml, go.mod, etc."""

import json
from pathlib import Path

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.manifest_detector import ManifestDetector


def test_detect_package_json(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({
            "name": "my-sample-app",
            "engines": {"node": ">=18.17.0"},
            "dependencies": {
                "next": "^14.1.0",
                "react": "^18.2.0",
                "@prisma/client": "~5.8.0",
            },
            "devDependencies": {
                "typescript": "^5.3.3",
                "tailwindcss": "^3.4.1",
            }
        })
    )

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [pkg_json])

    names = {item.name: item for item in results}
    assert "Node.js" in names
    assert names["Node.js"].version == "18.17.0"
    assert names["Node.js"].category == TechCategory.LANGUAGES

    assert "Next.js" in names
    assert names["Next.js"].version == "14.1.0"
    assert names["Next.js"].category == TechCategory.FRAMEWORKS

    assert "React" in names
    assert names["React"].version == "18.2.0"

    assert "TypeScript" in names
    assert names["TypeScript"].version == "5.3.3"
    assert names["TypeScript"].category == TechCategory.LANGUAGES

    assert "Tailwind CSS" in names


def test_detect_python_manifests(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi>=0.109.0\nuvicorn==0.27.0\nsqlalchemy>=2.0.25\n")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [req_file])

    names = {item.name: item for item in results}
    assert "Python" in names
    assert "FastAPI" in names
    assert names["FastAPI"].version == "0.109.0"
    assert "Uvicorn" in names
    assert names["Uvicorn"].version == "0.27.0"
    assert names["Uvicorn"].category == TechCategory.WEB_SERVERS
    assert "SQLAlchemy" in names
    assert names["SQLAlchemy"].category == TechCategory.DATABASES


def test_detect_go_mod(tmp_path: Path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text("""
module example.com/myproject

go 1.22.1

require (
    github.com/gin-gonic/gin v1.9.1
    gorm.io/gorm v1.25.7
)
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [go_mod])

    names = {item.name: item for item in results}
    assert "Go" in names
    assert names["Go"].version == "1.22.1"
    assert "Gin" in names
    assert names["Gin"].version == "1.9.1"
    assert "GORM" in names
    assert names["GORM"].category == TechCategory.DATABASES


def test_detect_pom_xml(tmp_path: Path):
    pom = tmp_path / "pom.xml"
    pom.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.2</version>
    </parent>
    <properties>
        <java.version>21</java.version>
    </properties>
</project>
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [pom])

    names = {item.name: item for item in results}
    assert "Java" in names
    assert names["Java"].version == "21"
    assert "Spring Boot" in names
    assert names["Spring Boot"].version == "3.2.2"
    assert "Maven" in names
    assert names["Maven"].category == TechCategory.CICD


def test_detect_cargo_toml(tmp_path: Path):
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text("""
[package]
name = "rusty_server"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4.4.0"
tokio = "1.35.0"
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [cargo])

    names = {item.name: item for item in results}
    assert "Rust" in names
    assert "Actix-web" in names
    assert names["Actix-web"].version == "4.4.0"
    assert "Tokio" in names
