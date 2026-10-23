"""Tests specifically verifying version extraction from manifests, runtime files, and pom.xml properties."""

from pathlib import Path

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.manifest_detector import ManifestDetector


def test_pom_xml_properties_and_framework_versions(tmp_path: Path):
    pom = tmp_path / "pom.xml"
    pom.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.sample.enterprise</groupId>
    <artifactId>legacy-portal</artifactId>
    <version>1.0.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.release>17</maven.compiler.release>
        <richfaces.version>3.3.3.Final</richfaces.version>
        <primefaces.version>12.0.0</primefaces.version>
        <jsf.version>2.2.14</jsf.version>
        <ojdbc.version>19.18.0.0</ojdbc.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.richfaces.framework</groupId>
            <artifactId>richfaces-impl</artifactId>
            <version>${richfaces.version}</version>
        </dependency>
        <dependency>
            <groupId>org.primefaces</groupId>
            <artifactId>primefaces</artifactId>
            <version>${primefaces.version}</version>
        </dependency>
        <dependency>
            <groupId>org.glassfish</groupId>
            <artifactId>javax.faces</artifactId>
            <version>${jsf.version}</version>
        </dependency>
        <dependency>
            <groupId>com.oracle.database.jdbc</groupId>
            <artifactId>ojdbc8</artifactId>
            <version>${ojdbc.version}</version>
        </dependency>
    </dependencies>
</project>
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [pom])
    techs = {item.name: item for item in results}

    # Java version via compiler release
    assert "Java" in techs
    assert techs["Java"].version == "17"

    # RichFaces with resolved property
    assert "RichFaces" in techs
    assert techs["RichFaces"].version == "3.3.3.Final"

    # PrimeFaces with resolved property
    assert "PrimeFaces" in techs
    assert techs["PrimeFaces"].version == "12.0.0"

    # JSF with resolved property
    assert "JavaServer Faces (JSF)" in techs or "Mojarra (JSF)" in techs
    jsf_item = techs.get("Mojarra (JSF)") or techs.get("JavaServer Faces (JSF)")
    assert jsf_item.version == "2.2.14"

    # Oracle JDBC driver
    assert "Oracle JDBC Driver" in techs
    assert techs["Oracle JDBC Driver"].version == "19.18.0.0"


def test_python_requirements_and_version_files(tmp_path: Path):
    # 1. requirements.txt with python version comment and packages
    req = tmp_path / "requirements.txt"
    req.write_text("""# Python: 3.11.6
fastapi==0.109.2
requests>=2.31.0
oracledb==2.0.1
custom-internal-lib==1.4.2
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [req])
    techs = {item.name: item for item in results}

    assert "Python" in techs
    assert techs["Python"].version == "3.11.6"

    assert "FastAPI" in techs
    assert techs["FastAPI"].version == "0.109.2"

    assert "Requests" in techs
    assert techs["Requests"].version == "2.31.0"

    assert "Oracle DB (python-oracledb)" in techs
    assert techs["Oracle DB (python-oracledb)"].version == "2.0.1"

    # Uncatalogued dependency with version
    assert "custom-internal-lib" in techs
    assert techs["custom-internal-lib"].version == "1.4.2"


def test_python_version_file_and_runtime_txt(tmp_path: Path):
    py_ver = tmp_path / ".python-version"
    py_ver.write_text("3.12.3\n")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [py_ver])
    techs = {item.name: item for item in results}

    assert "Python" in techs
    assert techs["Python"].version == "3.12.3"

    # Test runtime.txt
    rt = tmp_path / "runtime.txt"
    rt.write_text("python-3.10.12\n")
    results2 = detector.detect_filesystem(tmp_path, [rt])
    techs2 = {item.name: item for item in results2}
    assert "Python" in techs2
    assert techs2["Python"].version == "3.10.12"


def test_tool_versions_multi_language(tmp_path: Path):
    tv = tmp_path / ".tool-versions"
    tv.write_text("""python 3.11.8
nodejs 20.11.1
java temurin-17.0.9
golang 1.22.0
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [tv])
    techs = {item.name: item for item in results}

    assert "Python" in techs
    assert techs["Python"].version == "3.11.8"

    assert "Node.js" in techs
    assert techs["Node.js"].version == "20.11.1"

    assert "Java" in techs
    assert techs["Java"].version == "17.0.9"

    assert "Go" in techs
    assert techs["Go"].version == "1.22.0"


def test_gradle_java_toolchain_and_spring(tmp_path: Path):
    gradle = tmp_path / "build.gradle"
    gradle.write_text("""
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.2'
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [gradle])
    techs = {item.name: item for item in results}

    assert "Java" in techs
    assert techs["Java"].version == "17"

    assert "Spring Boot" in techs
    assert techs["Spring Boot"].version == "3.2.2"
