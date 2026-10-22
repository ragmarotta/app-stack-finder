"""Manifest and dependency detector for Node.js, Python, Java, Go, Rust, PHP, Ruby, and .NET."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import TechCategory, TechItem
from app_stack_finder.detectors.base import clean_version, safe_read_text

# Catalogos de mapeamento para rápida identificação e categorização precisa

NPM_CATALOG = {
    # Frameworks
    "next": ("Next.js", TechCategory.FRAMEWORKS, "React Production Framework"),
    "react": ("React", TechCategory.FRAMEWORKS, "JavaScript library for user interfaces"),
    "react-dom": ("React", TechCategory.FRAMEWORKS, "JavaScript library for user interfaces"),
    "vue": ("Vue.js", TechCategory.FRAMEWORKS, "Progressive JavaScript Framework"),
    "nuxt": ("Nuxt", TechCategory.FRAMEWORKS, "Vue Fullstack Framework"),
    "@angular/core": ("Angular", TechCategory.FRAMEWORKS, "Modern Web Developer Platform"),
    "svelte": ("Svelte", TechCategory.FRAMEWORKS, "Cybernetically enhanced web apps"),
    "@sveltejs/kit": ("SvelteKit", TechCategory.FRAMEWORKS, "Application framework for Svelte"),
    "express": ("Express", TechCategory.FRAMEWORKS, "Fast, unopinionated Node.js web framework"),
    "@nestjs/core": ("NestJS", TechCategory.FRAMEWORKS, "Progressive TypeScript enterprise framework"),
    "fastify": ("Fastify", TechCategory.FRAMEWORKS, "Extremely fast and low overhead web framework"),
    "koa": ("Koa", TechCategory.FRAMEWORKS, "Next generation web framework for Node.js"),
    "astro": ("Astro", TechCategory.FRAMEWORKS, "All-in-one web framework"),
    "remix": ("Remix", TechCategory.FRAMEWORKS, "Full stack web framework"),
    "@remix-run/react": ("Remix", TechCategory.FRAMEWORKS, "Full stack web framework"),
    "gatsby": ("Gatsby", TechCategory.FRAMEWORKS, "Static site generator for React"),
    "electron": ("Electron", TechCategory.FRAMEWORKS, "Cross-platform desktop application framework"),
    "react-native": ("React Native", TechCategory.FRAMEWORKS, "Native mobile apps with React"),

    # Databases & ORM
    "prisma": ("Prisma", TechCategory.DATABASES, "Next-generation ORM"),
    "@prisma/client": ("Prisma Client", TechCategory.DATABASES, "Prisma database client"),
    "mongoose": ("Mongoose (MongoDB)", TechCategory.DATABASES, "MongoDB object modeling for Node.js"),
    "typeorm": ("TypeORM", TechCategory.DATABASES, "TypeScript ORM"),
    "sequelize": ("Sequelize", TechCategory.DATABASES, "Promise-based Node.js ORM"),
    "pg": ("PostgreSQL Driver (pg)", TechCategory.DATABASES, "PostgreSQL client for Node.js"),
    "mysql2": ("MySQL Driver", TechCategory.DATABASES, "MySQL client for Node.js"),
    "ioredis": ("Redis (ioredis)", TechCategory.DATABASES, "Robust Redis client"),
    "redis": ("Redis Client", TechCategory.DATABASES, "Redis client for Node.js"),
    "sqlite3": ("SQLite3", TechCategory.DATABASES, "SQLite client for Node.js"),
    "drizzle-orm": ("Drizzle ORM", TechCategory.DATABASES, "TypeScript ORM"),

    # Languages & Compilers
    "typescript": ("TypeScript", TechCategory.LANGUAGES, "Typed superset of JavaScript"),

    # CI / CD & Build Tools
    "vite": ("Vite", TechCategory.FRAMEWORKS, "Next Generation Frontend Tooling"),
    "webpack": ("Webpack", TechCategory.FRAMEWORKS, "Static module bundler"),
    "tailwindcss": ("Tailwind CSS", TechCategory.FRAMEWORKS, "Utility-first CSS framework"),
}

PY_CATALOG = {
    # Frameworks
    "django": ("Django", TechCategory.FRAMEWORKS, "High-level Python web framework"),
    "fastapi": ("FastAPI", TechCategory.FRAMEWORKS, "Modern, fast web framework for building APIs"),
    "flask": ("Flask", TechCategory.FRAMEWORKS, "Lightweight WSGI web application framework"),
    "tornado": ("Tornado", TechCategory.FRAMEWORKS, "Asynchronous networking library"),
    "sanic": ("Sanic", TechCategory.FRAMEWORKS, "Async Python 3.7+ web server and web framework"),
    "pyramid": ("Pyramid", TechCategory.FRAMEWORKS, "Small, fast, down-to-earth Python web framework"),
    "streamlit": ("Streamlit", TechCategory.FRAMEWORKS, "Interactive web apps for machine learning and data science"),
    "gradio": ("Gradio", TechCategory.FRAMEWORKS, "UI components for machine learning models"),

    # Databases & ORMs
    "sqlalchemy": ("SQLAlchemy", TechCategory.DATABASES, "Database Toolkit and ORM"),
    "tortoise-orm": ("Tortoise ORM", TechCategory.DATABASES, "Async ORM for Python"),
    "peewee": ("Peewee", TechCategory.DATABASES, "Simple and small Python ORM"),
    "psycopg2": ("PostgreSQL (psycopg2)", TechCategory.DATABASES, "PostgreSQL adapter for Python"),
    "psycopg2-binary": ("PostgreSQL (psycopg2)", TechCategory.DATABASES, "PostgreSQL adapter for Python"),
    "psycopg": ("PostgreSQL (psycopg3)", TechCategory.DATABASES, "PostgreSQL adapter for Python"),
    "pymongo": ("MongoDB (pymongo)", TechCategory.DATABASES, "Python driver for MongoDB"),
    "motor": ("MongoDB (motor)", TechCategory.DATABASES, "Async Python driver for MongoDB"),
    "redis": ("Redis Client", TechCategory.DATABASES, "Python interface to Redis key-value store"),
    "alembic": ("Alembic", TechCategory.DATABASES, "Database migration tool for SQLAlchemy"),

    # Web Servers
    "gunicorn": ("Gunicorn", TechCategory.WEB_SERVERS, "Python WSGI HTTP Server for UNIX"),
    "uvicorn": ("Uvicorn", TechCategory.WEB_SERVERS, "Lightning-fast ASGI server"),
    "hypercorn": ("Hypercorn", TechCategory.WEB_SERVERS, "ASGI and WSGI Server based on Sans-IO specs"),

    # AI / Data
    "torch": ("PyTorch", TechCategory.FRAMEWORKS, "Deep learning framework"),
    "tensorflow": ("TensorFlow", TechCategory.FRAMEWORKS, "Machine learning platform"),
    "pandas": ("Pandas", TechCategory.FRAMEWORKS, "Data analysis and manipulation library"),
    "numpy": ("NumPy", TechCategory.FRAMEWORKS, "Fundamental package for scientific computing"),
    "scikit-learn": ("Scikit-Learn", TechCategory.FRAMEWORKS, "Machine Learning in Python"),

    # Async & Tasks
    "celery": ("Celery", TechCategory.FRAMEWORKS, "Distributed Task Queue"),
    "pydantic": ("Pydantic", TechCategory.FRAMEWORKS, "Data validation using Python type hints"),
}

COMPOSER_CATALOG = {
    "laravel/framework": ("Laravel", TechCategory.FRAMEWORKS, "The PHP Framework for Web Artisans"),
    "symfony/framework-bundle": ("Symfony", TechCategory.FRAMEWORKS, "Standard PHP Framework"),
    "symfony/symfony": ("Symfony", TechCategory.FRAMEWORKS, "Standard PHP Framework"),
    "yiisoft/yii2": ("Yii 2", TechCategory.FRAMEWORKS, "Yii PHP Framework"),
    "codeigniter4/framework": ("CodeIgniter", TechCategory.FRAMEWORKS, "CodeIgniter PHP Framework"),
    "roots/bedrock": ("WordPress (Bedrock)", TechCategory.FRAMEWORKS, "Modern WordPress stack"),
    "drupal/core": ("Drupal", TechCategory.FRAMEWORKS, "Drupal CMS / Framework"),
    "doctrine/orm": ("Doctrine ORM", TechCategory.DATABASES, "Object-Relational Mapping for PHP"),
    "guzzlehttp/guzzle": ("Guzzle", TechCategory.FRAMEWORKS, "PHP HTTP client"),
}

CARGO_CATALOG = {
    "actix-web": ("Actix-web", TechCategory.FRAMEWORKS, "Powerful, pragmatic, and extremely fast web framework"),
    "axum": ("Axum", TechCategory.FRAMEWORKS, "Ergonomic and modular web framework built with Tokio"),
    "rocket": ("Rocket", TechCategory.FRAMEWORKS, "Web framework for Rust with focus on usability and security"),
    "tokio": ("Tokio", TechCategory.FRAMEWORKS, "Event-driven, non-blocking I/O platform"),
    "diesel": ("Diesel", TechCategory.DATABASES, "Safe, extensible ORM and Query Builder"),
    "sqlx": ("SQLx", TechCategory.DATABASES, "Async SQL toolkit for Rust"),
    "sea-orm": ("SeaORM", TechCategory.DATABASES, "Async & dynamic ORM for Rust"),
}

GEMFILE_CATALOG = {
    "rails": ("Ruby on Rails", TechCategory.FRAMEWORKS, "Ruby MVC web application framework"),
    "sinatra": ("Sinatra", TechCategory.FRAMEWORKS, "Classy web-development dressed in a DSL"),
    "jekyll": ("Jekyll", TechCategory.FRAMEWORKS, "Transform plain text into static websites and blogs"),
    "sidekiq": ("Sidekiq", TechCategory.FRAMEWORKS, "Simple, efficient background processing for Ruby"),
    "devise": ("Devise", TechCategory.FRAMEWORKS, "Flexible authentication solution for Rails"),
    "activerecord": ("ActiveRecord", TechCategory.DATABASES, "Databases on Rails"),
}


class ManifestDetector(BaseDetector):
    """Detector profundo de manifestos de pacotes e dependências."""

    @property
    def name(self) -> str:
        return "ManifestDetector"

    def detect_filesystem(self, root_path: Path, files: Iterable[Path]) -> List[TechItem]:
        items: List[TechItem] = []
        for file_path in files:
            name = file_path.name.lower()
            rel_path = str(file_path.relative_to(root_path)) if file_path.is_relative_to(root_path) else file_path.name

            # 1. Node.js / JavaScript / TypeScript
            if name == "package.json":
                items.extend(self._parse_package_json(file_path, rel_path))
            elif name in {"yarn.lock", "pnpm-lock.yaml", "package-lock.json", "bun.lockb"}:
                pkg_mgr = {
                    "yarn.lock": "Yarn",
                    "pnpm-lock.yaml": "pnpm",
                    "package-lock.json": "npm",
                    "bun.lockb": "Bun",
                }[name]
                items.append(
                    TechItem(
                        name=pkg_mgr,
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=0.9,
                        description="JavaScript / Node.js Package Manager",
                    )
                )

            # 2. Python
            elif name == "requirements.txt" or (name.startswith("requirements") and name.endswith(".txt")):
                items.extend(self._parse_requirements_txt(file_path, rel_path))
            elif name == "pyproject.toml":
                items.extend(self._parse_pyproject_toml(file_path, rel_path))
            elif name == "pipfile":
                items.extend(self._parse_pipfile(file_path, rel_path))
            elif name == "poetry.lock":
                items.append(
                    TechItem(
                        name="Poetry",
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=0.95,
                        description="Python dependency management and packaging tool",
                    )
                )

            # 3. Java / Kotlin
            elif name == "pom.xml":
                items.extend(self._parse_pom_xml(file_path, rel_path))
            elif name in {"build.gradle", "build.gradle.kts"}:
                items.extend(self._parse_gradle(file_path, rel_path))

            # 4. Go
            elif name == "go.mod":
                items.extend(self._parse_go_mod(file_path, rel_path))

            # 5. Rust
            elif name == "cargo.toml":
                items.extend(self._parse_cargo_toml(file_path, rel_path))

            # 6. PHP
            elif name == "composer.json":
                items.extend(self._parse_composer_json(file_path, rel_path))

            # 7. Ruby
            elif name == "gemfile":
                items.extend(self._parse_gemfile(file_path, rel_path))

            # 8. .NET / C#
            elif name.endswith(".csproj") or name.endswith(".fsproj"):
                items.extend(self._parse_csproj(file_path, rel_path))
            elif name == "global.json":
                items.extend(self._parse_dotnet_global_json(file_path, rel_path))

        return items

    # --- Node.js / TypeScript ---
    def _parse_package_json(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = []
        content = safe_read_text(file_path)
        if not content:
            return items

        try:
            data = json.loads(content)
        except Exception:
            return items

        node_version = None
        if "engines" in data and isinstance(data["engines"], dict):
            node_version = clean_version(data["engines"].get("node"))

        items.append(
            TechItem(
                name="Node.js",
                category=TechCategory.LANGUAGES,
                version=node_version,
                source=rel_path,
                confidence=1.0,
                description="JavaScript runtime built on Chrome's V8 engine",
            )
        )

        all_deps = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            if section in data and isinstance(data[section], dict):
                all_deps.update(data[section])

        for dep, raw_ver in all_deps.items():
            dep_lower = dep.lower()
            if dep_lower in NPM_CATALOG:
                tech_name, category, desc = NPM_CATALOG[dep_lower]
                items.append(
                    TechItem(
                        name=tech_name,
                        category=category,
                        version=clean_version(str(raw_ver)),
                        source=f"{rel_path} ({dep})",
                        confidence=1.0,
                        description=desc,
                    )
                )

        return items

    # --- Python ---
    def _parse_requirements_txt(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Python",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=0.9,
                description="Python programming language",
            )
        ]
        content = safe_read_text(file_path)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Extrai nome do pacote e versão: ex: "fastapi>=0.100.0" ou "django==4.2"
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=><~!~^]+)(.+))?", line)
            if match:
                pkg_name = match.group(1).lower().replace("_", "-")
                raw_ver = match.group(3) if match.group(3) else None

                if pkg_name in PY_CATALOG:
                    tech_name, category, desc = PY_CATALOG[pkg_name]
                    items.append(
                        TechItem(
                            name=tech_name,
                            category=category,
                            version=clean_version(raw_ver),
                            source=f"{rel_path}:{line}",
                            confidence=0.95,
                            description=desc,
                        )
                    )
        return items

    def _parse_pyproject_toml(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Python",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=0.95,
                description="Python programming language",
            )
        ]
        content = safe_read_text(file_path)

        # Python version extraction
        py_match = re.search(r'(?:python\s*=\s*["\']([^"\']+)["\']|requires-python\s*=\s*["\']([^"\']+)["\'])', content)
        if py_match:
            raw_v = py_match.group(1) or py_match.group(2)
            items[0].version = clean_version(raw_v)

        for pkg_name, (tech_name, category, desc) in PY_CATALOG.items():
            pattern = rf'["\']?{re.escape(pkg_name)}["\']?\s*(?:=|[>=<~!^]+)\s*["\']?([^"\'\n,\}}]+)?'
            m = re.search(pattern, content, re.IGNORECASE)
            if m:
                raw_ver = m.group(1)
                items.append(
                    TechItem(
                        name=tech_name,
                        category=category,
                        version=clean_version(raw_ver) if raw_ver else None,
                        source=rel_path,
                        confidence=0.95,
                        description=desc,
                    )
                )

        return items

    def _parse_pipfile(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Python",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=0.95,
                description="Python programming language",
            )
        ]
        content = safe_read_text(file_path)
        for pkg_name, (tech_name, category, desc) in PY_CATALOG.items():
            pattern = rf'^{re.escape(pkg_name)}\s*=\s*["\']?([^"\'\n]+)["\']?'
            m = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if m:
                raw_ver = m.group(1)
                items.append(
                    TechItem(
                        name=tech_name,
                        category=category,
                        version=clean_version(raw_ver) if raw_ver != "*" else None,
                        source=rel_path,
                        confidence=0.95,
                        description=desc,
                    )
                )
        return items

    # --- Java / Kotlin ---
    def _parse_pom_xml(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Java",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=1.0,
                description="Java enterprise platform",
            ),
            TechItem(
                name="Maven",
                category=TechCategory.CICD,
                source=rel_path,
                confidence=1.0,
                description="Apache Maven build tool",
            ),
        ]
        content = safe_read_text(file_path)
        if not content:
            return items

        # Spring Boot check
        if "spring-boot" in content:
            sb_version = None
            sb_m = re.search(r"<spring-boot\.version>([^<]+)</spring-boot\.version>", content)
            if not sb_m:
                sb_m = re.search(r"<artifactId>spring-boot-starter-parent</artifactId>\s*<version>([^<]+)</version>", content)
            if sb_m:
                sb_version = clean_version(sb_m.group(1))

            items.append(
                TechItem(
                    name="Spring Boot",
                    category=TechCategory.FRAMEWORKS,
                    version=sb_version,
                    source=rel_path,
                    confidence=1.0,
                    description="Spring Boot enterprise Java framework",
                )
            )

        if "quarkus" in content:
            items.append(
                TechItem(
                    name="Quarkus",
                    category=TechCategory.FRAMEWORKS,
                    source=rel_path,
                    confidence=0.95,
                    description="Supersonic Subatomic Java",
                )
            )

        if "io.micronaut" in content:
            items.append(
                TechItem(
                    name="Micronaut",
                    category=TechCategory.FRAMEWORKS,
                    source=rel_path,
                    confidence=0.95,
                    description="Modern, JVM-based, full-stack framework",
                )
            )

        if "org.hibernate" in content:
            items.append(
                TechItem(
                    name="Hibernate",
                    category=TechCategory.DATABASES,
                    source=rel_path,
                    confidence=0.9,
                    description="Java Object-Relational Mapping (ORM)",
                )
            )

        # Java version
        java_v = re.search(r"<java\.version>([^<]+)</java\.version>", content)
        if not java_v:
            java_v = re.search(r"<maven\.compiler\.source>([^<]+)</maven\.compiler\.source>", content)
        if java_v:
            items[0].version = clean_version(java_v.group(1))

        return items

    def _parse_gradle(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Gradle",
                category=TechCategory.CICD,
                source=rel_path,
                confidence=1.0,
                description="Gradle Build Tool",
            )
        ]
        content = safe_read_text(file_path)
        if "kotlin" in content:
            items.append(
                TechItem(
                    name="Kotlin",
                    category=TechCategory.LANGUAGES,
                    source=rel_path,
                    confidence=0.95,
                    description="Kotlin programming language",
                )
            )
        else:
            items.append(
                TechItem(
                    name="Java",
                    category=TechCategory.LANGUAGES,
                    source=rel_path,
                    confidence=0.9,
                    description="Java programming language",
                )
            )

        if "org.springframework.boot" in content or "spring-boot" in content:
            sb_v = re.search(r'id\s*\(?["\']org\.springframework\.boot["\']\)?\s*version\s*["\']([^"\']+)["\']', content)
            items.append(
                TechItem(
                    name="Spring Boot",
                    category=TechCategory.FRAMEWORKS,
                    version=clean_version(sb_v.group(1)) if sb_v else None,
                    source=rel_path,
                    confidence=1.0,
                    description="Spring Boot application framework",
                )
            )

        if "io.quarkus" in content:
            items.append(
                TechItem(
                    name="Quarkus",
                    category=TechCategory.FRAMEWORKS,
                    source=rel_path,
                    confidence=0.95,
                )
            )

        return items

    # --- Go ---
    def _parse_go_mod(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path)
        items: List[TechItem] = []

        go_version = None
        go_match = re.search(r"^go\s+([0-9\.]+)", content, re.MULTILINE)
        if go_match:
            go_version = go_match.group(1)

        items.append(
            TechItem(
                name="Go",
                category=TechCategory.LANGUAGES,
                version=go_version,
                source=rel_path,
                confidence=1.0,
                description="Go programming language",
            )
        )

        go_frameworks = {
            "github.com/gin-gonic/gin": ("Gin", TechCategory.FRAMEWORKS, "HTTP web framework written in Go"),
            "github.com/labstack/echo": ("Echo", TechCategory.FRAMEWORKS, "High performance, extensible, minimalist Go web framework"),
            "github.com/gofiber/fiber": ("Fiber", TechCategory.FRAMEWORKS, "Express-inspired web framework written in Go"),
            "github.com/go-chi/chi": ("Chi", TechCategory.FRAMEWORKS, "Lightweight, idiomatic and composable router for Go"),
            "gorm.io/gorm": ("GORM", TechCategory.DATABASES, "The fantastic ORM library for Golang"),
            "github.com/spf13/cobra": ("Cobra", TechCategory.FRAMEWORKS, "CLI application library for Go"),
            "google.golang.org/grpc": ("gRPC (Go)", TechCategory.FRAMEWORKS, "RPC framework for Go"),
        }

        for pkg, (name, cat, desc) in go_frameworks.items():
            pattern = rf"{re.escape(pkg)}(?:/v\d+)?\s+v?([0-9a-zA-Z\.\-]+)"
            m = re.search(pattern, content)
            if m:
                items.append(
                    TechItem(
                        name=name,
                        category=cat,
                        version=clean_version(m.group(1)),
                        source=rel_path,
                        confidence=0.95,
                        description=desc,
                    )
                )

        return items

    # --- Rust ---
    def _parse_cargo_toml(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path)
        items: List[TechItem] = [
            TechItem(
                name="Rust",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=1.0,
                description="Rust systems programming language",
            )
        ]

        # Check rust edition
        edition_m = re.search(r'edition\s*=\s*["\'](\d{4})["\']', content)
        if edition_m:
            items[0].version = f"Edition {edition_m.group(1)}"

        for crate, (name, cat, desc) in CARGO_CATALOG.items():
            m = re.search(rf'^{re.escape(crate)}\s*=\s*(?:\{{.*version\s*=\s*|)["\']([^"\']+)["\']', content, re.MULTILINE)
            if m:
                items.append(
                    TechItem(
                        name=name,
                        category=cat,
                        version=clean_version(m.group(1)),
                        source=rel_path,
                        confidence=0.95,
                        description=desc,
                    )
                )

        return items

    # --- PHP ---
    def _parse_composer_json(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path)
        items: List[TechItem] = [
            TechItem(
                name="PHP",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=1.0,
                description="PHP programming language",
            )
        ]
        try:
            data = json.loads(content)
        except Exception:
            return items

        all_reqs = {}
        for sec in ("require", "require-dev"):
            if sec in data and isinstance(data[sec], dict):
                all_reqs.update(data[sec])

        if "php" in all_reqs:
            items[0].version = clean_version(str(all_reqs["php"]))

        for pkg, raw_v in all_reqs.items():
            pkg_lower = pkg.lower()
            if pkg_lower in COMPOSER_CATALOG:
                name, cat, desc = COMPOSER_CATALOG[pkg_lower]
                items.append(
                    TechItem(
                        name=name,
                        category=cat,
                        version=clean_version(str(raw_v)),
                        source=rel_path,
                        confidence=1.0,
                        description=desc,
                    )
                )

        return items

    # --- Ruby ---
    def _parse_gemfile(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path)
        items: List[TechItem] = [
            TechItem(
                name="Ruby",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=1.0,
                description="Ruby programming language",
            )
        ]

        ruby_v = re.search(r'^ruby\s+["\']([^"\']+)["\']', content, re.MULTILINE)
        if ruby_v:
            items[0].version = clean_version(ruby_v.group(1))

        for gem, (name, cat, desc) in GEMFILE_CATALOG.items():
            pattern = rf'gem\s+["\']{re.escape(gem)}["\'](?:\s*,\s*["\']([^"\']+)["\'])?'
            m = re.search(pattern, content)
            if m:
                raw_ver = m.group(1)
                items.append(
                    TechItem(
                        name=name,
                        category=cat,
                        version=clean_version(raw_ver) if raw_ver else None,
                        source=rel_path,
                        confidence=0.95,
                        description=desc,
                    )
                )

        return items

    # --- .NET / C# ---
    def _parse_csproj(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path)
        items: List[TechItem] = [
            TechItem(
                name="C#",
                category=TechCategory.LANGUAGES,
                source=rel_path,
                confidence=1.0,
                description="C# / .NET programming language",
            )
        ]

        tf_match = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", content)
        if tf_match:
            tf = tf_match.group(1)
            items.append(
                TechItem(
                    name=".NET",
                    category=TechCategory.FRAMEWORKS,
                    version=clean_version(tf.replace("net", "")),
                    source=rel_path,
                    confidence=1.0,
                    description=f"Microsoft .NET platform ({tf})",
                )
            )

        if "Microsoft.AspNetCore" in content:
            items.append(
                TechItem(
                    name="ASP.NET Core",
                    category=TechCategory.FRAMEWORKS,
                    source=rel_path,
                    confidence=1.0,
                    description="Open-source, cross-platform web framework for .NET",
                )
            )

        if "Microsoft.EntityFrameworkCore" in content:
            items.append(
                TechItem(
                    name="Entity Framework Core",
                    category=TechCategory.DATABASES,
                    source=rel_path,
                    confidence=1.0,
                    description="ORM for .NET",
                )
            )

        return items

    def _parse_dotnet_global_json(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path)
        items: List[TechItem] = []
        try:
            data = json.loads(content)
            sdk_v = data.get("sdk", {}).get("version")
            if sdk_v:
                items.append(
                    TechItem(
                        name=".NET SDK",
                        category=TechCategory.FRAMEWORKS,
                        version=clean_version(sdk_v),
                        source=rel_path,
                        confidence=1.0,
                        description="Microsoft .NET SDK",
                    )
                )
        except Exception:
            pass
        return items
