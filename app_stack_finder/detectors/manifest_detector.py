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

    # HTTP & Networking
    "requests": ("Requests", TechCategory.FRAMEWORKS, "HTTP library for Python"),
    "httpx": ("HTTPX", TechCategory.FRAMEWORKS, "Next-generation HTTP client for Python"),
    "aiohttp": ("aiohttp", TechCategory.FRAMEWORKS, "Async HTTP client/server for asyncio and Python"),
    "urllib3": ("urllib3", TechCategory.FRAMEWORKS, "HTTP library with thread-safe connection pooling"),

    # Enterprise DB Drivers
    "cx-oracle": ("Oracle DB (cx_Oracle)", TechCategory.DATABASES, "Oracle Database interface for Python"),
    "oracledb": ("Oracle DB (python-oracledb)", TechCategory.DATABASES, "Python driver for Oracle Database"),
    "pymysql": ("MySQL (PyMySQL)", TechCategory.DATABASES, "Pure Python MySQL client"),
    "asyncpg": ("PostgreSQL (asyncpg)", TechCategory.DATABASES, "Fast async PostgreSQL driver for Python"),

    # Cloud SDKs & Security
    "boto3": ("AWS SDK (Boto3)", TechCategory.INFRASTRUCTURE, "AWS SDK for Python"),
    "google-cloud-storage": ("Google Cloud SDK", TechCategory.INFRASTRUCTURE, "Google Cloud client library"),
    "azure-storage-blob": ("Azure SDK", TechCategory.INFRASTRUCTURE, "Azure client library"),
    "cryptography": ("Cryptography", TechCategory.SECURITY, "Cryptographic primitives for Python"),

    # Testing & Quality
    "pytest": ("Pytest", TechCategory.CICD, "Testing framework for Python"),
    "black": ("Black", TechCategory.CICD, "Python code formatter"),
    "ruff": ("Ruff", TechCategory.CICD, "Fast Python linter and formatter"),
    "mypy": ("Mypy", TechCategory.CICD, "Static type checker for Python"),
}

MAVEN_CATALOG = {
    # Spring Boot
    "org.springframework.boot:spring-boot": ("Spring Boot", TechCategory.FRAMEWORKS, "Spring Boot enterprise Java framework"),
    "org.springframework.boot:spring-boot-starter": ("Spring Boot", TechCategory.FRAMEWORKS, "Spring Boot starter"),
    "org.springframework.boot:spring-boot-starter-web": ("Spring Boot", TechCategory.FRAMEWORKS, "Spring Boot Web starter"),
    "org.springframework.boot:spring-boot-starter-data-jpa": ("Spring Boot Data JPA", TechCategory.FRAMEWORKS, "Spring Boot Data JPA starter"),
    "org.springframework.boot:spring-boot-starter-security": ("Spring Boot Security", TechCategory.FRAMEWORKS, "Spring Boot Security starter"),

    # Spring Framework
    "org.springframework:spring-webmvc": ("Spring MVC", TechCategory.FRAMEWORKS, "Spring MVC web framework"),
    "org.springframework:spring-web": ("Spring Framework", TechCategory.FRAMEWORKS, "Spring Web framework"),
    "org.springframework:spring-context": ("Spring Framework", TechCategory.FRAMEWORKS, "Spring Core / Context framework"),
    "org.springframework.security:spring-security-core": ("Spring Security", TechCategory.FRAMEWORKS, "Spring Security framework"),
    "org.springframework.security:spring-security-web": ("Spring Security", TechCategory.FRAMEWORKS, "Spring Security Web framework"),
    "org.springframework.data:spring-data-jpa": ("Spring Data JPA", TechCategory.DATABASES, "Spring Data JPA repository abstraction"),

    # Quarkus
    "io.quarkus:quarkus-core": ("Quarkus", TechCategory.FRAMEWORKS, "Supersonic Subatomic Java"),
    "io.quarkus:quarkus-resteasy": ("Quarkus", TechCategory.FRAMEWORKS, "Quarkus REST framework"),
    "io.quarkus:quarkus-resteasy-reactive": ("Quarkus", TechCategory.FRAMEWORKS, "Quarkus Reactive REST framework"),
    "io.quarkus:quarkus-universe-bom": ("Quarkus", TechCategory.FRAMEWORKS, "Quarkus BOM"),

    # Micronaut
    "io.micronaut:micronaut-core": ("Micronaut", TechCategory.FRAMEWORKS, "Modern JVM-based full-stack framework"),
    "io.micronaut:micronaut-runtime": ("Micronaut", TechCategory.FRAMEWORKS, "Micronaut Runtime"),
    "io.micronaut:micronaut-http-server-netty": ("Micronaut", TechCategory.FRAMEWORKS, "Micronaut HTTP Server Netty"),

    # JavaServer Faces (JSF) / Jakarta Faces
    "javax.faces:javax.faces-api": ("JavaServer Faces (JSF)", TechCategory.FRAMEWORKS, "JavaServer Faces UI framework"),
    "jakarta.faces:jakarta.faces-api": ("Jakarta Faces (JSF)", TechCategory.FRAMEWORKS, "Jakarta Faces UI framework"),
    "org.glassfish:jakarta.faces": ("Mojarra (Jakarta Faces)", TechCategory.FRAMEWORKS, "GlassFish / Eclipse Mojarra JSF Implementation"),
    "org.glassfish:javax.faces": ("Mojarra (JSF)", TechCategory.FRAMEWORKS, "Mojarra JSF Implementation"),
    "com.sun.faces:jsf-api": ("JavaServer Faces (JSF)", TechCategory.FRAMEWORKS, "Sun / Oracle JSF API"),
    "com.sun.faces:jsf-impl": ("Mojarra (JSF)", TechCategory.FRAMEWORKS, "Sun / Oracle Mojarra JSF Implementation"),
    "org.apache.myfaces.core:myfaces-api": ("Apache MyFaces (JSF)", TechCategory.FRAMEWORKS, "Apache MyFaces JSF Implementation"),
    "org.apache.myfaces.core:myfaces-impl": ("Apache MyFaces (JSF)", TechCategory.FRAMEWORKS, "Apache MyFaces JSF Implementation"),

    # PrimeFaces
    "org.primefaces:primefaces": ("PrimeFaces", TechCategory.FRAMEWORKS, "Popular UI Component Suite for JSF"),
    "org.primefaces.extensions:primefaces-extensions": ("PrimeFaces Extensions", TechCategory.FRAMEWORKS, "Extended components for PrimeFaces"),

    # RichFaces / Ajax4jsf
    "org.richfaces:richfaces": ("RichFaces", TechCategory.FRAMEWORKS, "Advanced UI component library for JSF"),
    "org.richfaces:richfaces-core": ("RichFaces", TechCategory.FRAMEWORKS, "RichFaces Core"),
    "org.richfaces.framework:richfaces-impl": ("RichFaces", TechCategory.FRAMEWORKS, "RichFaces Implementation"),
    "org.richfaces.ui:richfaces-ui": ("RichFaces", TechCategory.FRAMEWORKS, "RichFaces UI components"),
    "org.ajax4jsf:ajax4jsf": ("Ajax4jsf", TechCategory.FRAMEWORKS, "AJAX framework for JavaServer Faces"),

    # JBoss Seam
    "org.jboss.seam:jboss-seam": ("JBoss Seam", TechCategory.FRAMEWORKS, "Powerful application framework for Java EE"),
    "org.jboss.seam:jboss-seam-ui": ("JBoss Seam", TechCategory.FRAMEWORKS, "JBoss Seam UI"),

    # Apache Struts
    "org.apache.struts:struts2-core": ("Apache Struts", TechCategory.FRAMEWORKS, "Enterprise Java web application framework"),
    "struts:struts": ("Apache Struts 1", TechCategory.FRAMEWORKS, "Classic Apache Struts 1 framework"),

    # ORM / Persistence
    "org.hibernate:hibernate-core": ("Hibernate ORM", TechCategory.DATABASES, "Java Object-Relational Mapping (ORM)"),
    "org.hibernate.orm:hibernate-core": ("Hibernate ORM", TechCategory.DATABASES, "Java Object-Relational Mapping (ORM)"),
    "org.eclipse.persistence:eclipselink": ("EclipseLink", TechCategory.DATABASES, "JPA reference implementation"),
    "org.mybatis:mybatis": ("MyBatis", TechCategory.DATABASES, "First-class persistence framework with custom SQL"),

    # Database Drivers
    "org.postgresql:postgresql": ("PostgreSQL Driver", TechCategory.DATABASES, "Official JDBC driver for PostgreSQL"),
    "com.oracle.database.jdbc:ojdbc8": ("Oracle JDBC Driver", TechCategory.DATABASES, "Oracle Database JDBC Driver"),
    "com.oracle.database.jdbc:ojdbc11": ("Oracle JDBC Driver", TechCategory.DATABASES, "Oracle Database JDBC Driver"),
    "com.oracle.ojdbc:ojdbc8": ("Oracle JDBC Driver", TechCategory.DATABASES, "Oracle Database JDBC Driver"),
    "com.oracle:ojdbc6": ("Oracle JDBC Driver", TechCategory.DATABASES, "Oracle Database JDBC Driver"),
    "com.oracle:ojdbc14": ("Oracle JDBC Driver", TechCategory.DATABASES, "Oracle Database JDBC Driver"),
    "com.mysql:mysql-connector-j": ("MySQL Driver", TechCategory.DATABASES, "Official MySQL JDBC Driver"),
    "mysql:mysql-connector-java": ("MySQL Driver", TechCategory.DATABASES, "MySQL JDBC Driver"),
    "com.microsoft.sqlserver:mssql-jdbc": ("Microsoft SQL Server Driver", TechCategory.DATABASES, "Microsoft JDBC Driver for SQL Server"),
    "org.mariadb.jdbc:mariadb-java-client": ("MariaDB Driver", TechCategory.DATABASES, "MariaDB JDBC Driver"),
    "com.h2database:h2": ("H2 Database", TechCategory.DATABASES, "H2 In-Memory Java Database"),

    # Integration & Messaging
    "org.apache.camel:camel-core": ("Apache Camel", TechCategory.FRAMEWORKS, "Versatile open-source integration framework"),
    "org.apache.kafka:kafka-clients": ("Apache Kafka Client", TechCategory.FRAMEWORKS, "Apache Kafka event streaming client"),
    "com.rabbitmq:amqp-client": ("RabbitMQ Client", TechCategory.FRAMEWORKS, "Official RabbitMQ Java Client"),

    # Migrations
    "org.flywaydb:flyway-core": ("Flyway", TechCategory.DATABASES, "Database migration tool"),
    "org.liquibase:liquibase-core": ("Liquibase", TechCategory.DATABASES, "Database change management"),

    # Servlets / Web Servers
    "org.apache.tomcat:tomcat-catalina": ("Apache Tomcat", TechCategory.WEB_SERVERS, "Java Servlet Container"),
    "org.eclipse.jetty:jetty-server": ("Jetty", TechCategory.WEB_SERVERS, "Lightweight HTTP server and Servlet engine"),
    "io.undertow:undertow-core": ("Undertow", TechCategory.WEB_SERVERS, "Flexible performant web server from JBoss"),
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

            # 0. Version Manager & Runtime Environment Files (.python-version, runtime.txt, .tool-versions, .nvmrc)
            if name == ".python-version":
                items.extend(self._parse_python_version_file(file_path, rel_path))
            elif name == "runtime.txt":
                items.extend(self._parse_runtime_txt(file_path, rel_path))
            elif name == ".tool-versions":
                items.extend(self._parse_tool_versions(file_path, rel_path))
            elif name in {".nvmrc", ".node-version"}:
                items.extend(self._parse_nvmrc(file_path, rel_path))

            # 1. Node.js / JavaScript / TypeScript
            elif name == "package.json":
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

    # --- Python Version Managers & Runtime Files ---
    def _parse_python_version_file(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path).strip()
        if not content:
            return []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                v = clean_version(line)
                if v:
                    return [
                        TechItem(
                            name="Python",
                            category=TechCategory.LANGUAGES,
                            version=v,
                            source=rel_path,
                            confidence=1.0,
                            description="Python programming language",
                        )
                    ]
        return []

    def _parse_runtime_txt(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path).strip()
        if not content:
            return []
        line = content.splitlines()[0].strip()
        if line.lower().startswith(("python-", "python ")):
            v = clean_version(re.sub(r"^python[- ]", "", line, flags=re.IGNORECASE))
            return [TechItem(name="Python", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0)]
        elif line.lower().startswith(("java-", "java ")):
            v = clean_version(re.sub(r"^java[- ]", "", line, flags=re.IGNORECASE))
            return [TechItem(name="Java", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0)]
        elif line.lower().startswith(("ruby-", "ruby ")):
            v = clean_version(re.sub(r"^ruby[- ]", "", line, flags=re.IGNORECASE))
            return [TechItem(name="Ruby", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0)]
        elif line.lower().startswith(("nodejs-", "node-")):
            v = clean_version(re.sub(r"^node(js)?[- ]", "", line, flags=re.IGNORECASE))
            return [TechItem(name="Node.js", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0)]
        return []

    def _parse_tool_versions(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = []
        content = safe_read_text(file_path)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                tool, raw_v = parts[0].lower(), parts[1]
                v = clean_version(raw_v)
                if tool == "python":
                    items.append(TechItem(name="Python", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0))
                elif tool in ("nodejs", "node"):
                    items.append(TechItem(name="Node.js", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0))
                elif tool == "java":
                    items.append(TechItem(name="Java", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0))
                elif tool == "golang":
                    items.append(TechItem(name="Go", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0))
                elif tool == "ruby":
                    items.append(TechItem(name="Ruby", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0))
                elif tool == "rust":
                    items.append(TechItem(name="Rust", category=TechCategory.LANGUAGES, version=v, source=rel_path, confidence=1.0))
        return items

    def _parse_nvmrc(self, file_path: Path, rel_path: str) -> List[TechItem]:
        content = safe_read_text(file_path).strip()
        if content:
            line = content.splitlines()[0].strip()
            v = clean_version(line)
            if v:
                return [
                    TechItem(
                        name="Node.js",
                        category=TechCategory.LANGUAGES,
                        version=v,
                        source=rel_path,
                        confidence=1.0,
                        description="Node.js version manager configuration",
                    )
                ]
        return []

    # --- Python ---
    def _parse_requirements_txt(self, file_path: Path, rel_path: str) -> List[TechItem]:
        py_item = TechItem(
            name="Python",
            category=TechCategory.LANGUAGES,
            source=rel_path,
            confidence=0.9,
            description="Python programming language",
        )
        items: List[TechItem] = [py_item]
        content = safe_read_text(file_path)

        # Checa se há versão do Python declarada em comentários (ex: # Python 3.11, # python: 3.12, # requires-python: >=3.10)
        py_ver_match = re.search(r"^\s*#\s*(?:python|requires-python)[:\s]+([0-9\.]+)", content, re.IGNORECASE | re.MULTILINE)
        if py_ver_match:
            py_item.version = clean_version(py_ver_match.group(1))

        # Checa marcadores de ambiente com python_version (ex: python_version >= '3.11' ou python_version == "3.10")
        if not py_item.version:
            marker_match = re.search(r'python_version\s*(?:==|>=)\s*["\']([0-9\.]+)["\']', content)
            if marker_match:
                py_item.version = clean_version(marker_match.group(1))

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Remove comentários inline e marcadores de ambiente após ';'
            line_clean = line.split("#")[0].split(";")[0].strip()

            # Extrai nome do pacote e versão: ex: "fastapi>=0.100.0" ou "django==4.2"
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=><~!~^]+)(.+))?", line_clean)
            if match:
                pkg_raw = match.group(1)
                pkg_name = pkg_raw.lower().replace("_", "-")
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
                elif raw_ver:
                    cleaned_v = clean_version(raw_ver)
                    if cleaned_v:
                        items.append(
                            TechItem(
                                name=pkg_raw,
                                category=TechCategory.FRAMEWORKS,
                                version=cleaned_v,
                                source=f"{rel_path}:{line}",
                                confidence=0.8,
                                description=f"Python dependency: {pkg_raw}",
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
        # Check python_version under [requires]
        req_match = re.search(r'python_version\s*=\s*["\']([^"\']+)["\']', content)
        if req_match:
            items[0].version = clean_version(req_match.group(1))

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

        properties: Dict[str, str] = {}
        java_version = None

        try:
            # Remove namespace padrão do POM para facilitar consultas ElementTree
            xml_clean = re.sub(r'\sxmlns="[^"]+"', "", content, count=1)
            root = ET.fromstring(xml_clean)

            # 1. Coleta todas as properties
            props_elem = root.find("properties")
            if props_elem is not None:
                for child in props_elem:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child.text:
                        properties[tag] = child.text.strip()

            def resolve_val(val: Optional[str]) -> Optional[str]:
                if not val:
                    return None
                val = val.strip()
                for _ in range(5):
                    m = re.search(r"\$\{([^}]+)\}", val)
                    if not m:
                        break
                    prop_name = m.group(1)
                    if prop_name in properties:
                        val = val.replace(m.group(0), properties[prop_name])
                    elif prop_name in ("project.version", "version"):
                        proj_ver = root.findtext("version", "")
                        if proj_ver:
                            val = val.replace(m.group(0), proj_ver.strip())
                        else:
                            break
                    else:
                        break
                return val

            # 2. Identifica Java Version
            for j_key in ("java.version", "java-version", "maven.compiler.release", "maven.compiler.source", "maven.compiler.target", "jdk.version", "targetJdk"):
                if j_key in properties:
                    java_version = resolve_val(properties[j_key])
                    break

            if not java_version:
                for plugin in root.findall(".//plugins/plugin"):
                    aid = plugin.findtext("artifactId", "")
                    if aid == "maven-compiler-plugin":
                        cfg = plugin.find("configuration")
                        if cfg is not None:
                            rel = cfg.findtext("release") or cfg.findtext("source") or cfg.findtext("target")
                            if rel:
                                java_version = resolve_val(rel)
                                break

            # 3. Analisa Parent
            parent = root.find("parent")
            if parent is not None:
                p_aid = parent.findtext("artifactId", "").strip()
                p_ver = resolve_val(parent.findtext("version", ""))
                if "spring-boot" in p_aid:
                    items.append(
                        TechItem(
                            name="Spring Boot",
                            category=TechCategory.FRAMEWORKS,
                            version=clean_version(p_ver),
                            source=f"{rel_path} (parent: {p_aid})",
                            confidence=1.0,
                            description="Spring Boot enterprise Java framework",
                        )
                    )
                elif "quarkus" in p_aid:
                    items.append(
                        TechItem(
                            name="Quarkus",
                            category=TechCategory.FRAMEWORKS,
                            version=clean_version(p_ver),
                            source=f"{rel_path} (parent: {p_aid})",
                            confidence=1.0,
                            description="Supersonic Subatomic Java",
                        )
                    )

            # 4. Varre todas as dependencies
            for dep in root.findall(".//dependencies/dependency"):
                gid = dep.findtext("groupId", "").strip()
                aid = dep.findtext("artifactId", "").strip()
                raw_v = resolve_val(dep.findtext("version", ""))

                key = f"{gid}:{aid}".lower()
                matched_tech = None
                matched_category = TechCategory.FRAMEWORKS
                matched_desc = f"Java dependency {key}"

                if key in MAVEN_CATALOG:
                    matched_tech, matched_category, matched_desc = MAVEN_CATALOG[key]
                elif gid == "org.springframework.boot":
                    matched_tech = "Spring Boot"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "Spring Boot dependency"
                    if not raw_v and "spring-boot.version" in properties:
                        raw_v = resolve_val(properties["spring-boot.version"])
                elif gid.startswith("org.springframework"):
                    matched_tech = "Spring Framework"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "Spring Framework dependency"
                    if not raw_v and "spring.version" in properties:
                        raw_v = resolve_val(properties["spring.version"])
                elif gid.startswith("io.quarkus"):
                    matched_tech = "Quarkus"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "Quarkus framework"
                    if not raw_v:
                        for q_prop in ("quarkus.platform.version", "quarkus.version"):
                            if q_prop in properties:
                                raw_v = resolve_val(properties[q_prop])
                                break
                elif gid.startswith("io.micronaut"):
                    matched_tech = "Micronaut"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "Micronaut framework"
                    if not raw_v and "micronaut.version" in properties:
                        raw_v = resolve_val(properties["micronaut.version"])
                elif "richfaces" in gid or "richfaces" in aid:
                    matched_tech = "RichFaces"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "RichFaces component suite for JSF"
                    if not raw_v and "richfaces.version" in properties:
                        raw_v = resolve_val(properties["richfaces.version"])
                elif "primefaces" in gid or "primefaces" in aid:
                    matched_tech = "PrimeFaces"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "PrimeFaces component suite for JSF"
                    if not raw_v and "primefaces.version" in properties:
                        raw_v = resolve_val(properties["primefaces.version"])
                elif ("faces" in gid or "faces" in aid or "mojarra" in aid or "myfaces" in gid) and "test" not in aid:
                    matched_tech = "JavaServer Faces (JSF)"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "JavaServer Faces (JSF)"
                    if not raw_v and "jsf.version" in properties:
                        raw_v = resolve_val(properties["jsf.version"])
                elif "seam" in gid or "seam" in aid:
                    matched_tech = "JBoss Seam"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "JBoss Seam framework"
                    if not raw_v and "seam.version" in properties:
                        raw_v = resolve_val(properties["seam.version"])
                elif "struts" in gid or "struts" in aid:
                    matched_tech = "Apache Struts"
                    matched_category = TechCategory.FRAMEWORKS
                    matched_desc = "Apache Struts framework"
                    if not raw_v and "struts.version" in properties:
                        raw_v = resolve_val(properties["struts.version"])
                elif "hibernate" in gid and "hibernate" in aid:
                    matched_tech = "Hibernate ORM"
                    matched_category = TechCategory.DATABASES
                    matched_desc = "Hibernate ORM"
                    if not raw_v and "hibernate.version" in properties:
                        raw_v = resolve_val(properties["hibernate.version"])

                if matched_tech:
                    items.append(
                        TechItem(
                            name=matched_tech,
                            category=matched_category,
                            version=clean_version(raw_v),
                            source=f"{rel_path} ({gid}:{aid})",
                            confidence=0.95,
                            description=matched_desc,
                        )
                    )

        except Exception:
            # Fallback regex para POMs com XML mal formatado
            if "spring-boot" in content:
                sb_m = re.search(r"<spring-boot\.version>([^<]+)</spring-boot\.version>", content)
                if not sb_m:
                    sb_m = re.search(r"<artifactId>spring-boot-starter-parent</artifactId>[\s\S]*?<version>([^<]+)</version>", content)
                items.append(
                    TechItem(
                        name="Spring Boot",
                        category=TechCategory.FRAMEWORKS,
                        version=clean_version(sb_m.group(1)) if sb_m else None,
                        source=rel_path,
                        confidence=0.95,
                        description="Spring Boot enterprise Java framework",
                    )
                )

        if not java_version:
            jv_m = re.search(r"<(?:java\.version|java-version|maven\.compiler\.release|maven\.compiler\.source|maven\.compiler\.target)>([^<]+)</", content)
            if jv_m:
                java_version = jv_m.group(1)

        if java_version:
            items[0].version = clean_version(java_version)

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

        # Detecta Java / Kotlin
        is_kotlin = "kotlin" in content
        lang_name = "Kotlin" if is_kotlin else "Java"

        # Java version in Gradle
        java_v = None
        jv_m = re.search(r'(?:sourceCompatibility|targetCompatibility)\s*=\s*["\']?([0-9\._]+|JavaVersion\.VERSION_[0-9_]+)["\']?', content)
        if jv_m:
            raw_jv = jv_m.group(1).replace("JavaVersion.VERSION_", "").replace("_", ".")
            java_v = clean_version(raw_jv)
        else:
            tc_m = re.search(r'(?:jvmToolchain|JavaLanguageVersion\.of)\s*\(?\s*([0-9]+)\s*\)?', content)
            if tc_m:
                java_v = clean_version(tc_m.group(1))

        # Kotlin version in Gradle
        kotlin_v = None
        if is_kotlin:
            kt_m = re.search(r'id\s*\(?["\']org\.jetbrains\.kotlin[a-zA-Z0-9\.\-]*["\']\)?\s*version\s*["\']([^"\']+)["\']', content)
            if kt_m:
                kotlin_v = clean_version(kt_m.group(1))

        if is_kotlin:
            items.append(
                TechItem(
                    name="Kotlin",
                    category=TechCategory.LANGUAGES,
                    version=kotlin_v,
                    source=rel_path,
                    confidence=0.95,
                    description="Kotlin programming language",
                )
            )
            if java_v:
                items.append(
                    TechItem(
                        name="Java",
                        category=TechCategory.LANGUAGES,
                        version=java_v,
                        source=rel_path,
                        confidence=0.9,
                        description="Java platform target",
                    )
                )
        else:
            items.append(
                TechItem(
                    name="Java",
                    category=TechCategory.LANGUAGES,
                    version=java_v,
                    source=rel_path,
                    confidence=0.9,
                    description="Java programming language",
                )
            )

        if "org.springframework.boot" in content or "spring-boot" in content:
            sb_v = re.search(r'(?:id\s*\(?["\']org\.springframework\.boot["\']\)?|springBootVersion)\s*(?:version\s*|,\s*|=>\s*|=)?\s*["\']([^"\']+)["\']', content)
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
            q_v = re.search(r'id\s*\(?["\']io\.quarkus["\']\)?\s*version\s*["\']([^"\']+)["\']', content)
            items.append(
                TechItem(
                    name="Quarkus",
                    category=TechCategory.FRAMEWORKS,
                    version=clean_version(q_v.group(1)) if q_v else None,
                    source=rel_path,
                    confidence=0.95,
                    description="Supersonic Subatomic Java",
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
