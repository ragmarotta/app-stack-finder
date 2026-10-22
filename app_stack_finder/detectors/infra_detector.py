"""Infrastructure, Containers, Cloud and CI/CD detector."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import TechCategory, TechItem
from app_stack_finder.detectors.base import clean_version, safe_read_text

IMAGE_DB_MAP = {
    "postgres": ("PostgreSQL", TechCategory.DATABASES, "Relational database"),
    "postgresql": ("PostgreSQL", TechCategory.DATABASES, "Relational database"),
    "mysql": ("MySQL", TechCategory.DATABASES, "Relational database"),
    "mariadb": ("MariaDB", TechCategory.DATABASES, "Relational database"),
    "redis": ("Redis", TechCategory.DATABASES, "In-memory data structure store"),
    "mongo": ("MongoDB", TechCategory.DATABASES, "Document database"),
    "mongodb": ("MongoDB", TechCategory.DATABASES, "Document database"),
    "elasticsearch": ("Elasticsearch", TechCategory.DATABASES, "Distributed search and analytics"),
    "rabbitmq": ("RabbitMQ", TechCategory.INFRASTRUCTURE, "Message broker"),
    "kafka": ("Apache Kafka", TechCategory.INFRASTRUCTURE, "Distributed event streaming"),
    "nginx": ("Nginx", TechCategory.WEB_SERVERS, "HTTP and reverse proxy server"),
    "traefik": ("Traefik", TechCategory.WEB_SERVERS, "Cloud Native Application Proxy"),
    "caddy": ("Caddy", TechCategory.WEB_SERVERS, "Fast, multi-platform web server with automatic HTTPS"),
    "httpd": ("Apache HTTP Server", TechCategory.WEB_SERVERS, "Apache Web Server"),
    "minio/minio": ("MinIO", TechCategory.INFRASTRUCTURE, "High Performance Object Storage"),
    "localstack/localstack": ("LocalStack", TechCategory.INFRASTRUCTURE, "Cloud emulator"),
}


class InfraDetector(BaseDetector):
    """Detector para Docker, Kubernetes, Terraform, Ansible, CI/CD e Cloud."""

    @property
    def name(self) -> str:
        return "InfraDetector"

    def detect_filesystem(self, root_path: Path, files: Iterable[Path]) -> List[TechItem]:
        items: List[TechItem] = []
        has_k8s = False
        has_terraform = False
        has_github_actions = False

        for file_path in files:
            name = file_path.name.lower()
            rel_path = str(file_path.relative_to(root_path)) if file_path.is_relative_to(root_path) else file_path.name
            rel_path_posix = rel_path.replace("\\", "/")

            # --- 1. Docker & Containers ---
            if name == "dockerfile" or name.startswith("dockerfile.") or name == "containerfile":
                items.extend(self._parse_dockerfile(file_path, rel_path))

            elif name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
                items.extend(self._parse_docker_compose(file_path, rel_path))

            # --- 2. CI / CD Workflows ---
            elif ".github/workflows/" in rel_path_posix and (name.endswith(".yml") or name.endswith(".yaml")):
                if not has_github_actions:
                    has_github_actions = True
                    items.append(
                        TechItem(
                            name="GitHub Actions",
                            category=TechCategory.CICD,
                            source=rel_path,
                            confidence=1.0,
                            description="GitHub Actions CI/CD workflows",
                        )
                    )
            elif name == ".gitlab-ci.yml":
                items.append(
                    TechItem(
                        name="GitLab CI",
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=1.0,
                        description="GitLab Continuous Integration",
                    )
                )
            elif name == "jenkinsfile" or name.startswith("jenkinsfile."):
                items.append(
                    TechItem(
                        name="Jenkins",
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=1.0,
                        description="Jenkins Automation Server pipeline",
                    )
                )
            elif ".circleci/config.yml" in rel_path_posix:
                items.append(
                    TechItem(
                        name="CircleCI",
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=1.0,
                        description="CircleCI Continuous Integration platform",
                    )
                )
            elif name == "bitbucket-pipelines.yml":
                items.append(
                    TechItem(
                        name="Bitbucket Pipelines",
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=1.0,
                        description="Bitbucket CI/CD pipeline",
                    )
                )
            elif name in {"azure-pipelines.yml", "azure-pipelines.yaml"}:
                items.append(
                    TechItem(
                        name="Azure DevOps Pipelines",
                        category=TechCategory.CICD,
                        source=rel_path,
                        confidence=1.0,
                        description="Azure Pipelines CI/CD",
                    )
                )

            # --- 3. Helm & Kubernetes ---
            elif name == "chart.yaml":
                items.extend(self._parse_helm_chart(file_path, rel_path))

            elif (name.endswith(".yaml") or name.endswith(".yml")) and not has_k8s:
                if self._check_k8s_manifest(file_path):
                    has_k8s = True
                    items.append(
                        TechItem(
                            name="Kubernetes",
                            category=TechCategory.INFRASTRUCTURE,
                            source=rel_path,
                            confidence=0.95,
                            description="Kubernetes container orchestration manifests",
                        )
                    )

            # --- 4. Terraform / IaC ---
            elif name.endswith(".tf") or name.endswith(".tfvars") or name == ".terraform.lock.hcl":
                if not has_terraform:
                    has_terraform = True
                    items.append(
                        TechItem(
                            name="Terraform",
                            category=TechCategory.INFRASTRUCTURE,
                            source=rel_path,
                            confidence=1.0,
                            description="HashiCorp Terraform Infrastructure as Code",
                        )
                    )
                items.extend(self._parse_terraform_providers(file_path, rel_path))

            # --- 5. Ansible ---
            elif name in {"ansible.cfg", "playbook.yml", "site.yml"} or "roles/" in rel_path_posix:
                if name.endswith(".yml") or name.endswith(".cfg"):
                    content = safe_read_text(file_path)
                    if "hosts:" in content or "tasks:" in content or "[defaults]" in content:
                        items.append(
                            TechItem(
                                name="Ansible",
                                category=TechCategory.INFRASTRUCTURE,
                                source=rel_path,
                                confidence=0.9,
                                description="Ansible configuration management and orchestration",
                            )
                        )

            # --- 6. AWS CloudFormation / SAM ---
            elif name in {"samconfig.toml", "template.yaml", "template.yml"}:
                content = safe_read_text(file_path)
                if "AWSTemplateFormatVersion" in content or "Transform: AWS::Serverless" in content:
                    items.append(
                        TechItem(
                            name="AWS CloudFormation",
                            category=TechCategory.INFRASTRUCTURE,
                            source=rel_path,
                            confidence=1.0,
                            description="Amazon Web Services CloudFormation template",
                        )
                    )

            # --- 7. Serverless Framework / Pulumi ---
            elif name in {"serverless.yml", "serverless.yaml", "serverless.ts"}:
                items.append(
                    TechItem(
                        name="Serverless Framework",
                        category=TechCategory.INFRASTRUCTURE,
                        source=rel_path,
                        confidence=1.0,
                        description="Serverless Framework application",
                    )
                )
            elif name == "pulumi.yaml":
                items.append(
                    TechItem(
                        name="Pulumi",
                        category=TechCategory.INFRASTRUCTURE,
                        source=rel_path,
                        confidence=1.0,
                        description="Pulumi modern Infrastructure as Code",
                    )
                )

            # --- 8. Modern Cloud Deployments ---
            elif name == "vercel.json":
                items.append(
                    TechItem(
                        name="Vercel",
                        category=TechCategory.INFRASTRUCTURE,
                        source=rel_path,
                        confidence=1.0,
                        description="Vercel frontend cloud platform configuration",
                    )
                )
            elif name == "netlify.toml":
                items.append(
                    TechItem(
                        name="Netlify",
                        category=TechCategory.INFRASTRUCTURE,
                        source=rel_path,
                        confidence=1.0,
                        description="Netlify cloud web hosting configuration",
                    )
                )
            elif name == "fly.toml":
                items.append(
                    TechItem(
                        name="Fly.io",
                        category=TechCategory.INFRASTRUCTURE,
                        source=rel_path,
                        confidence=1.0,
                        description="Fly.io global application deployment platform",
                    )
                )
            elif name == "procfile":
                items.append(
                    TechItem(
                        name="Heroku",
                        category=TechCategory.INFRASTRUCTURE,
                        source=rel_path,
                        confidence=0.85,
                        description="Heroku Procfile process declaration",
                    )
                )

        return items

    def _parse_dockerfile(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Docker",
                category=TechCategory.INFRASTRUCTURE,
                source=rel_path,
                confidence=1.0,
                description="Docker container build configuration",
            )
        ]
        content = safe_read_text(file_path)
        for line in content.splitlines():
            line = line.strip()
            if line.upper().startswith("FROM "):
                # FROM python:3.11-alpine AS base
                parts = line.split()
                if len(parts) >= 2:
                    raw_img = parts[1]
                    # Parse image name and tag
                    if ":" in raw_img:
                        img_name, tag = raw_img.split(":", 1)
                    else:
                        img_name, tag = raw_img, None

                    base_lower = img_name.split("/")[-1].lower()
                    if base_lower in IMAGE_DB_MAP:
                        name, cat, desc = IMAGE_DB_MAP[base_lower]
                        items.append(
                            TechItem(
                                name=name,
                                category=cat,
                                version=clean_version(tag) if tag else None,
                                source=f"{rel_path} (FROM {raw_img})",
                                confidence=0.9,
                                description=desc,
                            )
                        )
                    # Check Linux Distro or Language inside FROM
                    if "alpine" in raw_img.lower():
                        items.append(
                            TechItem(
                                name="Alpine Linux",
                                category=TechCategory.INFRASTRUCTURE,
                                source=f"{rel_path} (FROM {raw_img})",
                                confidence=0.9,
                                description="Alpine Linux lightweight container image",
                            )
                        )
                    if "ubuntu" in raw_img.lower() or "debian" in raw_img.lower():
                        os_name = "Ubuntu" if "ubuntu" in raw_img.lower() else "Debian"
                        items.append(
                            TechItem(
                                name=os_name,
                                category=TechCategory.INFRASTRUCTURE,
                                source=f"{rel_path} (FROM {raw_img})",
                                confidence=0.85,
                            )
                        )
        return items

    def _parse_docker_compose(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = [
            TechItem(
                name="Docker Compose",
                category=TechCategory.INFRASTRUCTURE,
                source=rel_path,
                confidence=1.0,
                description="Multi-container Docker orchestration",
            )
        ]
        content = safe_read_text(file_path)
        if not content:
            return items

        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return items
        except Exception:
            return items

        # Check docker-compose version
        if "version" in data and isinstance(data["version"], (str, int, float)):
            items[0].version = str(data["version"])

        services = data.get("services")
        if isinstance(services, dict):
            for svc_name, svc_conf in services.items():
                if not isinstance(svc_conf, dict):
                    continue
                image = svc_conf.get("image")
                if image and isinstance(image, str):
                    img_clean = image.split(":")[0].strip()
                    tag = image.split(":")[1].strip() if ":" in image else None
                    base_name = img_clean.split("/")[-1].lower()

                    if base_name in IMAGE_DB_MAP:
                        name, cat, desc = IMAGE_DB_MAP[base_name]
                        items.append(
                            TechItem(
                                name=name,
                                category=cat,
                                version=clean_version(tag) if tag else None,
                                source=f"{rel_path} (service: {svc_name}, image: {image})",
                                confidence=1.0,
                                description=desc,
                            )
                        )
        return items

    def _parse_helm_chart(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = []
        content = safe_read_text(file_path)
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                version = data.get("version")
                items.append(
                    TechItem(
                        name="Helm",
                        category=TechCategory.INFRASTRUCTURE,
                        version=str(version) if version else None,
                        source=rel_path,
                        confidence=1.0,
                        description=f"Helm package manager chart ({data.get('name', '')})",
                    )
                )
        except Exception:
            items.append(
                TechItem(
                    name="Helm",
                    category=TechCategory.INFRASTRUCTURE,
                    source=rel_path,
                    confidence=1.0,
                )
            )
        return items

    def _check_k8s_manifest(self, file_path: Path) -> bool:
        content = safe_read_text(file_path, max_bytes=8192)
        if "apiVersion:" in content and "kind:" in content:
            kinds = {"deployment", "service", "ingress", "pod", "statefulset", "daemonset", "configmap", "secret"}
            for k in kinds:
                if re.search(rf"\bkind:\s*{k}\b", content, re.IGNORECASE):
                    return True
        return False

    def _parse_terraform_providers(self, file_path: Path, rel_path: str) -> List[TechItem]:
        items: List[TechItem] = []
        content = safe_read_text(file_path)
        provider_map = {
            "aws": ("AWS (Amazon Web Services)", TechCategory.INFRASTRUCTURE),
            "azurerm": ("Microsoft Azure", TechCategory.INFRASTRUCTURE),
            "google": ("Google Cloud Platform (GCP)", TechCategory.INFRASTRUCTURE),
            "cloudflare": ("Cloudflare", TechCategory.SECURITY),
            "kubernetes": ("Kubernetes", TechCategory.INFRASTRUCTURE),
            "helm": ("Helm", TechCategory.INFRASTRUCTURE),
            "datadog": ("Datadog", TechCategory.INFRASTRUCTURE),
        }

        for prov, (tech_name, cat) in provider_map.items():
            pattern = rf'(?:provider\s+["\']?{prov}["\']?|source\s*=\s*["\'][^"\']*/{prov}["\'])'
            if re.search(pattern, content, re.IGNORECASE):
                items.append(
                    TechItem(
                        name=tech_name,
                        category=cat,
                        source=rel_path,
                        confidence=0.9,
                        description=f"Managed via Terraform provider '{prov}'",
                    )
                )
        return items
