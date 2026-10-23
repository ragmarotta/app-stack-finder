"""Data models for technology stack detection."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TechCategory(str, Enum):
    """Categorias oficiais de tecnologias detectadas."""

    LANGUAGES = "Linguagens"
    FRAMEWORKS = "Frameworks"
    DATABASES = "Banco de Dados"
    INFRASTRUCTURE = "Infraestrutura / Cloud"
    CICD = "CI/CD"
    SECURITY = "Segurança / WAF / CDN"
    WEB_SERVERS = "Servidores Web"
    OTHER = "Outros"

    @classmethod
    def from_str(cls, value: str) -> "TechCategory":
        for member in cls:
            if member.value.lower() == value.lower() or member.name.lower() == value.lower():
                return member
        return cls.OTHER


CANONICAL_TECH_NAMES: Dict[str, str] = {
    "amazon alb": "AWS Application Load Balancer (ALB)",
}


@dataclass
class TechItem:
    """Representação de uma tecnologia identificada."""

    name: str
    category: TechCategory
    version: Optional[str] = None
    confidence: float = 1.0  # 0.0 a 1.0
    source: str = ""  # ex: "package.json", "HTTP Header: Server", "Dockerfile"
    description: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def canonical_name(self) -> str:
        return CANONICAL_TECH_NAMES.get(self.name.lower(), self.name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.canonical_name(),
            "category": self.category.value if isinstance(self.category, TechCategory) else str(self.category),
            "version": self.version,
            "confidence": round(self.confidence, 2),
            "source": self.source,
            "description": self.description,
            "details": self.details,
        }

    def key(self) -> tuple[str, str]:
        """Chave única para deduplicação (nome e categoria)."""
        cat_str = self.category.value if isinstance(self.category, TechCategory) else str(self.category)
        return (self.canonical_name().lower(), cat_str.lower())


@dataclass
class ScanTarget:
    """Informações sobre o alvo escaneado."""

    target_type: str  # "url", "directory", "git"
    target_value: str  # URL ou Path ou Git Remote
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Resultado completo da análise de tecnologias."""

    target: ScanTarget
    items: List[TechItem] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def deduplicate_and_merge(self) -> None:
        """Deduplica itens mantendo as informações mais precisas (com versão e maior confiança)."""
        merged: Dict[tuple[str, str], TechItem] = {}

        for item in self.items:
            item.name = item.canonical_name()
            k = item.key()
            if k not in merged:
                merged[k] = item
            else:
                existing = merged[k]
                existing.name = existing.canonical_name()
                # Prefere o item com versão definida
                if not existing.version and item.version:
                    existing.version = item.version
                # Prefere a maior confiança
                if item.confidence > existing.confidence:
                    existing.confidence = item.confidence
                # Concatena fontes distintas
                if item.source and item.source not in existing.source:
                    existing.source = f"{existing.source}, {item.source}"
                # Mescla detalhes
                if item.details:
                    existing.details.update(item.details)
                if not existing.description and item.description:
                    existing.description = item.description

        # Ordenar por Categoria e Nome
        self.items = sorted(
            list(merged.values()),
            key=lambda x: (x.category.value, x.name.lower())
        )

    def by_category(self) -> Dict[TechCategory, List[TechItem]]:
        """Agrupa os itens encontrados por categoria."""
        grouped: Dict[TechCategory, List[TechItem]] = {}
        for cat in TechCategory:
            grouped[cat] = []

        for item in self.items:
            cat = item.category if isinstance(item.category, TechCategory) else TechCategory.from_str(str(item.category))
            grouped.setdefault(cat, []).append(item)

        # Remove categorias vazias
        return {cat: items for cat, items in grouped.items() if items}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "summary": {
                "total_technologies": len(self.items),
                "categories_count": len(self.by_category()),
            },
            "technologies": [item.to_dict() for item in self.items],
            "technologies_by_category": {
                cat.value: [item.to_dict() for item in items]
                for cat, items in self.by_category().items()
            },
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
