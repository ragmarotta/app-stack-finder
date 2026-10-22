"""Abstract interfaces for stack detection modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterable, List

from app_stack_finder.core.models import TechItem


class BaseDetector(ABC):
    """Contrato base para detectores de tecnologias."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome identificador do detector."""
        pass

    @property
    def description(self) -> str:
        """Descrição sucinta do detector."""
        return self.__doc__ or ""

    @property
    def supports_filesystem(self) -> bool:
        """Indica se este detector processa arquivos locais/repositórios."""
        return True

    @property
    def supports_url(self) -> bool:
        """Indica se este detector analisa endpoints HTTP/S."""
        return False

    def detect_filesystem(self, root_path: Path, files: Iterable[Path]) -> List[TechItem]:
        """Executa a análise em arquivos do sistema local."""
        return []

    async def detect_url(self, url: str, response_data: Dict[str, Any]) -> List[TechItem]:
        """Executa a análise em respostas HTTP/S."""
        return []
