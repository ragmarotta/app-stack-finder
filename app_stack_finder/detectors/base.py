"""Base utilities and abstractions for detectors."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import TechCategory, TechItem


def clean_version(raw_version: Optional[str]) -> Optional[str]:
    """Limpa caracteres de prefixo como ^, ~, >=, ==, <=, etc. e sufixos de containers."""
    if not raw_version:
        return None
    cleaned = raw_version.strip()
    # Remove prefixos comuns de dependências npm, cargo, pip, composer
    cleaned = re.sub(r"^[~^><=!v\s]+", "", cleaned)
    # Remove sufixos como -alpine, -slim, etc.
    cleaned = re.sub(r"-(alpine|slim|bullseye|bookworm|buster|windowsservercore|nanoserver)[a-zA-Z0-9\.\-]*$", "", cleaned, flags=re.IGNORECASE)
    # Extrai números de versão
    match = re.search(r"(\d+(?:\.\d+)+)", cleaned)
    if match:
        return match.group(1)
    match_single = re.search(r"^(\d+)", cleaned)
    if match_single:
        return match_single.group(1)
    return cleaned if cleaned else None


def safe_read_text(file_path: Path, max_bytes: int = 512 * 1024) -> str:
    """Lê arquivo de texto com limite de tamanho e fallback de codificação para evitar OOM."""
    try:
        with open(file_path, "rb") as f:
            raw = f.read(max_bytes)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="ignore")
    except Exception:
        return ""
