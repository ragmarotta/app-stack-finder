"""Optimized file system walker that avoids scanning unnecessary or heavy directories."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator, Iterable, Optional, Set

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "target",  # Maven / Cargo
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".output",
    "vendor",  # Composer / Go
    ".terraform",
    ".idea",
    ".vscode",
    ".vs",
    "bin",
    "obj",
    "coverage",
    ".serverless",
}


def walk_files(
    root_path: Path,
    ignored_dirs: Optional[Iterable[str]] = None,
    max_depth: Optional[int] = 12,
) -> Generator[Path, None, None]:
    """Varre diretórios de forma preguiçosa (stream/generator), podando diretórios ignorados.

    Args:
        root_path: Diretório raiz para iniciar a busca.
        ignored_dirs: Conjunto de nomes de pastas a ignorar.
        max_depth: Profundidade máxima de recursão no diretório.

    Yields:
        Path: Caminho absoluto para cada arquivo encontrado.
    """
    ignore_set = set(DEFAULT_IGNORED_DIRS)
    if ignored_dirs:
        ignore_set.update(ignored_dirs)

    root_resolved = root_path.resolve()
    base_depth = len(root_resolved.parts)

    for dirpath, dirnames, filenames in os.walk(root_resolved, topdown=True, followlinks=False):
        current_path = Path(dirpath)
        current_depth = len(current_path.parts) - base_depth

        # Modifica dirnames in-place para podar subárvores inteiras (não descer nessas pastas)
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in ignore_set and not (d.startswith(".") and d not in {".github", ".circleci"})
        ]

        if max_depth is not None and current_depth >= max_depth:
            dirnames.clear()
            continue

        for filename in filenames:
            yield current_path / filename
