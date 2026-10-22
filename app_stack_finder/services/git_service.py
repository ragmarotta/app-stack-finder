"""Git service for safely cloning and accessing remote repositories."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
from urllib.parse import urlparse, urlunparse


class GitServiceError(Exception):
    """Erro em operações Git."""
    pass


class GitService:
    """Serviço para clonar repositórios Git remotos temporariamente."""

    @contextmanager
    def clone_repository(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        token: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        depth: int = 1,
    ) -> Generator[Path, None, None]:
        """Clona um repositório Git em diretório temporário e o limpa automaticamente ao finalizar.

        Args:
            repo_url: URL HTTPS ou SSH do repositório.
            branch: Nome da branch/tag opcional.
            token: Token de acesso pessoal (PAT) opcional para repositórios privados.
            ssh_key_path: Caminho para chave SSH privada opcional.
            depth: Profundidade do clone (padrão 1 para alta velocidade).

        Yields:
            Path: Diretório onde o repositório foi clonado.
        """
        temp_dir = tempfile.mkdtemp(prefix="stack_finder_git_")
        target_path = Path(temp_dir)

        try:
            auth_url = self._prepare_repo_url(repo_url, token)
            cmd = ["git", "clone", "--depth", str(depth)]

            if branch:
                cmd.extend(["--branch", branch])

            cmd.extend([auth_url, str(target_path)])

            env = os.environ.copy()
            if ssh_key_path:
                key_path = Path(ssh_key_path).expanduser().resolve()
                if not key_path.exists():
                    raise GitServiceError(f"Chave SSH não encontrada: {ssh_key_path}")
                env["GIT_SSH_COMMAND"] = f"ssh -i {key_path} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

            # Executa o clone
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                timeout=300,
            )

            if result.returncode != 0:
                # Oculta o token em caso de erro no log
                sanitized_stderr = result.stderr
                if token:
                    sanitized_stderr = sanitized_stderr.replace(token, "***")
                raise GitServiceError(f"Falha ao clonar repositório Git: {sanitized_stderr.strip()}")

            yield target_path

        finally:
            # Limpeza garantida dos arquivos temporários
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _prepare_repo_url(self, repo_url: str, token: Optional[str]) -> str:
        """Insere o token na URL caso seja HTTPS e um token tenha sido fornecido."""
        if not token:
            return repo_url

        parsed = urlparse(repo_url)
        if parsed.scheme in ("http", "https"):
            # Suporta GitHub (x-access-token ou username:token) ou GitLab (oauth2)
            netloc = f"x-access-token:{token}@{parsed.hostname}"
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            return urlunparse(parsed._replace(netloc=netloc))

        return repo_url
