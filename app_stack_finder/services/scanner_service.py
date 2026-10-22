"""Orchestrator service for scanning URLs, local directories, and remote Git repositories."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import httpx

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import ScanResult, ScanTarget, TechItem
from app_stack_finder.detectors import DEFAULT_DETECTORS
from app_stack_finder.services.git_service import GitService
from app_stack_finder.utils.file_walker import walk_files

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; AppStackFinder/1.0; +https://github.com/app-stack-finder)"


class ScannerService:
    """Serviço principal que orquestra a execução dos detectores sobre os alvos."""

    def __init__(
        self,
        detectors: Optional[List[BaseDetector]] = None,
        git_service: Optional[GitService] = None,
    ):
        self.detectors = detectors if detectors is not None else list(DEFAULT_DETECTORS)
        self.git_service = git_service or GitService()

    def register_detector(self, detector: BaseDetector) -> None:
        """Permite adicionar novos detectores em tempo de execução (Open-Closed Principle)."""
        self.detectors.append(detector)

    # --- Escaneamento de Diretório Local ---
    def scan_directory(
        self,
        dir_path: str | Path,
        ignored_dirs: Optional[Iterable[str]] = None,
        max_depth: int = 12,
    ) -> ScanResult:
        """Varre um diretório local e detecta manifestos, configurações e tecnologias."""
        start_time = time.perf_counter()
        target_path = Path(dir_path).resolve()

        if not target_path.exists():
            raise FileNotFoundError(f"Diretório não encontrado: {dir_path}")
        if not target_path.is_dir():
            raise NotADirectoryError(f"O caminho especificado não é um diretório: {dir_path}")

        # Coleta os arquivos de forma otimizada
        files = list(walk_files(target_path, ignored_dirs=ignored_dirs, max_depth=max_depth))

        all_items: List[TechItem] = []
        for detector in self.detectors:
            if detector.supports_filesystem:
                try:
                    items = detector.detect_filesystem(target_path, files)
                    all_items.extend(items)
                except Exception as ex:
                    # Falha em um detector não interrompe os outros
                    continue

        elapsed = time.perf_counter() - start_time
        result = ScanResult(
            target=ScanTarget(target_type="directory", target_value=str(target_path)),
            items=all_items,
            metadata={
                "elapsed_time_seconds": elapsed,
                "files_scanned": len(files),
            },
        )
        result.deduplicate_and_merge()
        return result

    # --- Escaneamento de Repositório Git Remoto ---
    def scan_git(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        token: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        ignored_dirs: Optional[Iterable[str]] = None,
        max_depth: int = 12,
    ) -> ScanResult:
        """Clona temporariamente um repositório Git e realiza a varredura profunda."""
        with self.git_service.clone_repository(
            repo_url=repo_url,
            branch=branch,
            token=token,
            ssh_key_path=ssh_key_path,
        ) as temp_repo_dir:
            res = self.scan_directory(temp_repo_dir, ignored_dirs=ignored_dirs, max_depth=max_depth)
            # Atualiza o alvo para refletir a URL remota em vez do path temporário
            res.target = ScanTarget(target_type="git", target_value=repo_url)
            if branch:
                res.metadata["branch"] = branch
            return res

    # --- Escaneamento de URL Web ---
    async def scan_url(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
    ) -> ScanResult:
        """Envia requisições HTTP e analisa cabeçalhos, cookies, corpo e WAF/CDN."""
        start_time = time.perf_counter()

        # Ajusta esquema caso omitido
        target_url = url.strip()
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        req_headers = {"User-Agent": DEFAULT_USER_AGENT}
        if headers:
            req_headers.update(headers)

        response_data: Dict[str, Any] = {
            "url": target_url,
            "headers": {},
            "cookies": {},
            "body": "",
            "status_code": 0,
        }

        all_items: List[TechItem] = []
        try:
            async with httpx.AsyncClient(
                verify=verify_ssl,
                timeout=timeout,
                follow_redirects=follow_redirects,
            ) as client:
                resp = await client.get(target_url, headers=req_headers)
                response_data["status_code"] = resp.status_code
                response_data["headers"] = dict(resp.headers)
                response_data["cookies"] = dict(resp.cookies)
                response_data["body"] = resp.text

                for detector in self.detectors:
                    if detector.supports_url:
                        try:
                            items = await detector.detect_url(target_url, response_data, client=client)
                            all_items.extend(items)
                        except TypeError:
                            items = await detector.detect_url(target_url, response_data)
                            all_items.extend(items)
                        except Exception:
                            continue
        except Exception as e:
            response_data["error"] = str(e)
            # Tenta executar detectores mesmo se a conexão falhar ou já tiver dados parciais
            for detector in self.detectors:
                if detector.supports_url:
                    try:
                        items = await detector.detect_url(target_url, response_data)
                        all_items.extend(items)
                    except Exception:
                        continue

        elapsed = time.perf_counter() - start_time
        result = ScanResult(
            target=ScanTarget(target_type="url", target_value=target_url),
            items=all_items,
            metadata={
                "elapsed_time_seconds": elapsed,
                "http_status": response_data.get("status_code"),
                "error": response_data.get("error"),
            },
        )
        result.deduplicate_and_merge()
        return result
