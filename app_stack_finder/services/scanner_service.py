"""Orchestrator service for scanning URLs, local directories, and remote Git repositories."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlparse

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
        no_proxy: bool = False,
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
        client: Optional[httpx.AsyncClient] = None
        should_close_client = True

        try:
            # 1. Tenta conectar respeitando ambiente ou diretamente se no_proxy=True
            use_trust_env = not no_proxy
            client = httpx.AsyncClient(
                verify=verify_ssl,
                timeout=timeout,
                follow_redirects=follow_redirects,
                trust_env=use_trust_env,
            )

            try:
                resp = await client.get(target_url, headers=req_headers)
            except (httpx.ProxyError, httpx.ConnectError) as proxy_err:
                # Se falhar pelo proxy corporativo (comum em intranets/domínios internos não roteados pelo proxy), faz fallback direto
                if use_trust_env:
                    await client.aclose()
                    client = httpx.AsyncClient(
                        verify=verify_ssl,
                        timeout=timeout,
                        follow_redirects=follow_redirects,
                        trust_env=False,
                    )
                    resp = await client.get(target_url, headers=req_headers)
                else:
                    raise proxy_err

            effective_url = str(resp.url)
            response_data["url"] = effective_url
            response_data["status_code"] = resp.status_code
            response_data["headers"] = dict(resp.headers)
            response_data["cookies"] = dict(resp.cookies)
            response_data["body"] = resp.text

            # 2. Probe para descobrir banners de servidores ocultos em páginas de erro 404 (root e contexto)
            probe_urls = [
                urljoin(effective_url, "/__app_stack_finder_probe_404__"),
            ]
            # Se a URL tem subcaminho (ex: /app/...), sonda também o contexto da aplicação
            app_context = effective_url.split("?")[0]
            if "/" in app_context.replace("://", ""):
                parts = app_context.split("/")
                if len(parts) > 3:
                    ctx_base = "/".join(parts[:4]) + "/"
                    probe_urls.append(urljoin(ctx_base, "__app_stack_finder_probe_404__"))

            for probe_url in probe_urls:
                try:
                    probe_resp = await client.get(probe_url, headers=req_headers, timeout=3.5)
                    body_404 = probe_resp.text[:4096]
                    if body_404:
                        response_data["probe_404_body"] = body_404
                        response_data["probe_404_headers"] = dict(probe_resp.headers)
                        # Se encontrou banner de servidor conhecido, não precisa testar os próximos
                        if any(kw in body_404.lower() for kw in ["jboss", "tomcat", "apache", "nginx"]):
                            break
                except Exception:
                    pass

            # 3. Execução dos detectores
            for detector in self.detectors:
                if detector.supports_url:
                    try:
                        items = await detector.detect_url(effective_url, response_data, client=client)
                        all_items.extend(items)
                    except TypeError:
                        items = await detector.detect_url(effective_url, response_data)
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
        finally:
            if client and should_close_client:
                try:
                    await client.aclose()
                except Exception:
                    pass

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
