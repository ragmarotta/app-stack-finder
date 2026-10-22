"""Service responsible for downloading and updating remote signature rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

DEFAULT_RULES_URL = "https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json"
DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_RULES_PATH = DEFAULT_DATA_DIR / "technologies.json"


class UpdaterService:
    """Gerencia o download e a atualização de assinaturas e regras remotas."""

    def __init__(
        self,
        remote_url: str = DEFAULT_RULES_URL,
        target_path: Optional[Path] = None,
        console: Optional[Console] = None,
    ) -> None:
        self.remote_url = remote_url
        self.target_path = Path(target_path) if target_path else DEFAULT_RULES_PATH
        self.console = console or Console()

    def update_rules(self, timeout: float = 30.0) -> bool:
        """
        Baixa o arquivo technologies.json remoto e salva no destino local.
        Retorna True em caso de sucesso, False caso ocorra erro (tratado sem quebrar o sistema).
        """
        self.console.print(f"[bold cyan]Baixando assinaturas remotas de:[/bold cyan] {self.remote_url}")
        try:
            self.target_path.parent.mkdir(parents=True, exist_ok=True)
            with httpx.Client(follow_redirects=True, timeout=timeout) as client:
                resp = client.get(self.remote_url)
                resp.raise_for_status()
                data = resp.json()

                if "technologies" not in data and not isinstance(data, dict):
                    raise ValueError("Conteúdo JSON inválido: chave 'technologies' não encontrada.")

                # Gravação atômica via arquivo temporário
                temp_file = self.target_path.with_suffix(".tmp")
                temp_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                temp_file.replace(self.target_path)

            tech_count = len(data.get("technologies", data))
            self.console.print(
                f"[bold green]✔[/bold green] Assinaturas atualizadas com sucesso! "
                f"[bold cyan]{tech_count}[/bold cyan] tecnologias salvas em [dim]{self.target_path}[/dim]"
            )
            return True

        except httpx.RequestError as exc:
            self.console.print(
                f"[bold yellow]⚠ Aviso de Rede:[/bold yellow] Não foi possível baixar as regras remotas ({exc}). "
                "A ferramenta continuará operando normalmente com as regras internas predefinidas.",
            )
            return False
        except httpx.HTTPStatusError as exc:
            self.console.print(
                f"[bold yellow]⚠ Erro HTTP {exc.response.status_code}:[/bold yellow] Falha ao obter as regras de {self.remote_url}. "
                "A ferramenta continuará operando normalmente com as regras internas predefinidas.",
            )
            return False
        except Exception as exc:
            self.console.print(
                f"[bold yellow]⚠ Erro ao processar regras remotas:[/bold yellow] {exc}. "
                "A ferramenta continuará operando normalmente com as regras internas predefinidas.",
            )
            return False
