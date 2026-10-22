"""Reporters for generating Rich CLI tables, Markdown reports, and JSON output."""

from __future__ import annotations

import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app_stack_finder.core.models import ScanResult, TechCategory


class Reporter:
    """Formatador de relatórios para terminal humano e arquivos de saída."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_rich_report(self, result: ScanResult) -> None:
        """Renderiza um relatório visual e agradável no terminal usando Rich."""
        # Cabeçalho Informativo
        target_info = (
            f"[bold cyan]Alvo:[/bold cyan] {result.target.target_value} "
            f"([bold yellow]{result.target.target_type.upper()}[/bold yellow])\n"
            f"[bold cyan]Data/Hora:[/bold cyan] {result.target.timestamp}\n"
            f"[bold cyan]Total de Tecnologias:[/bold cyan] [bold green]{len(result.items)}[/bold green]"
        )

        if "elapsed_time_seconds" in result.metadata:
            target_info += f" | [bold cyan]Duração:[/bold cyan] {result.metadata['elapsed_time_seconds']:.2f}s"
        if "files_scanned" in result.metadata:
            target_info += f" | [bold cyan]Arquivos Analisados:[/bold cyan] {result.metadata['files_scanned']}"
        if "http_status" in result.metadata:
            target_info += f" | [bold cyan]HTTP Status:[/bold cyan] {result.metadata['http_status']}"

        self.console.print(
            Panel(
                target_info,
                title="[bold magenta]🔍 App Stack Finder - Relatório de Detecção[/bold magenta]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        if not result.items:
            self.console.print(
                Panel(
                    "[yellow]Nenhuma tecnologia conhecida ou assinatura identificada no alvo informado.[/yellow]",
                    border_style="yellow",
                )
            )
            return

        # Tabelas por Categoria
        by_cat = result.by_category()
        for cat, items in by_cat.items():
            table = Table(
                title=f"[bold blue]📂 {cat.value}[/bold blue] ({len(items)})",
                title_justify="left",
                header_style="bold cyan",
                border_style="bright_black",
                show_lines=False,
            )

            table.add_column("Tecnologia", style="bold white", width=24)
            table.add_column("Versão", style="green", width=16)
            table.add_column("Confiança", style="yellow", justify="center", width=12)
            table.add_column("Evidência / Fonte", style="dim italic", min_width=25)
            table.add_column("Descrição", style="white", min_width=30)

            for item in items:
                version_str = f"[bold green]{item.version}[/bold green]" if item.version else "[dim]-[/dim]"
                conf_pct = f"{int(item.confidence * 100)}%"
                conf_colored = f"[green]{conf_pct}[/green]" if item.confidence >= 0.9 else f"[yellow]{conf_pct}[/yellow]"
                table.add_row(
                    item.name,
                    version_str,
                    conf_colored,
                    item.source or "-",
                    item.description or "-",
                )

            self.console.print(table)
            self.console.print()

    def to_markdown(self, result: ScanResult) -> str:
        """Gera um relatório completo em formato Markdown."""
        lines = [
            "# 🔍 App Stack Finder - Relatório de Tecnologias",
            "",
            f"- **Alvo:** `{result.target.target_value}`",
            f"- **Tipo:** `{result.target.target_type.upper()}`",
            f"- **Data/Hora:** `{result.target.timestamp}`",
            f"- **Total de Tecnologias Encontradas:** `{len(result.items)}`",
        ]

        if "elapsed_time_seconds" in result.metadata:
            lines.append(f"- **Tempo de Análise:** `{result.metadata['elapsed_time_seconds']:.2f}s`")
        if "files_scanned" in result.metadata:
            lines.append(f"- **Arquivos Analisados:** `{result.metadata['files_scanned']}`")
        if "http_status" in result.metadata:
            lines.append(f"- **HTTP Status Code:** `{result.metadata['http_status']}`")

        lines.extend(["", "---", ""])

        if not result.items:
            lines.append("*Nenhuma tecnologia detectada para o alvo especificado.*")
            return "\n".join(lines)

        by_cat = result.by_category()
        for cat, items in by_cat.items():
            lines.append(f"## 📂 {cat.value} ({len(items)})")
            lines.append("")
            lines.append("| Tecnologia | Versão | Confiança | Evidência / Fonte | Descrição |")
            lines.append("|:---|:---|:---:|:---|:---|")
            for item in items:
                v = item.version or "-"
                conf = f"{int(item.confidence * 100)}%"
                src = (item.source or "-").replace("|", "\\|")
                desc = (item.description or "-").replace("|", "\\|")
                lines.append(f"| **{item.name}** | `{v}` | {conf} | {src} | {desc} |")
            lines.append("")

        return "\n".join(lines)

    def to_json(self, result: ScanResult, indent: int = 2) -> str:
        """Exporta o resultado em formato JSON formatado."""
        return result.to_json(indent=indent)
