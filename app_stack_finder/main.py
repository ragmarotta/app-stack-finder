"""Command Line Interface entrypoint for app-stack-finder."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from app_stack_finder import __version__
from app_stack_finder.core.models import ScanResult
from app_stack_finder.services.scanner_service import ScannerService
from app_stack_finder.utils.reporter import Reporter

console = Console()
reporter = Reporter(console=console)


def handle_output(result: ScanResult, format_type: str, output_path: Optional[str]) -> None:
    """Exporta o resultado no formato selecionado e/ou salva em arquivo."""
    format_type = format_type.lower()

    if format_type == "json":
        output_content = reporter.to_json(result)
    elif format_type in ("markdown", "md"):
        output_content = reporter.to_markdown(result)
    else:  # rich
        output_content = None
        reporter.print_rich_report(result)

    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        # Se o formato foi rich mas o usuário especificou output file, gera markdown por padrão
        if output_content is None:
            output_content = reporter.to_markdown(result)
        out_file.write_text(output_content, encoding="utf-8")
        console.print(f"[bold green]✔[/bold green] Relatório salvo com sucesso em: [cyan]{out_file.resolve()}[/cyan]")
    elif output_content is not None:
        click.echo(output_content)


@click.group(invoke_without_command=True)
@click.version_option(__version__, "-v", "--version", message="%(prog)s version %(version)s")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """App Stack Finder: Análise profunda e fingerprinting de tecnologias, frameworks e infraestrutura."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# --- Comando Inteligente Genérico: SCAN ---
@cli.command("scan")
@click.argument("target", required=True)
@click.option("--format", "-f", "format_type", type=click.Choice(["rich", "json", "markdown", "md"], case_sensitive=False), default="rich", help="Formato de saída do relatório.")
@click.option("--output", "-o", "output_path", type=click.Path(dir_okay=False, writable=True), help="Caminho do arquivo para salvar o relatório.")
@click.option("--token", "-t", envvar="STACK_FINDER_TOKEN", help="Token (PAT) para repositórios Git privados.")
@click.option("--ssh-key", "ssh_key_path", envvar="STACK_FINDER_SSH_KEY", type=click.Path(exists=True), help="Chave SSH para repositórios privados.")
@click.option("--branch", "-b", help="Branch específica para repositório Git.")
@click.option("--timeout", default=15.0, type=float, help="Timeout para requisições HTTP (segundos).")
@click.option("--insecure", "-k", is_flag=True, help="Ignora validação de certificados SSL em URLs.")
def scan_auto(
    target: str,
    format_type: str,
    output_path: Optional[str],
    token: Optional[str],
    ssh_key_path: Optional[str],
    branch: Optional[str],
    timeout: float,
    insecure: bool,
) -> None:
    """Analisa automaticamente uma URL, diretório local ou repositório Git remoto."""
    scanner = ScannerService()

    # 1. Checa se é URL
    if target.startswith(("http://", "https://")) and not target.endswith(".git"):
        with console.status(f"[bold cyan]Analisando endpoint HTTP/S {target}...[/bold cyan]"):
            result = asyncio.run(scanner.scan_url(target, timeout=timeout, verify_ssl=not insecure))
        handle_output(result, format_type, output_path)
        return

    # 2. Checa se é Git remoto
    if target.endswith(".git") or target.startswith("git@") or "github.com/" in target or "gitlab.com/" in target:
        with console.status(f"[bold cyan]Clonando e analisando repositório Git remoto {target}...[/bold cyan]"):
            try:
                result = scanner.scan_git(
                    repo_url=target,
                    branch=branch,
                    token=token,
                    ssh_key_path=ssh_key_path,
                )
            except Exception as e:
                console.print(f"[bold red]Erro ao processar repositório Git:[/bold red] {e}", err=True)
                sys.exit(1)
        handle_output(result, format_type, output_path)
        return

    # 3. Trata como diretório local
    local_path = Path(target)
    if local_path.exists():
        with console.status(f"[bold cyan]Varrendo diretório local {local_path.resolve()}...[/bold cyan]"):
            try:
                result = scanner.scan_directory(local_path)
            except Exception as e:
                console.print(f"[bold red]Erro ao escanear diretório:[/bold red] {e}", err=True)
                sys.exit(1)
        handle_output(result, format_type, output_path)
        return

    # Caso não seja diretório existente e pareça domínio (ex: 'example.com')
    if "." in target and not Path(target).exists():
        with console.status(f"[bold cyan]Analisando endpoint {target}...[/bold cyan]"):
            result = asyncio.run(scanner.scan_url(target, timeout=timeout, verify_ssl=not insecure))
        handle_output(result, format_type, output_path)
        return

    console.print(f"[bold red]Erro:[/bold red] Alvo inválido ou inexistente: '{target}'", err=True)
    sys.exit(1)


# --- Subcomando Explícito: DIR ---
@cli.command("dir")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, dir_okay=True), default=".")
@click.option("--format", "-f", "format_type", type=click.Choice(["rich", "json", "markdown", "md"], case_sensitive=False), default="rich", help="Formato de saída.")
@click.option("--output", "-o", "output_path", type=click.Path(dir_okay=False, writable=True), help="Salva relatório em arquivo.")
@click.option("--max-depth", default=12, type=int, help="Profundidade máxima de varredura.")
@click.option("--exclude", "-e", multiple=True, help="Diretórios adicionais a ignorar.")
def scan_dir_cmd(directory: str, format_type: str, output_path: Optional[str], max_depth: int, exclude: tuple[str, ...]) -> None:
    """Analisa arquivos e manifestos em um diretório local."""
    scanner = ScannerService()
    path = Path(directory)
    with console.status(f"[bold cyan]Varrendo diretório {path.resolve()}...[/bold cyan]"):
        try:
            result = scanner.scan_directory(path, ignored_dirs=exclude, max_depth=max_depth)
        except Exception as e:
            console.print(f"[bold red]Erro ao escanear diretório:[/bold red] {e}", err=True)
            sys.exit(1)
    handle_output(result, format_type, output_path)


# --- Subcomando Explícito: URL ---
@cli.command("url")
@click.argument("target_url", required=True)
@click.option("--format", "-f", "format_type", type=click.Choice(["rich", "json", "markdown", "md"], case_sensitive=False), default="rich", help="Formato de saída.")
@click.option("--output", "-o", "output_path", type=click.Path(dir_okay=False, writable=True), help="Salva relatório em arquivo.")
@click.option("--timeout", default=15.0, type=float, help="Timeout da requisição HTTP.")
@click.option("--insecure", "-k", is_flag=True, help="Ignora certificados SSL inválidos.")
def scan_url_cmd(target_url: str, format_type: str, output_path: Optional[str], timeout: float, insecure: bool) -> None:
    """Analisa cabeçalhos, cookies, WAF, CDN e DOM de uma URL remota."""
    scanner = ScannerService()
    with console.status(f"[bold cyan]Conectando e inspecionando {target_url}...[/bold cyan]"):
        try:
            result = asyncio.run(scanner.scan_url(target_url, timeout=timeout, verify_ssl=not insecure))
        except Exception as e:
            console.print(f"[bold red]Erro na requisição HTTP:[/bold red] {e}", err=True)
            sys.exit(1)
    handle_output(result, format_type, output_path)


# --- Subcomando Explícito: GIT ---
@cli.command("git")
@click.argument("repo_url", required=True)
@click.option("--format", "-f", "format_type", type=click.Choice(["rich", "json", "markdown", "md"], case_sensitive=False), default="rich", help="Formato de saída.")
@click.option("--output", "-o", "output_path", type=click.Path(dir_okay=False, writable=True), help="Salva relatório em arquivo.")
@click.option("--branch", "-b", help="Branch ou tag específica.")
@click.option("--token", "-t", envvar="STACK_FINDER_TOKEN", help="Token de acesso pessoal (PAT).")
@click.option("--ssh-key", "ssh_key_path", envvar="STACK_FINDER_SSH_KEY", type=click.Path(exists=True), help="Caminho da chave SSH privada.")
def scan_git_cmd(repo_url: str, format_type: str, output_path: Optional[str], branch: Optional[str], token: Optional[str], ssh_key_path: Optional[str]) -> None:
    """Clona temporariamente um repositório Git e executa análise profunda de stack."""
    scanner = ScannerService()
    with console.status(f"[bold cyan]Clonando e analisando repositório Git {repo_url}...[/bold cyan]"):
        try:
            result = scanner.scan_git(
                repo_url=repo_url,
                branch=branch,
                token=token,
                ssh_key_path=ssh_key_path,
            )
        except Exception as e:
            console.print(f"[bold red]Erro ao processar repositório Git:[/bold red] {e}", err=True)
            sys.exit(1)
    handle_output(result, format_type, output_path)


if __name__ == "__main__":
    cli()
