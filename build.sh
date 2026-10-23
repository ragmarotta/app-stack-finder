#!/usr/bin/env bash
# ==============================================================================
# Script de Build do App Stack Finder
# Empacota a aplicação em executáveis standalone para Linux e Windows (.exe)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BOLD="\033[1m"
RESET="\033[0m"

log_info() {
    echo -e "${CYAN}ℹ [BUILD]${RESET} $1"
}

log_success() {
    echo -e "${GREEN}✔ [SUCESSO]${RESET} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠ [AVISO]${RESET} $1"
}

log_error() {
    echo -e "${RED}✖ [ERRO]${RESET} $1"
}

setup_env() {
    log_info "Verificando ambiente Python e PyInstaller..."
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    elif [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi

    if ! command -v pyinstaller &>/dev/null; then
        log_info "PyInstaller não encontrado no path. Instalando no ambiente..."
        pip install pyinstaller
    fi
    log_success "PyInstaller pronto: $(pyinstaller --version)"
}

test_binary() {
    local bin_path="$1"
    echo ""
    echo -e "${BOLD}${CYAN}========================================================================${RESET}"
    echo -e "${BOLD}${GREEN}  Testando Executável: ${bin_path} --help${RESET}"
    echo -e "${BOLD}${CYAN}========================================================================${RESET}"
    echo ""
    "$bin_path" --help
    echo ""
    echo -e "${BOLD}${CYAN}========================================================================${RESET}"
    log_success "Executável respondeu ao comando --help com sucesso e exibiu todas as opções!"
}

build_linux() {
    log_info "Compilando executável standalone nativo para Linux (ELF)..."
    setup_env

    pyinstaller --noconfirm --clean app-stack-finder.spec

    if [ -f "dist/app-stack-finder" ]; then
        chmod +x dist/app-stack-finder
        # Cria também a versão com sufixo -linux para distribuição
        cp dist/app-stack-finder dist/app-stack-finder-linux
        log_success "Executável Linux gerado com sucesso em:"
        echo -e "  - ${BOLD}dist/app-stack-finder${RESET} ($(du -h dist/app-stack-finder | cut -f1))"
        echo -e "  - ${BOLD}dist/app-stack-finder-linux${RESET} ($(du -h dist/app-stack-finder-linux | cut -f1))"
    else
        log_error "Erro: dist/app-stack-finder não foi gerado."
        exit 1
    fi

    test_binary "dist/app-stack-finder"
}

build_windows() {
    log_info "Compilação para Windows (.exe)..."

    # Se Docker estiver disponível, tenta gerar via container wine
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        log_info "Docker detectado. Verificando possibilidade de compilar via container..."
        if docker run --rm -v "$PWD:/src" -w /src cdrx/pyinstaller-windows:python3 \
            "pip install -e . && pyinstaller --noconfirm --clean app-stack-finder.spec" 2>/dev/null; then
            if [ -f "dist/app-stack-finder.exe" ]; then
                log_success "Executável Windows gerado via Docker em: dist/app-stack-finder.exe"
                return 0
            fi
        fi
    fi

    # Se Wine estiver instalado
    if command -v wine &>/dev/null && wine python --version &>/dev/null; then
        log_info "Wine detectado no sistema host. Compilando via Wine..."
        wine python -m PyInstaller --noconfirm --clean app-stack-finder.spec
        if [ -f "dist/app-stack-finder.exe" ]; then
            log_success "Executável Windows gerado via Wine em: dist/app-stack-finder.exe"
            return 0
        fi
    fi

    log_warn "Para gerar o executável .exe nativamente no Windows:"
    echo -e "  1. Abra o prompt no Windows e execute: ${BOLD}build.bat${RESET}"
    echo -e "  2. Ou utilize a pipeline automatizada do GitHub Actions em: ${BOLD}.github/workflows/build-binaries.yml${RESET}"
}

clean_build() {
    log_info "Limpando diretórios build/ e dist/..."
    rm -rf build/ dist/
    log_success "Diretórios de build limpos."
}

show_usage() {
    echo "Uso: $0 [linux|windows|all|clean|test]"
    echo ""
    echo "Comandos:"
    echo "  linux    (Padrão) Compila o executável standalone para Linux e executa o --help"
    echo "  windows  Compila o executável .exe para Windows (via Docker/Wine ou instruções)"
    echo "  all      Compila para ambas as plataformas (Linux e Windows)"
    echo "  test     Executa o teste do binário compilado chamando --help"
    echo "  clean    Limpa arquivos temporários das pastas build/ e dist/"
    echo ""
}

# Entrada do script
TARGET="${1:-linux}"

case "$TARGET" in
    linux)
        build_linux
        ;;
    windows)
        build_windows
        ;;
    all)
        build_linux
        echo ""
        build_windows
        ;;
    test)
        if [ -f "dist/app-stack-finder" ]; then
            test_binary "dist/app-stack-finder"
        else
            log_error "Binário dist/app-stack-finder não encontrado. Execute './build.sh linux' primeiro."
            exit 1
        fi
        ;;
    clean)
        clean_build
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        log_error "Opção desconhecida: $TARGET"
        show_usage
        exit 1
        ;;
esac
