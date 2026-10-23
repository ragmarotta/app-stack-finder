@echo off
setlocal enabledelayedexpansion

echo ========================================================================
echo   Build do App Stack Finder para Windows (.exe)
echo ========================================================================
echo.

REM 1. Verifica ambiente virtual
if not exist ".venv" (
    echo [*] Criando ambiente virtual Python...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

REM 2. Instala dependências
echo [*] Instalando dependencias do projeto e PyInstaller...
python -m pip install --upgrade pip
pip install -e .
pip install pyinstaller

REM 3. Compilação com a spec unificada
echo [*] Compilando app-stack-finder.exe...
pyinstaller --noconfirm --clean app-stack-finder.spec

REM 4. Validação e Teste do Executável gerado
if exist "dist\app-stack-finder.exe" (
    echo.
    echo ========================================================================
    echo   Testando Executavel: dist\app-stack-finder.exe --help
    echo ========================================================================
    echo.
    dist\app-stack-finder.exe --help
    echo.
    echo ========================================================================
    echo [SUCESSO] Executavel Windows gerado em: dist\app-stack-finder.exe
    echo ========================================================================
) else (
    echo [ERRO] Falha ao compilar dist\app-stack-finder.exe
    exit /b 1
)

endlocal
