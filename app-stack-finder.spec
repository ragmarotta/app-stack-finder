# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification file for app-stack-finder.
Supports both Linux (standalone ELF binary) and Windows (PE .exe executable).
"""

import sys
from PyInstaller.utils.hooks import collect_all

datas = [('app_stack_finder/data', 'app_stack_finder/data')]
binaries = []
hiddenimports = [
    'click',
    'rich',
    'rich.console',
    'rich.table',
    'rich.panel',
    'rich.syntax',
    'httpx',
    'yaml',
    'urllib.parse',
    'asyncio',
]

# Coleta pacotes que dependem de submódulos dinâmicos
for pkg in ['rich', 'httpx', 'yaml', 'click', 'app_stack_finder']:
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(pkg)
        datas.extend(pkg_datas)
        binaries.extend(pkg_binaries)
        hiddenimports.extend(pkg_hidden)
    except Exception:
        pass

a = Analysis(
    ['app_stack_finder/main.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas', 'unittest', 'pytest'],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

is_windows = sys.platform.startswith('win')
exe_name = 'app-stack-finder.exe' if is_windows else 'app-stack-finder'

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False if is_windows else True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
