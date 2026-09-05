# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = collect_submodules('webview')
datas = [
    ('index.html', '.'),
    ('manifest.webmanifest', '.'),
    ('sw.js', '.'),
]

# pywebview backends and their data are discovered by collect_submodules.
for pkg in ('webview', 'uvicorn', 'fastapi', 'pydantic'):
    datas += collect_data_files(pkg)


block_cipher = None

a = Analysis(
    ['desktop_launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ConfigPortTester',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
