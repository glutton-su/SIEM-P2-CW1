# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for SIEM application.
Build with: pyinstaller SIEM.spec
"""

import sys
from pathlib import Path

block_cipher = None

# Get the absolute path of the project
project_path = Path(SPECPATH).resolve()

a = Analysis(
    ['main.py'],
    pathex=[str(project_path)],
    binaries=[],
    datas=[
        ('siem/siemlogo.ico', 'siem'),
    ],
    hiddenimports=[
        'win32evtlog',
        'win32evtlogutil', 
        'win32con',
        'win32security',
        'win32api',
        'pywintypes',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SIEM',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window - GUI app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='siem/siemlogo.ico',  # Application icon
    uac_admin=True,  # Request administrator privileges on startup
)
