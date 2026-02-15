# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for WAFPierce GUI application.
This bundles the entire application with all dependencies into a single executable.
"""

import os
import sys

block_cipher = None

# Get the project root directory
project_root = os.path.dirname(os.path.abspath(SPEC))

# Data files to include (wordlists, logo, etc.)
datas = [
    # Include wordlists folder
    (os.path.join(project_root, 'wordlists'), 'wordlists'),
    # Include logo
    (os.path.join(project_root, 'wafpierce', 'logo_Temp'), os.path.join('wafpierce', 'logo_Temp')),
    # Include categories file
    (os.path.join(project_root, 'categories.txt'), '.'),
]

# Hidden imports that PyInstaller might miss
hidden_imports = [
    'PySide6',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'requests',
    'wafpierce',
    'wafpierce.gui',
    'wafpierce.pierce',
    'wafpierce.chain',
    'wafpierce.error_handler',
    'wafpierce.exceptions',
    'json',
    'threading',
    'subprocess',
    'tempfile',
    'concurrent.futures',
]

a = Analysis(
    [os.path.join(project_root, 'run_gui.py')],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
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
    name='WAFPierce',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to False for GUI app (no console window)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(project_root, 'wafpierce', 'logo_Temp', 'logo_wafpierce.png') if os.path.exists(os.path.join(project_root, 'wafpierce', 'logo_Temp', 'logo_wafpierce.png')) else None,
)
