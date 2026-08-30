# HashCalc CPU - PyInstaller specification
# Build from repository root with:
#   pyinstaller packaging/HashCalc_CPU.spec

from pathlib import Path

project_root = Path(SPECPATH).resolve().parent

a = Analysis(
    ["src/hashcalc_cpu.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=[],
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
    name="HashCalc_CPU",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
