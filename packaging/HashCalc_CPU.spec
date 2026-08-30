from pathlib import Path

# SPECPATH is the directory containing this .spec file.
# The project root is therefore its parent.
project_root = Path(SPECPATH).resolve().parent
script = project_root / "src" / "hashcalc_cpu.py"

a = Analysis(
    [str(script)],
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
