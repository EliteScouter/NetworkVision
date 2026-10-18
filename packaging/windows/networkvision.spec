# PyInstaller spec: one-folder build of the backend for the Windows installer.
#   pyinstaller --noconfirm --distpath <out> packaging/windows/networkvision.spec
# Run from the repository root with backend requirements + pyinstaller installed.
import os

from PyInstaller.utils.hooks import collect_all, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
BACKEND = os.path.join(ROOT, "backend")

datas, binaries, hiddenimports = [], [], []
# Packages that load modules or data dynamically (uvicorn protocols/loops, SNMP MIBs, SQL dialects).
for pkg in ("pysnmp", "pyasn1", "uvicorn", "pykeepass", "segno", "tzdata", "certifi"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h
hiddenimports += collect_submodules("app")
hiddenimports += ["aiosqlite", "aiomysql", "sqlalchemy.dialects.sqlite.aiosqlite", "sqlalchemy.dialects.mysql.aiomysql"]

a = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[BACKEND],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "ruff"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="networkvision",
    console=True,
    icon=None,
    version=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="NetworkVision")
