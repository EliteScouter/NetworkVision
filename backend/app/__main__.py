"""``python -m app``: run the server with host/port from settings.

This is how the native packages start NetworkVision (systemd on Linux, the
Windows service). Docker keeps calling uvicorn directly.
"""

from __future__ import annotations

import sys


def self_check() -> None:
    """Prove a packaged bundle is complete: every module imports, SNMP MIBs load, the UI is there."""
    import importlib
    import pkgutil
    from pathlib import Path

    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

    from . import __path__ as pkg_path
    from .config import get_settings

    for mod in pkgutil.walk_packages(pkg_path, "app."):
        importlib.import_module(mod.name)
    SnmpEngine()
    s = get_settings()
    if not (Path(s.static_dir) / "index.html").is_file():
        raise SystemExit(f"web UI missing: {s.static_dir}/index.html")
    print(f"ok {s.host}:{s.port} data={s.data_dir} static={s.static_dir}")


def main() -> None:
    import uvicorn

    from .config import get_settings
    from .main import app

    if "--check" in sys.argv:  # used by the package builds
        return self_check()
    s = get_settings()
    uvicorn.run(app, host=s.host, port=s.port, proxy_headers=True, server_header=False,
                log_level=s.log_level.lower(), access_log=False)


if __name__ == "__main__":
    main()
