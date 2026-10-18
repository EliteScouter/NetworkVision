"""PyInstaller entry point for networkvision.exe (the Windows service runs this)."""

from app.__main__ import main

if __name__ == "__main__":
    main()
