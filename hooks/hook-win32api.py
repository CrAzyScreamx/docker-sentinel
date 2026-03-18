# PyInstaller hook for win32api.
# The rthook_pywin32.py runtime hook pre-installs falsy stubs for all pywin32
# modules before the frozen importer runs, so win32api.pyd is never loaded and
# its DLL dependency on pywintypes3XX.dll is never triggered.
# This hook intentionally does nothing — it exists only to prevent PyInstaller
# from collecting win32api.pyd (which would cause it to attempt DLL resolution).
excludedimports = ["win32api", "pywintypes", "win32con", "win32job"]
