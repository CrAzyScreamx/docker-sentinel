# Runtime hook — runs before any user code.
#
# mcp.os.win32.utilities imports pywintypes, win32api, win32con, win32job at
# module level on Windows. docker-sentinel never uses MCP tools, so these are
# only imported — never called. However, loading win32api.pyd requires
# pywintypes3XX.dll to be pre-loaded, which is fragile inside a PyInstaller
# bundle.
#
# Strategy: pre-install falsy stub modules for all four pywin32 modules BEFORE
# the frozen importer tries to load them. mcp.os.win32.utilities guards every
# actual win32 call with `if not win32api:` / `if not win32job:`, so falsy
# stubs make all those guards fire and the code paths that need real DLLs are
# never reached.
import sys
import types

if sys.platform == "win32":

    class _FalsyStub(types.ModuleType):
        """A module that evaluates to False so `if not win32api:` guards work.

        Attribute access returns a callable child stub instead of raising so
        that deep import chains (pkg_resources → appdirs → win32com →
        pythoncom → pywintypes.__import_pywin32_system_module__) can complete
        at module-import time without crashing.  The bool(module) == False
        invariant is preserved on the stub object itself, which is all the
        mcp.os.win32.utilities guards check.
        """

        def __bool__(self):
            return False

        def __call__(self, *args, **kwargs):
            return None

        def __getattr__(self, name):
            child = _FalsyStub(f"{self.__name__}.{name}")
            object.__setattr__(self, name, child)  # cache to avoid recursion
            return child

    for _mod in ("pywintypes", "win32api", "win32con", "win32job"):
        if _mod not in sys.modules:
            sys.modules[_mod] = _FalsyStub(_mod)
