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
        """A module that evaluates to False so `if not win32api:` guards work."""

        def __bool__(self):
            return False

        def __getattr__(self, name):
            # Raise a clear error if anything ever tries to USE the stub.
            raise AttributeError(
                f"{self.__name__}.{name} is not available "
                f"(pywin32 stub — MCP tools are not supported in this build)"
            )

    for _mod in ("pywintypes", "win32api", "win32con", "win32job"):
        if _mod not in sys.modules:
            sys.modules[_mod] = _FalsyStub(_mod)
