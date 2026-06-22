"""Shared console helpers for the UTF command-line tools."""
import sys


def enable_utf8() -> None:
    """Force stdout/stderr to UTF-8 so box-drawing glyphs and emoji used by
    the CLIs (``─``, ``✅``, ``🚀`` …) don't raise ``UnicodeEncodeError`` on
    Windows consoles defaulting to cp1252. A no-op where reconfigure is
    unavailable or fails.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
