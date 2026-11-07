"""Windows specifics for the GUI: DPI scale, fonts, Documents folder, opening files.

Every function is safe to call on other platforms (returns a neutral value).
Stdlib only (ctypes).
"""

from __future__ import annotations

import os
import sys

PROCESS_SYSTEM_DPI_AWARE = 1


def enable_dpi_awareness() -> float:
    """Make the process DPI-aware and return the UI scale (1.0 = 96 DPI).

    Without this Windows bitmap-stretches the window on 125-200 % displays
    (blurry text). We use *system* DPI awareness: sharp on the main display,
    and Windows still scales the window if it is dragged to a monitor with a
    different DPI. ``L2LC_UI_SCALE`` overrides the result (for tests and
    screenshots).
    """
    scale = 1.0
    if os.name == "nt":
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(PROCESS_SYSTEM_DPI_AWARE)
        except (AttributeError, OSError):
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except (AttributeError, OSError):
                pass
        try:
            scale = ctypes.windll.user32.GetDpiForSystem() / 96.0
        except (AttributeError, OSError):
            scale = 1.0
    try:
        scale = float(os.environ.get("L2LC_UI_SCALE", "") or scale)
    except ValueError:
        pass
    return max(1.0, min(scale, 4.0))


def fit_to_screen(width: int, height: int) -> tuple[int, int]:
    """Shrink the window to the work area (screen minus taskbar) on Windows.

    1120x860 at 150 % is 1680x1290, taller than a 1920x1080 laptop screen.
    """
    if os.name != "nt":
        return width, height
    import ctypes
    from ctypes import wintypes

    rect = wintypes.RECT()
    SPI_GETWORKAREA = 0x0030
    try:
        if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            max_w, max_h = rect.right - rect.left, rect.bottom - rect.top
            return min(width, int(max_w * 0.95)), min(height, int(max_h * 0.95))
    except (AttributeError, OSError):
        pass
    return width, height


def font_candidates() -> list[str]:
    """Default UI font. On Windows prefer one with CJK glyphs: adapter friendly
    names, marks, company and site names are often Chinese or Japanese."""
    if os.name != "nt":
        return []
    fonts = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")
    names = ("msjh.ttc",    # Microsoft JhengHei (Traditional Chinese; also kana)
             "msyh.ttc",    # Microsoft YaHei (Simplified Chinese)
             "YuGothM.ttc", # Yu Gothic (Japanese)
             "meiryo.ttc",
             "segoeui.ttf", "arial.ttf")
    return [os.path.join(fonts, n) for n in names]


def latin_font_candidates() -> list[str]:
    """Font for the big number and the verdict (Latin only, nicer shapes)."""
    if os.name != "nt":
        return []
    fonts = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")
    return [os.path.join(fonts, n) for n in ("segoeui.ttf", "arial.ttf")]


def documents_dir() -> str:
    """The user's Documents folder, following OneDrive / folder redirection on Windows."""
    if os.name == "nt":
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("b", ctypes.c_ubyte * 16)]

        folderid_documents = GUID()
        ctypes.memmove(folderid_documents.b, uuid.UUID("FDD39AD0-238F-46AF-ADB4-6C85480369C7").bytes_le, 16)
        p = ctypes.c_wchar_p()
        try:
            shell32 = ctypes.windll.shell32
            shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                                                     ctypes.POINTER(ctypes.c_wchar_p)]
            if shell32.SHGetKnownFolderPath(ctypes.byref(folderid_documents), 0, None, ctypes.byref(p)) == 0:
                path = p.value
                ctypes.windll.ole32.CoTaskMemFree(p)
                if path:
                    return path
        except (AttributeError, OSError):
            pass
    return os.path.join(os.path.expanduser("~"), "Documents")


def open_with_default_app(path: str) -> bool:
    """Open a file or folder with its default app on Windows. False elsewhere."""
    if os.name != "nt":
        return False
    os.startfile(os.path.abspath(path))  # noqa: S606 - report.html in the browser, folders in Explorer
    return True


def app_icon() -> str | None:
    """Path of the window icon when running from a PyInstaller bundle or the repo."""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    for rel in (("l2-loopcheck.ico",), ("packaging", "windows", "l2-loopcheck.ico")):
        p = os.path.join(base, *rel)
        if os.path.isfile(p):
            return p
    return None
