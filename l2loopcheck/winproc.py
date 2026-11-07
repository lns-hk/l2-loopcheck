"""Windows child-process helpers: no console windows, graceful stop.

``Popen.terminate()`` on Windows is ``TerminateProcess``: dumpcap dies at once,
the pcapng stream is cut mid-block and the final drop statistics are lost.
dumpcap handles console control events (Ctrl+C / Ctrl+Break) by finishing the
capture cleanly, so we start it in its own process group and send it
CTRL_BREAK_EVENT instead.

Two cases:
* We have a console (CLI): the child shares it, in a new process group, so a
  Ctrl+C typed by the user reaches only us and we stop the child ourselves.
* We have no console (GUI, windowed exe): the child gets its own *hidden*
  console (no window flashes). To signal it we attach to that console for a
  moment, send the event to the child's process group and detach again.

Stdlib only (ctypes). Every function is a no-op or returns a safe default on
other platforms.
"""

from __future__ import annotations

import os
import subprocess
import threading

CTRL_BREAK_EVENT = 1
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0

_console_lock = threading.Lock()


def _kernel32():
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    k.GetConsoleProcessList.restype = wintypes.DWORD
    k.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
    k.AttachConsole.argtypes = [wintypes.DWORD]
    k.AttachConsole.restype = wintypes.BOOL
    k.FreeConsole.argtypes = []
    k.FreeConsole.restype = wintypes.BOOL
    return k


def has_console() -> bool:
    """True if this process is attached to a console (CLI), False for a GUI."""
    if os.name != "nt":
        return True
    import ctypes
    from ctypes import wintypes

    buf = (wintypes.DWORD * 4)()
    return _kernel32().GetConsoleProcessList(buf, 4) > 0


def hidden_kwargs() -> dict:
    """Popen/run kwargs for a short-lived helper (e.g. ``dumpcap -D``): no window."""
    return {"creationflags": CREATE_NO_WINDOW} if os.name == "nt" else {}


def stoppable_kwargs(shared_console: bool | None = None) -> dict:
    """Popen kwargs for a long-running child we will stop with ``send_ctrl_break``."""
    if os.name != "nt":
        return {}
    if shared_console is None:
        shared_console = has_console()
    if shared_console:
        return {"creationflags": CREATE_NEW_PROCESS_GROUP}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= STARTF_USESHOWWINDOW
    si.wShowWindow = SW_HIDE
    return {"creationflags": CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, "startupinfo": si}


def send_ctrl_break(proc: subprocess.Popen) -> bool:
    """Ask a child started with ``stoppable_kwargs`` to stop. False if it could not be signalled."""
    if os.name != "nt" or proc.poll() is not None:
        return False
    flags = 0
    try:
        flags = proc._l2lc_flags  # type: ignore[attr-defined]
    except AttributeError:
        pass
    k = _kernel32()
    if not flags & CREATE_NEW_CONSOLE:
        # Shared console: the child is alone in its process group (group id = its pid).
        return bool(k.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, proc.pid))
    # Own hidden console: only possible while we have no console ourselves.
    with _console_lock:
        if has_console() or not k.AttachConsole(proc.pid):
            return False
        try:
            return bool(k.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, proc.pid))
        finally:
            k.FreeConsole()


def popen_stoppable(cmd: list[str], shared_console: bool | None = None, **kwargs) -> subprocess.Popen:
    """``subprocess.Popen`` that can later be stopped with ``send_ctrl_break``."""
    extra = stoppable_kwargs(shared_console)
    if "creationflags" in kwargs:
        extra["creationflags"] = extra.get("creationflags", 0) | kwargs.pop("creationflags")
    proc = subprocess.Popen(cmd, **extra, **kwargs)
    proc._l2lc_flags = extra.get("creationflags", 0)  # type: ignore[attr-defined]
    return proc
