"""Settings, background tasks and small widgets shared by the GUI pages."""

from __future__ import annotations

import html
import json
import os
import traceback
from typing import Callable, Optional

from PySide6.QtCore import QObject, QRunnable, QStandardPaths, Qt, QThreadPool, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from . import theme

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".l2loopcheck", "settings.json")


def documents_dir() -> str:
    return QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation) or os.path.expanduser("~")


def default_runs_dir() -> str:
    return os.path.join(documents_dir(), "l2-loopcheck")


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(s: dict) -> None:
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)


def open_path(path: str) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))


class _Task(QObject, QRunnable):
    finished_ok = Signal(object)
    failed = Signal(str)
    _live: set = set()

    def __init__(self, fn: Callable, ok: Callable, fail: Optional[Callable]) -> None:
        QObject.__init__(self)
        QRunnable.__init__(self)
        self.setAutoDelete(False)
        self.fn, self.ok, self.fail = fn, ok, fail
        self.finished_ok.connect(self._on_ok, Qt.QueuedConnection)
        self.failed.connect(self._on_fail, Qt.QueuedConnection)

    def run(self) -> None:  # worker thread
        try:
            result = self.fn()
        except Exception as e:  # noqa: BLE001 - shown to the engineer instead of crashing the window
            self.failed.emit(f"{e}\n\n{traceback.format_exc()}" if not str(e) else str(e))
            return
        self.finished_ok.emit(result)

    @Slot(object)
    def _on_ok(self, result) -> None:
        _Task._live.discard(self)
        self.ok(result)

    @Slot(str)
    def _on_fail(self, message: str) -> None:
        _Task._live.discard(self)
        if self.fail:
            self.fail(message)


def run_task(fn: Callable, ok: Callable, fail: Optional[Callable] = None) -> None:
    """Run ``fn`` on a worker thread; ``ok`` and ``fail`` are called back on the GUI thread."""
    t = _Task(fn, ok, fail)
    _Task._live.add(t)
    QThreadPool.globalInstance().start(t)


def label(text: str = "", name: str = "", wrap: bool = True) -> QLabel:
    w = QLabel(text)
    if name:
        w.setObjectName(name)
    w.setWordWrap(wrap)
    w.setTextFormat(Qt.AutoText)
    return w


def plain(text: str) -> QLabel:
    """A label that shows untrusted text literally."""
    w = QLabel(text)
    w.setWordWrap(True)
    w.setTextFormat(Qt.PlainText)
    return w


def button(text: str, on_click: Callable, name: str = "") -> QPushButton:
    b = QPushButton(text)
    if name:
        b.setObjectName(name)
    b.setCursor(Qt.PointingHandCursor)
    b.clicked.connect(lambda _checked=False: on_click())
    return b


def card(spacing: int = 10) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("Card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(20, 16, 20, 16)
    lay.setSpacing(spacing)
    return f, lay


def page(title: str, intro: str = "") -> tuple[QWidget, QVBoxLayout]:
    """A scrolling page: returns (the widget to add to the stack, the layout to fill)."""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.NoFrame)
    body = QWidget()
    body.setObjectName("ScrollBody")
    lay = QVBoxLayout(body)
    lay.setContentsMargins(36, 26, 36, 22)
    lay.setSpacing(12)
    lay.addWidget(label(title, "PageTitle"))
    if intro:
        lay.addWidget(label(intro, "Muted"))
    area.setWidget(body)
    return area, lay


class Banner(QFrame):
    """A coloured message box. Text is shown literally."""

    def __init__(self) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 9, 14, 9)
        self.text = QLabel()
        self.text.setWordWrap(True)
        self.text.setTextFormat(Qt.RichText)
        lay.addWidget(self.text)
        self.hide()

    def show_message(self, kind: str, message: str, lead: str = "") -> None:
        bg, border, fg = theme.BANNER[kind]
        self.setStyleSheet(f"Banner {{ background:{bg}; border:1px solid {border}; border-radius:6px; }}")
        lead_html = f"<b>{html.escape(lead)}</b> " if lead else ""
        self.text.setText(f"<span style='color:{fg}'>{lead_html}{html.escape(message)}</span>")
        self.show()

    def clear(self) -> None:
        self.hide()


def pill(text: str, fg: str, bg: str) -> QLabel:
    w = QLabel(text)
    w.setAlignment(Qt.AlignCenter)
    w.setStyleSheet(f"background:{bg}; color:{fg}; border-radius:5px; padding:2px 8px; font-weight:600;")
    return w
