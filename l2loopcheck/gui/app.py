"""The application window: home screen, wizard, results."""

from __future__ import annotations

import json
import os
import sys
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QApplication, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog,
                               QLineEdit, QMainWindow, QMessageBox, QPushButton, QSpinBox, QStackedWidget, QVBoxLayout, QWidget)

from .. import __version__
from ..cli import analyze_file, write_outputs
from . import theme
from .common import button, card, default_runs_dir, label, load_settings, plain, run_task, save_settings
from .results import ResultsPage
from .wizard import VANTAGE, Wizard


def app_icon() -> QIcon:
    bundle = getattr(sys, "_MEIPASS", None)
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for p in ([os.path.join(bundle, "l2-loopcheck.ico")] if bundle else []) + [
            os.path.join(root, "packaging", "windows", "l2-loopcheck.ico"),
            os.path.join(root, "packaging", "linux", "l2-loopcheck.png")]:
        if os.path.isfile(p):
            return QIcon(p)
    return QIcon()


class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget, settings: dict) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Report and storage settings")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.company = QLineEdit(settings.get("company", ""))
        self.logo = QLineEdit(settings.get("logo_path", ""))
        row = QHBoxLayout()
        row.addWidget(self.logo, 1)
        row.addWidget(button("Browse...", self._logo))
        self.folder = QLineEdit(settings.get("runs_dir") or default_runs_dir())
        self.size = QSpinBox()
        self.size.setRange(100, 100000)
        self.size.setSuffix(" MB")
        self.size.setValue(int(settings.get("max_total_mb", 2048)))
        form.addRow("Company on reports", self.company)
        form.addRow("Logo (PNG or JPG)", row)
        form.addRow("Save runs in", self.folder)
        form.addRow("Capture size limit", self.size)
        lay.addLayout(form)
        box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        box.accepted.connect(self._save)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

    def _logo(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Logo", "", "Images (*.png *.jpg *.jpeg)")
        if p:
            self.logo.setText(p)

    def _save(self) -> None:
        self.settings.update({"company": self.company.text().strip(), "logo_path": self.logo.text().strip(),
                              "runs_dir": self.folder.text().strip(), "max_total_mb": self.size.value()})
        save_settings(self.settings)
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"l2-loopcheck {__version__}")
        self.setWindowIcon(app_icon())
        self.resize(1100, 800)
        self.settings = load_settings()
        self.wizard: Wizard | None = None
        central = QWidget()
        lay = QVBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        header = QWidget()
        header.setObjectName("Header")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(24, 12, 24, 12)
        hl.addWidget(label("l2-loopcheck", "AppTitle", False))
        hl.addWidget(label("Network health and security check", "HeaderNote", False))
        hl.addStretch(1)
        hl.addWidget(label(f"v{__version__}", "HeaderNote", False))
        lay.addWidget(header)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.home_page = self._build_home()
        self.results = ResultsPage(self.settings)
        self.results.home.connect(self.show_home)
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.results)

    def _build_home(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Page")
        outer = QHBoxLayout(w)
        outer.addStretch(1)
        col = QVBoxLayout()
        col.setSpacing(14)
        col.addStretch(1)
        col.addWidget(label("What would you like to do?", "PageTitle"))
        col.addWidget(label("Find Layer-2 loops, broadcast storms, spanning-tree faults and security weaknesses from "
                            "captured traffic. It only listens, unless you choose to send the loop probe.", "Muted"))
        for title, text, fn in (("Run a check", "Connect this computer to the network. A step-by-step guide takes you to a report.", self.start_wizard),
                                ("Analyse a capture file", "Check a .pcap or .pcapng file you already have.", self.analyse_file),
                                ("Open a saved result", "Reopen a result.json from an earlier run.", self.open_saved)):
            b = QPushButton(f"{title}\n{text}")
            b.setObjectName("Choice")
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _c=False, f=fn: f())
            col.addWidget(b)
        self.busy = label("", "Muted")
        col.addWidget(self.busy)
        col.addStretch(2)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(button("Report and storage settings...", self.open_settings))
        col.addLayout(row)
        holder = QWidget()
        holder.setLayout(col)
        holder.setFixedWidth(760)
        outer.addWidget(holder)
        outer.addStretch(1)
        return w

    def open_settings(self) -> None:
        SettingsDialog(self, self.settings).exec()

    def show_home(self) -> None:
        self._drop_wizard()
        self.busy.setText("")
        self.stack.setCurrentWidget(self.home_page)

    def _drop_wizard(self) -> None:
        if self.wizard is not None:
            self.stack.removeWidget(self.wizard)
            self.wizard.deleteLater()
            self.wizard = None

    def start_wizard(self) -> None:
        self._drop_wizard()
        self.wizard = Wizard(self.settings)
        self.wizard.cancelled.connect(self.show_home)
        self.wizard.finished.connect(self.show_result)
        self.stack.addWidget(self.wizard)
        self.stack.setCurrentWidget(self.wizard)

    def show_result(self, result: dict, run_dir: str) -> None:
        self._drop_wizard()
        self.results.show_result(result, run_dir)
        self.stack.setCurrentWidget(self.results)

    def analyse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open a capture file", "", "Captures (*.pcap *.pcapng *.cap);;All files (*)")
        if not path:
            return
        names = [v[1] for v in VANTAGE]
        pick, ok = QInputDialog.getItem(self, "Where was this captured?", "Capture point:", names, len(names) - 1, False)
        if not ok:
            return
        vantage = next(v[0] for v in VANTAGE if v[1] == pick) or None
        base = self.settings.get("runs_dir") or default_runs_dir()
        run_dir = os.path.join(base, time.strftime("%Y%m%d-%H%M%S"))
        branding = {k: self.settings.get(k, "") for k in ("company", "logo_path")}

        def work() -> dict:
            r = analyze_file(path, vantage)
            os.makedirs(run_dir, exist_ok=True)
            write_outputs(r, os.path.join(run_dir, "result.json"), os.path.join(run_dir, "report.html"), branding)
            return r

        self.busy.setText(f"Analysing {os.path.basename(path)}...")
        run_task(work, lambda r: self.show_result(r, run_dir), self._analyse_failed)

    def _analyse_failed(self, message: str) -> None:
        self.busy.setText("")
        QMessageBox.critical(self, "Could not analyse this file", message)

    def open_saved(self) -> None:
        start = self.settings.get("runs_dir") or default_runs_dir()
        path, _ = QFileDialog.getOpenFileName(self, "Open a saved result", start, "Result (result.json *.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                r = json.load(f)
            r["verdict"], r["capture"]  # noqa: B018 - reject files that are not results
        except (OSError, ValueError, KeyError, TypeError) as e:
            QMessageBox.critical(self, "Not a saved result", str(e))
            return
        self.show_result(r, os.path.dirname(path))

    def closeEvent(self, event) -> None:
        if self.wizard is not None and self.wizard.busy:
            if QMessageBox.question(self, "Capture running", "Stop the capture and quit? The results so far are saved.",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                event.ignore()
                return
            s = self.wizard.running.session
            self.wizard.running.timer.stop()
            self.wizard.running.session = None
            if s:
                s.stop({})
        event.accept()


def run_gui() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(theme.stylesheet())
    app.setWindowIcon(app_icon())
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run_gui())
