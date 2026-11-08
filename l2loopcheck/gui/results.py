"""The results page: verdicts, severity counts, findings and every way to get the report."""

from __future__ import annotations

import html
import json
import os
import shutil

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QMessageBox, QSplitter,
                               QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ..cli import write_outputs
from ..report.redact import redact
from . import theme
from .common import Banner, button, card, label, open_path, pill

SEV_ORDER = ("critical", "high", "warning", "low", "info")


def _tile(n: int, sev: str) -> QFrame:
    f = QFrame()
    f.setObjectName("Card")
    bar = theme.SEVERITY[sev][1]
    f.setStyleSheet(f"QFrame#Card {{ border-top: 4px solid {bar}; }}")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(14, 6, 14, 8)
    lay.setSpacing(0)
    lay.addWidget(label(str(n), "Stat", False))
    lay.addWidget(label(theme.SEVERITY[sev][2], "Muted", False))
    return f


class ResultsPage(QWidget):
    home = Signal()

    def __init__(self, settings: dict) -> None:
        super().__init__()
        self.settings = settings
        self.result: dict = {}
        self.run_dir = ""
        self.findings: list[dict] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        body = QVBoxLayout()
        body.setContentsMargins(30, 20, 30, 12)
        body.setSpacing(10)
        head = QHBoxLayout()
        titles = QVBoxLayout()
        titles.addWidget(label("Check complete", "PageTitle"))
        self.sub = label("", "Muted")
        titles.addWidget(self.sub)
        head.addLayout(titles, 1)
        self.open_btn = button("Open full report in browser", self.open_report, "Primary")
        head.addWidget(self.open_btn, 0, Qt.AlignTop)
        body.addLayout(head)
        self.banner = Banner()
        body.addWidget(self.banner)
        c, cl = card()
        row = QHBoxLayout()
        self.network = label("")
        self.security = label("")
        row.addWidget(self.network, 1)
        row.addWidget(self.security, 1)
        cl.addLayout(row)
        self.tiles = QHBoxLayout()
        cl.addLayout(self.tiles)
        self.note = label("", "Muted")
        cl.addWidget(self.note)
        body.addWidget(c)
        split = QSplitter(Qt.Horizontal)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Severity", "Finding", "Area"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.itemSelectionChanged.connect(self._selected)
        split.addWidget(self.table)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        split.addWidget(self.detail)
        split.setSizes([560, 500])
        body.addWidget(split, 1)
        lay.addLayout(body, 1)
        foot = QFrame()
        foot.setObjectName("Footer")
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(30, 12, 30, 12)
        fl.addWidget(button("Save HTML report...", self.save_html))
        fl.addWidget(button("Save JSON...", self.save_json))
        fl.addWidget(button("Save redacted HTML...", self.save_redacted))
        fl.addWidget(button("Open folder", lambda: self.run_dir and open_path(self.run_dir)))
        fl.addStretch(1)
        fl.addWidget(button("Back to home", self.home.emit))
        lay.addWidget(foot)

    def show_result(self, result: dict, run_dir: str) -> None:
        self.result, self.run_dir = result, run_dir
        v, cap = result["verdict"], result["capture"]
        sec = v.get("security") or {"posture": "Not assessed", "counts": {}, "checks_limited": 0}
        self.sub.setText(f"{cap['packets']:,} frames over {cap['duration_s']:.0f} s. Saved in {run_dir}")
        self.sub.setTextFormat(Qt.PlainText)
        self.network.setText(self._verdict_html("Network health", v["label"], f"confidence: {v['confidence']}"))
        self.security.setText(self._verdict_html("Security", sec["posture"], ""))
        while self.tiles.count():
            w = self.tiles.takeAt(0).widget()
            if w:
                w.setParent(None)
        for s in SEV_ORDER:
            n = sum(1 for f in v["findings"] if f["severity"] == s)
            self.tiles.addWidget(_tile(n, s))
        self.note.setText(f"{sec['checks_limited']} checks were limited by where this capture was taken. The full report "
                          "lists them, so a missing finding is not mistaken for a pass." if sec["checks_limited"] else "")
        self._quality_banner(result)
        self.findings = v["findings"]
        self.table.setRowCount(len(self.findings))
        for i, f in enumerate(self.findings):
            fg, bg, text = theme.SEVERITY.get(f["severity"], theme.SEVERITY["info"])
            badge = pill(text, fg, bg)
            badge.setAttribute(Qt.WA_TransparentForMouseEvents)  # clicks still select the row
            self.table.setItem(i, 0, QTableWidgetItem(""))
            self.table.setCellWidget(i, 0, badge)
            self.table.setItem(i, 1, QTableWidgetItem(f["title"]))
            self.table.setItem(i, 2, QTableWidgetItem("Security" if f.get("category") == "security" else "Network"))
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(2)
        if self.findings:
            self.table.selectRow(0)
        else:
            self.detail.setHtml("<p>No findings.</p>")
        self.open_btn.setEnabled(os.path.isfile(self.report_path()))

    def _verdict_html(self, area: str, value: str, extra: str) -> str:
        colour = theme.VERDICT.get(value, theme.MUTED)
        tail = f"<br><span style='color:{theme.MUTED}'>{html.escape(extra)}</span>" if extra else ""
        return (f"<span style='color:{theme.MUTED}'>{html.escape(area)}</span><br>"
                f"<span style='font-size:18pt;font-weight:600;color:{colour}'>{html.escape(value)}</span>{tail}")

    def _quality_banner(self, r: dict) -> None:
        v, cap = r["verdict"], r["capture"]
        problems = [x for x in v.get("limitations", []) if not x.startswith("Captured from one port")]
        declared, seen = cap.get("vantage_declared"), cap.get("vantage_observed")
        if declared and seen and declared != seen and not (declared in ("span", "trunk") and seen == "access"):
            problems.append(f"this port was described as {declared}, but the traffic looks like {seen}")
        if not cap["packets"]:
            self.banner.show_message("error", "No frames were captured. Check the cable and the adapter.", "No result.")
        elif problems:
            self.banner.show_message("warning", "; ".join(problems).capitalize() + ".", "Capture quality:")
        else:
            self.banner.clear()

    def _selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        f = self.findings[rows[0].row()]
        e = html.escape
        _fg, bg, text = theme.SEVERITY.get(f["severity"], theme.SEVERITY["info"])
        parts = [f"<p><span style='background:{bg};color:white'>&nbsp;{text}&nbsp;</span> &nbsp;"
                 f"<span style='color:{theme.MUTED}'>{e(f.get('confidence', ''))}</span></p>",
                 f"<h3>{e(f['title'])}</h3>", f"<p><b>Observed</b><br>{e(f['observed'])}</p>"]
        if f.get("hypothesis"):
            parts.append(f"<p><b>What it may mean</b><br><i>{e(f['hypothesis'])}</i></p>")
        if f.get("recommendation"):
            parts.append(f"<p><b>What to do</b><br>{e(f['recommendation'])}</p>")
        if f.get("frames"):
            parts.append(f"<p style='color:{theme.MUTED}'>Frames in the capture file: "
                         f"{e(', '.join(str(x) for x in f['frames'][:10]))}</p>")
        self.detail.setHtml("".join(parts))

    # ------------------------------------------------------------ outputs
    def report_path(self) -> str:
        return os.path.join(self.run_dir, "report.html")

    def branding(self) -> dict:
        return {k: self.settings.get(k, "") for k in ("company", "logo_path")}

    def open_report(self) -> None:
        if os.path.isfile(self.report_path()):
            open_path(self.report_path())
        else:
            QMessageBox.warning(self, "Report missing", f"No report found in {self.run_dir}.")

    def _ask(self, title: str, name: str, flt: str) -> str:
        path, _ = QFileDialog.getSaveFileName(self, title, os.path.join(os.path.expanduser("~"), name), flt)
        return path

    def _write(self, fn, path: str) -> None:
        try:
            fn(path)
        except OSError as e:
            QMessageBox.critical(self, "Could not save", str(e))

    def save_html(self) -> None:
        p = self._ask("Save HTML report", "l2-loopcheck-report.html", "HTML (*.html)")
        if p:
            self._write(lambda x: shutil.copyfile(self.report_path(), x) if os.path.isfile(self.report_path())
                        else write_outputs(self.result, None, x, self.branding()), p)

    def save_json(self) -> None:
        p = self._ask("Save JSON", "l2-loopcheck-result.json", "JSON (*.json)")
        if p:
            def write(path: str) -> None:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.result, f, indent=2, default=str)

            self._write(write, p)

    def save_redacted(self) -> None:
        p = self._ask("Save redacted HTML for sharing", "l2-loopcheck-redacted.html", "HTML (*.html)")
        if p:
            self._write(lambda x: write_outputs(redact(json.loads(json.dumps(self.result, default=str))), None, x, {}), p)
