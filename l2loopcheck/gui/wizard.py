"""The "Run a check" wizard: site and authorisation, adapter, pre-flight, plan, capture."""

from __future__ import annotations

import html
import os
import time
from typing import Callable, Optional

from PySide6.QtCore import QPointF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout,
                               QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QRadioButton, QStackedWidget,
                               QVBoxLayout, QWidget)

from .. import preflight as pf
from ..capture import CaptureToolMissing, WIRESHARK_URL
from ..live import LiveSession
from . import theme
from .common import Banner, button, card, default_runs_dir, label, open_path, page, pill, plain, run_task, save_settings

STEPS = ["Site and authorisation", "Network adapter", "Pre-flight checks", "Plan", "Capture"]
VANTAGE = [("access", "Access port", "An ordinary switch port. Shows flooded traffic and this computer's own traffic."),
           ("span", "SPAN or mirror port", "The switch copies other ports here. Shows other hosts' traffic."),
           ("trunk", "Trunk or uplink", "Carries several tagged VLANs."),
           ("", "I don't know", "The tool will infer it from the traffic.")]
DURATIONS = [("2 minutes (quick look only)", 120), ("5 minutes", 300), ("10 minutes (recommended minimum)", 600),
             ("30 minutes", 1800), ("1 hour", 3600), ("Until I press Stop", 0)]
SHORT_RUN_S = 60
NO_FRAMES_WARN_S = 15


class SitePage(QWidget):
    changed = Signal()

    def __init__(self, settings: dict) -> None:
        super().__init__()
        self.settings = settings
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        area, lay = page("Site and authorisation", "This goes on the report. Nothing is captured yet.")
        outer.addWidget(area)
        c, cl = card()
        form = QFormLayout()
        self.fields = {}
        for key, text, hint in (("site", "Site name *", "e.g. Level 3 comms room"), ("client", "Client", ""),
                                ("engineer", "Engineer *", "Your name"), ("org", "Organisation", "Your company"),
                                ("case_ref", "Case reference", "")):
            e = QLineEdit(settings.get(key, "") if key in ("engineer", "org") else "")
            e.setPlaceholderText(hint)
            e.textChanged.connect(self.changed)
            form.addRow(text, e)
            self.fields[key] = e
        cl.addLayout(form)
        lay.addWidget(c)
        self.auth = QCheckBox("I am authorised by the network owner to capture traffic on this network.")
        self.auth.toggled.connect(self.changed)
        lay.addWidget(self.auth)
        lay.addWidget(label("Packet captures can contain private data. The saved capture files stay on this computer "
                            "until you move them.", "Muted"))
        lay.addStretch(1)

    def values(self) -> dict:
        return {k: e.text().strip() for k, e in self.fields.items()}

    def problem(self) -> str:
        v = self.values()
        if not v["site"] or not v["engineer"]:
            return "Enter the site name and the engineer."
        if not self.auth.isChecked():
            return "Confirm that you are authorised to capture on this network."
        return ""

    def enter(self) -> None:
        pass


class NetworkPage(QWidget):
    changed = Signal()

    def __init__(self, settings: dict) -> None:
        super().__init__()
        self.settings = settings
        self.adapters: list[dict] = []
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        area, lay = page("Network adapter", "Pick the adapter plugged into the switch you want to check.")
        outer.addWidget(area)
        c, cl = card()
        row = QHBoxLayout()
        self.combo = QComboBox()
        self.combo.currentIndexChanged.connect(self._sync)
        row.addWidget(self.combo, 1)
        self.refresh_btn = button("Refresh", self.load)
        row.addWidget(self.refresh_btn)
        cl.addLayout(row)
        self.warn = Banner()
        cl.addWidget(self.warn)
        cl.addWidget(label("Why this adapter was suggested", "Section"))
        self.reasons = plain("Looking for adapters...")
        cl.addWidget(self.reasons)
        lay.addWidget(c)
        v, vl = card(4)
        vl.addWidget(label("How is this port connected?", "Section"))
        self.vantage = QButtonGroup(self)
        self.vantage_ids = {}
        for i, (key, text, why) in enumerate(VANTAGE):
            r = QRadioButton(f"{text}:  {why}")
            r.setChecked(key == "")
            self.vantage.addButton(r, i)
            self.vantage_ids[i] = key
            vl.addWidget(r)
        lay.addWidget(v)
        self.confirm = QCheckBox("Yes, this adapter is cabled to the network I want to check.")
        self.confirm.toggled.connect(self.changed)
        lay.addWidget(self.confirm)
        lay.addStretch(1)

    def enter(self) -> None:
        if not self.adapters:
            self.load()

    def load(self) -> None:
        self.reasons.setText("Looking for adapters...")
        self.refresh_btn.setEnabled(False)
        run_task(pf.discover_adapters, self._loaded, self._failed)

    def _failed(self, message: str) -> None:
        self.refresh_btn.setEnabled(True)
        self.adapters = []
        self.combo.clear()
        self.reasons.setText("")
        self.warn.show_message("error", message, "Cannot list adapters:")
        self.changed.emit()

    def _loaded(self, adapters: list) -> None:
        self.refresh_btn.setEnabled(True)
        self.adapters = adapters
        self.confirm.setChecked(False)
        pick, reasons = pf.suggest(adapters)
        self.combo.blockSignals(True)
        self.combo.clear()
        for a in adapters:
            self.combo.addItem(pf.adapter_label(a))
        if pick:
            self.combo.setCurrentIndex(adapters.index(pick))
        self.combo.blockSignals(False)
        self.reasons.setText("\n".join(f"• {r}" for r in reasons))
        self.reasons.setMinimumHeight(self.reasons.fontMetrics().lineSpacing() * (len(reasons) + 1))
        self._sync()

    def selected(self) -> Optional[dict]:
        i = self.combo.currentIndex()
        return self.adapters[i] if 0 <= i < len(self.adapters) else None

    def selected_vantage(self) -> Optional[str]:
        return self.vantage_ids[self.vantage.checkedId()] or None

    def _sync(self, *_a) -> None:
        a = self.selected()
        warnings = pf.adapter_warnings(a) if a else []
        self.confirm.setChecked(False)
        if warnings:
            worst = "error" if any(s == pf.ERROR for s, _m in warnings) else "warning"
            self.warn.show_message(worst, " ".join(m for _s, m in warnings),
                                   "Cannot use this adapter:" if worst == "error" else "Check this is right:")
        else:
            self.warn.clear()
        self.changed.emit()

    def problem(self) -> str:
        a = self.selected()
        if a is None:
            return "No adapter available. Install Wireshark or plug in a network adapter, then press Refresh."
        if any(s == pf.ERROR for s, _m in pf.adapter_warnings(a)):
            return "This adapter cannot be used. Pick another one."
        if not self.confirm.isChecked():
            return "Confirm that this is the right adapter."
        return ""


class PreflightPage(QWidget):
    changed = Signal()

    def __init__(self, get_adapter: Callable[[], Optional[dict]], settings: dict) -> None:
        super().__init__()
        self.get_adapter, self.settings = get_adapter, settings
        self.checks: list[dict] = []
        self.running = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        area, lay = page("Pre-flight checks", "Quick checks on this computer. The test capture only listens; nothing is sent.")
        outer.addWidget(area)
        c, cl = card()
        self.rows = QGridLayout()
        self.rows.setColumnStretch(1, 1)
        self.rows.setHorizontalSpacing(16)
        cl.addLayout(self.rows)
        h = QHBoxLayout()
        h.addStretch(1)
        self.again = button("Check again", self.run)
        h.addWidget(self.again)
        cl.addLayout(h)
        lay.addWidget(c)
        self.result = Banner()
        lay.addWidget(self.result)
        self.accept = QCheckBox("I have read the warnings and want to continue.")
        self.accept.toggled.connect(self.changed)
        self.accept.hide()
        lay.addWidget(self.accept)
        lay.addStretch(1)

    def enter(self) -> None:
        self.run()

    def run(self) -> None:
        a = self.get_adapter()
        folder = self.settings.get("runs_dir") or default_runs_dir()
        self.running = True
        self.checks = []
        self.again.setEnabled(False)
        self.accept.setChecked(False)
        self.accept.hide()
        self.result.show_message("info", "Running the checks. This takes about five seconds.")
        self.changed.emit()
        run_task(lambda: pf.run_preflight(a, folder, max_total_mb=int(self.settings.get("max_total_mb", 2048))),
                 self._done, self._failed)

    def _failed(self, message: str) -> None:
        self.running = False
        self.again.setEnabled(True)
        self.result.show_message("error", message, "The checks could not run:")
        self.changed.emit()

    def _done(self, checks: list) -> None:
        self.running = False
        self.again.setEnabled(True)
        self.checks = checks
        while self.rows.count():
            w = self.rows.takeAt(0).widget()
            if w:
                w.setParent(None)
        for i, c in enumerate(checks):
            colour, text = theme.STATUS[c["status"]]
            self.rows.addWidget(label(f"<b style='color:{colour}'>{text}</b>"), i, 0, Qt.AlignTop)
            d = label(f"<b>{html.escape(c['title'])}</b><br>{html.escape(c['detail'])}")
            self.rows.addWidget(d, i, 1)
        errors = pf.blocking(checks)
        warnings = [c for c in checks if c["status"] == pf.WARNING]
        if errors:
            self.result.show_message("error", "Fix the items marked Problem, then press Check again.", "Cannot continue.")
        elif warnings:
            self.result.show_message("warning", "The capture will run, but its results may be incomplete.", "Warnings.")
            self.accept.show()
        else:
            self.result.show_message("ok", "Ready to capture.", "All clear.")
        self.changed.emit()

    def problem(self) -> str:
        if self.running or not self.checks:
            return "Waiting for the checks to finish."
        if pf.blocking(self.checks):
            return "Fix the problems first."
        if any(c["status"] == pf.WARNING for c in self.checks) and not self.accept.isChecked():
            return "Confirm that you have read the warnings."
        return ""


class PlanPage(QWidget):
    changed = Signal()

    def __init__(self, settings: dict, ask: Callable[[str, str], bool]) -> None:
        super().__init__()
        self.settings, self.ask = settings, ask
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        area, lay = page("Plan", "Confirm what will happen.")
        outer.addWidget(area)
        c, cl = card()
        form = QFormLayout()
        self.duration = QComboBox()
        for text, _s in DURATIONS:
            self.duration.addItem(text)
        self.duration.setCurrentIndex(2)
        form.addRow("Capture for", self.duration)
        row = QHBoxLayout()
        self.folder = QLineEdit(settings.get("runs_dir") or default_runs_dir())
        row.addWidget(self.folder, 1)
        row.addWidget(button("Change...", self._browse))
        form.addRow("Save in", row)
        cl.addLayout(form)
        cl.addWidget(label("Short captures can miss intermittent problems. Spanning-tree changes and DHCP activity often "
                           "need ten minutes or more. Capture while the problem is happening if you can.", "Muted"))
        lay.addWidget(c)
        w, wl = card(4)
        wl.addWidget(label("What will happen", "Section"))
        self.summary = plain("")
        wl.addWidget(self.summary)
        lay.addWidget(w)
        p, pl = card(4)
        pl.addWidget(label("Optional: active loop probe", "Section"))
        self.probe = QCheckBox("Send up to 3 broadcast test frames, 1 per second, during this capture.")
        self.probe.toggled.connect(self._probe_toggled)
        pl.addWidget(self.probe)
        pl.addWidget(label("If a frame comes back, this port is part of a loop. It is the only thing this tool ever "
                           "transmits. Leave it off unless the site owner has agreed.", "Muted"))
        lay.addWidget(p)
        lay.addStretch(1)
        self.duration.currentIndexChanged.connect(lambda _i: self._update())
        self._update()

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Save runs in", self.folder.text())
        if d:
            self.folder.setText(d)

    def _probe_toggled(self, on: bool) -> None:
        if on and not self.ask("Send test frames?", "This transmits up to 3 broadcast frames on the network. "
                                                    "Has the site owner agreed to this?"):
            self.probe.setChecked(False)
        self._update()

    def seconds(self) -> int:
        return DURATIONS[self.duration.currentIndex()][1]

    def _update(self) -> None:
        d = self.duration.currentText().split(" (")[0].lower()
        sends = "Up to 3 test frames will be sent." if self.probe.isChecked() else "Nothing will be sent on the network."
        self.summary.setText(f"• Capture all frames on the selected adapter, {d}.\n• {sends}\n"
                             "• Save the capture files, marks, results and an HTML report.\n"
                             "• Capture files are limited to "
                             f"{int(self.settings.get('max_total_mb', 2048)):,} MB; the oldest are removed first, and "
                             "files around your marks are kept.")

    def enter(self) -> None:
        self._update()

    def problem(self) -> str:
        return "" if self.folder.text().strip() else "Choose where to save the run."


class Timeline(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setMinimumHeight(130)
        self.series: list[dict] = []

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(8, 8, -8, -22)
        p.fillRect(self.rect(), QColor(theme.CARD))
        p.setPen(QPen(QColor(theme.BORDER), 1))
        p.drawRect(r)
        data = self.series[-300:]
        p.setPen(QColor(theme.MUTED))
        peak = max([1.0] + [max(s["flooded"], s["copies"]) for s in data])
        p.drawText(r.left() + 6, r.top() + 15, f"{peak:,.0f} frames/s")
        p.drawText(self.rect().adjusted(10, 0, -10, -3), Qt.AlignLeft | Qt.AlignBottom,
                   "Blue: broadcast + multicast/s    Red: repeated frames/s")
        if len(data) >= 2:
            for key, colour in (("flooded", "#2f6fa8"), ("copies", theme.DANGER)):
                pts = [QPointF(r.left() + r.width() * i / (len(data) - 1), r.bottom() - r.height() * s[key] / peak)
                       for i, s in enumerate(data)]
                p.setPen(QPen(QColor(colour), 1.6))
                p.drawPolyline(QPolygonF(pts))
        p.end()


class RunningPage(QWidget):
    finished = Signal(object, str)  # result dict, run folder
    failed = Signal(str)

    def __init__(self, ask: Callable[[str, str], bool]) -> None:
        super().__init__()
        self.ask = ask
        self.session: Optional[LiveSession] = None
        self.seconds = 0
        self.started = 0.0
        self.stopping = False
        self.branding: dict = {}
        self.probe_pending = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        area, lay = page("Capture running", "You can leave the laptop running. Press Stop at any time; the results so far are kept.")
        outer.addWidget(area)
        self.banner = Banner()
        lay.addWidget(self.banner)
        c, cl = card()
        top = QHBoxLayout()
        big = QVBoxLayout()
        self.repeats = label("0", "BigNumber", False)
        big.addWidget(self.repeats)
        big.addWidget(label("repeated frames per second. Stays near 0 on a healthy network.", "Muted"))
        top.addLayout(big, 2)
        self.stats = {}
        grid = QGridLayout()
        for i, (key, text) in enumerate((("flooded", "broadcast + multicast/s"), ("total", "all frames/s"),
                                         ("tc", "topology changes"), ("saved", "MB saved"))):
            v = label("0", "Stat", False)
            grid.addWidget(v, 0, i)
            grid.addWidget(label(text, "Muted"), 1, i)
            self.stats[key] = v
        top.addLayout(grid, 3)
        self.stop_btn = button("Stop", self.request_stop, "Danger")
        top.addWidget(self.stop_btn, 0, Qt.AlignTop)
        cl.addLayout(top)
        self.status = plain("")
        cl.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        cl.addWidget(self.progress)
        lay.addWidget(c)
        t, tl = card()
        self.timeline = Timeline()
        tl.addWidget(self.timeline)
        lay.addWidget(t)
        m, ml = card()
        ml.addWidget(label("Add a mark each time you change something", "Section"))
        ml.addWidget(label("Unplug one suspect cable at a time and note it here. If the red number drops to 0, your last "
                           "mark names the cable that closed the loop.", "Muted"))
        row = QHBoxLayout()
        self.mark = QLineEdit()
        self.mark.setPlaceholderText("e.g. unplugged 2/F uplink")
        self.mark.returnPressed.connect(self.add_mark)
        row.addWidget(self.mark, 1)
        row.addWidget(button("Add mark", self.add_mark))
        ml.addLayout(row)
        self.marks = QPlainTextEdit()
        self.marks.setReadOnly(True)
        self.marks.setMaximumHeight(90)
        ml.addWidget(self.marks)
        lay.addWidget(m)
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self.tick)

    def start(self, session: LiveSession, seconds: int, branding: dict, probe: bool) -> None:
        self.session, self.seconds, self.branding = session, seconds, branding
        self.probe_pending = probe
        self.stopping = False
        self.banner.clear()
        self.marks.clear()
        self.stop_btn.setEnabled(True)
        self.stop_btn.setText("Stop")
        self.progress.setRange(0, seconds or 0)
        self.started = time.time()
        session.start()
        self.timer.start()
        self.tick()

    def add_mark(self) -> None:
        if not self.session or self.stopping:
            return
        n = len(self.session.marks()) + 1
        m = self.session.add_mark(self.mark.text().strip() or f"Mark {n}")
        self.marks.appendPlainText(f"{n}. {time.strftime('%H:%M:%S', time.localtime(m['ts']))}  {m['label']}")
        self.mark.clear()
        self.mark.setFocus()

    def tick(self) -> None:
        s = self.session
        if not s or self.stopping:
            return
        snap = s.snapshot()
        elapsed = time.time() - self.started
        self.repeats.setText(f"{snap['copies']:,}")
        colour = theme.OK if snap["copies"] == 0 else theme.WARN if snap["copies"] < 50 else theme.DANGER
        self.repeats.setStyleSheet(f"color:{colour}")
        self.stats["flooded"].setText(f"{snap['flooded']:,}")
        self.stats["total"].setText(f"{snap['total']:,}")
        self.stats["tc"].setText(f"{snap['tc_total']}")
        self.stats["saved"].setText(f"{snap['saved_mb']:.0f}")
        self.timeline.series = s.series(300)
        self.timeline.update()
        left = f", {int(self.seconds - elapsed)} s left" if self.seconds else ""
        self.status.setText(f"Elapsed {int(elapsed // 60)}:{int(elapsed % 60):02d}{left}. "
                            f"{snap['packets']:,} frames captured. Folder: {s.run_dir}")
        if self.seconds:
            self.progress.setValue(min(int(elapsed), self.seconds))
        if self.probe_pending and elapsed >= 3:
            self.probe_pending = False
            self._run_probe()
        if s.ended.is_set():
            self.banner.show_message("error", s.error or "The capture tool stopped unexpectedly.", "Capture stopped:")
            self.stop()
            return
        if snap["packets"] == 0 and elapsed >= NO_FRAMES_WARN_S:
            self.banner.show_message("warning", f"No frames in {int(elapsed)} seconds. Check the cable and the adapter.",
                                     "Nothing is arriving.")
        elif self.banner.isVisible() and snap["packets"]:
            self.banner.clear()
        if self.seconds and elapsed >= self.seconds:
            self.stop()

    def _run_probe(self) -> None:
        s = self.session

        def done(res: dict) -> None:
            self.banner.show_message("error" if res["loop_confirmed"] else "ok",
                                     "A test frame came back: this port is part of a loop." if res["loop_confirmed"]
                                     else f"{res['sent']} test frames sent; none came back.", "Probe:")

        run_task(lambda: s.run_probe(log=lambda _m: None), done,
                 lambda m: self.banner.show_message("warning", m, "Probe not available:"))

    def request_stop(self) -> None:
        elapsed = time.time() - self.started
        if elapsed < SHORT_RUN_S and not self.ask(
                "Stop this early?", f"Only {int(elapsed)} seconds have been captured, so the results will be weak. Stop anyway?"):
            return
        self.stop()

    def stop(self) -> None:
        s = self.session
        if not s or self.stopping:
            return
        self.stopping = True
        self.timer.stop()
        self.stop_btn.setEnabled(False)
        self.stop_btn.setText("Stopping...")
        self.status.setText("Stopping the capture and writing the report...")
        run_task(lambda: s.stop(self.branding), lambda r: self._done(r, s), self.failed.emit)

    def _done(self, result: dict, s: LiveSession) -> None:
        self.session = None
        self.finished.emit(result, s.run_dir)

    @property
    def active(self) -> bool:
        return self.session is not None


class Wizard(QWidget):
    finished = Signal(object, str)
    cancelled = Signal()

    def __init__(self, settings: dict) -> None:
        super().__init__()
        self.settings = settings
        self.stack = QStackedWidget()
        self.site = SitePage(settings)
        self.network = NetworkPage(settings)
        self.pre = PreflightPage(self.network.selected, settings)
        self.plan = PlanPage(settings, self.ask)
        self.running = RunningPage(self.ask)
        self.pages = [self.site, self.network, self.pre, self.plan, self.running]
        for p in self.pages:
            self.stack.addWidget(p)
            if hasattr(p, "changed"):
                p.changed.connect(self.sync)
        self.running.finished.connect(self.finished)
        self.running.failed.connect(self._capture_failed)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.stack, 1)
        foot = QFrame()
        foot.setObjectName("Footer")
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(36, 12, 36, 12)
        self.where = label("", "Muted", False)
        self.hint = label("", "Muted", False)
        fl.addWidget(self.where)
        fl.addSpacing(14)
        fl.addWidget(self.hint, 1)
        self.cancel_btn = button("Cancel", self.cancelled.emit)
        self.back_btn = button("Back", self.back)
        self.next_btn = button("Next", self.next, "Primary")
        for b in (self.cancel_btn, self.back_btn, self.next_btn):
            fl.addWidget(b)
        lay.addWidget(foot)
        self.foot = foot
        self.go(0)

    def ask(self, title: str, text: str) -> bool:
        return QMessageBox.question(self, title, text, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def go(self, i: int) -> None:
        self.stack.setCurrentIndex(i)
        self.pages[i].enter() if hasattr(self.pages[i], "enter") else None
        self.sync()

    def sync(self) -> None:
        i = self.stack.currentIndex()
        self.where.setText(f"Step {i + 1} of {len(STEPS)}  ·  {STEPS[i]}")
        self.foot.setVisible(i < 4)
        problem = self.pages[i].problem() if i < 4 else ""
        self.hint.setText(problem)
        self.next_btn.setEnabled(not problem)
        self.next_btn.setText("Start capture" if i == 3 else "Next")
        self.back_btn.setEnabled(i > 0)

    def next(self) -> None:
        i = self.stack.currentIndex()
        if i < 3:
            self.go(i + 1)
        else:
            self.start()

    def back(self) -> None:
        self.go(max(0, self.stack.currentIndex() - 1))

    def engagement(self) -> dict:
        v = self.site.values()
        return {**v, "authorised": self.site.auth.isChecked(), "authorised_by": v["engineer"], "preflight": self.pre.checks}

    def start(self) -> None:
        v = self.site.values()
        self.settings.update({"engineer": v["engineer"], "org": v["org"], "runs_dir": self.plan.folder.text().strip()})
        save_settings(self.settings)
        a = self.network.selected()
        run_dir = os.path.join(self.plan.folder.text().strip(), time.strftime("%Y%m%d-%H%M%S"))
        branding = {**{k: self.settings.get(k, "") for k in ("company", "logo_path")}, "company": self.settings.get("company") or v["org"]}
        try:
            session = LiveSession(a["name"], "auto", run_dir, int(self.settings.get("max_total_mb", 2048)),
                                  vantage=self.network.selected_vantage(), engagement=self.engagement())
        except CaptureToolMissing:
            QMessageBox.warning(self, "Wireshark needed", f"Install Wireshark first: {WIRESHARK_URL}")
            return
        self.stack.setCurrentIndex(4)
        self.sync()
        try:
            self.running.start(session, self.plan.seconds(), branding, self.plan.probe.isChecked())
        except OSError as e:
            QMessageBox.critical(self, "Could not start", str(e))
            self.go(3)

    def _capture_failed(self, message: str) -> None:
        folder = self.running.session.run_dir if self.running.session else ""
        self.running.session = None
        QMessageBox.critical(self, "The report could not be written",
                             f"{message}\n\nThe capture files are in {folder}.")
        if folder:
            open_path(folder)
        self.cancelled.emit()

    @property
    def busy(self) -> bool:
        return self.running.active
