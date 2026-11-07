"""Dear PyGui front end for onsite engineers: no commands to type.

Flow: pick the network adapter -> Start -> watch the big REPEATS/s number while
unplugging suspect cables, adding a mark each time -> Stop -> Open report.
Also: open an existing capture file, send the loop probe (with confirmation),
and fill in report details (company, logo, engineer, case reference, site).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from typing import Optional

import dearpygui.dearpygui as dpg

from .. import __version__
from ..capture import WIRESHARK_URL, CaptureToolMissing, list_interfaces
from ..live import LiveSession

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".l2loopcheck", "settings.json")
DEFAULT_RUNS = os.path.join(os.path.expanduser("~"), "Documents", "l2-loopcheck")
BRANDING_KEYS = ("company", "logo_path", "engineer", "case_ref", "site")

GREEN, AMBER, RED, GREY = (46, 160, 67), (230, 150, 20), (220, 50, 40), (150, 155, 160)
VERDICT_COLOURS = {"Loop likely": RED, "STP unstable": AMBER, "Storm without clear loop": AMBER,
                   "Inconclusive": GREY, "Healthy": GREEN}


def _font_candidates() -> list[str]:
    if sys.platform == "darwin":
        return ["/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial.ttf"]
    if os.name == "nt":
        windir = os.environ.get("WINDIR", r"C:\Windows")
        return [os.path.join(windir, "Fonts", f) for f in ("segoeui.ttf", "arial.ttf")]
    return ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf"]


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
    if path.endswith(".html"):
        webbrowser.open("file://" + os.path.abspath(path))
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    elif os.name == "nt":
        os.startfile(path)  # noqa: S606 - opening the run folder in Explorer
    else:
        subprocess.Popen(["xdg-open", path])


class App:
    def __init__(self) -> None:
        self.settings = load_settings()
        self.session: Optional[LiveSession] = None
        self.interfaces: list[tuple[str, str]] = []
        self.last_result: Optional[dict] = None
        self.last_run_dir: Optional[str] = None
        self.big_font = self.mid_font = None
        self._last_ui = 0.0
        self._pending: list = []  # callables to run on the UI thread
        self._lock = threading.Lock()

    # --------------------------------------------------------------- helpers
    def later(self, fn) -> None:
        with self._lock:
            self._pending.append(fn)

    def status(self, msg: str, colour=GREY) -> None:
        dpg.set_value("status", msg)
        dpg.configure_item("status", color=colour)

    def branding(self) -> dict:
        return {k: self.settings.get(k, "") for k in BRANDING_KEYS}

    def runs_dir(self) -> str:
        base = self.settings.get("runs_dir") or DEFAULT_RUNS
        return os.path.join(base, time.strftime("%Y%m%d-%H%M%S"))

    # ------------------------------------------------------------ interfaces
    def refresh_interfaces(self, *_):
        try:
            self.interfaces = list_interfaces("auto")
        except CaptureToolMissing:
            self.interfaces = []
            dpg.configure_item("missing_tool", show=True)
            return
        except Exception as e:  # noqa: BLE001
            self.interfaces = []
            self.status(f"Could not list adapters: {e}", RED)
            return
        items = [self._iface_label(n, d) for n, d in self.interfaces]
        dpg.configure_item("iface", items=items)
        last = self.settings.get("interface")
        pick = next((self._iface_label(n, d) for n, d in self.interfaces if n == last), items[0] if items else "")
        dpg.set_value("iface", pick)
        self.status(f"{len(items)} network adapters found. Pick the one plugged into the switch, then Start.")

    @staticmethod
    def _iface_label(name: str, desc: str) -> str:
        return f"{desc}  [{name}]" if desc else name

    def selected_iface(self) -> Optional[str]:
        label = dpg.get_value("iface")
        for n, d in self.interfaces:
            if self._iface_label(n, d) == label:
                return n
        return None

    # ---------------------------------------------------------- start / stop
    def start(self, *_):
        if self.session:
            return
        iface = self.selected_iface()
        if not iface:
            self.status("Pick a network adapter first.", RED)
            return
        self.settings["interface"] = iface
        save_settings(self.settings)
        try:
            self.session = LiveSession(iface, "auto", self.runs_dir(),
                                       int(self.settings.get("max_total_mb", 2048)),
                                       on_end=lambda err: self.later(lambda: self._capture_ended(err)))
            self.session.start()
        except CaptureToolMissing:
            dpg.configure_item("missing_tool", show=True)
            self.session = None
            return
        except Exception as e:  # noqa: BLE001
            self.session = None
            self.status(f"Could not start capture: {e}", RED)
            return
        dpg.configure_item("btn_start", show=False)
        dpg.configure_item("btn_stop", show=True)
        dpg.configure_item("live_group", enabled=True)
        dpg.configure_item("result_group", show=False)
        dpg.set_value("marks_list", "")
        self.status(f"Capturing on {iface}. Unplug suspect cables one at a time and add a mark each time.", GREEN)

    def _capture_ended(self, err: Optional[str]) -> None:
        if self.session and err:
            self.status(f"Capture stopped: {err}", RED)
            self.stop()

    def stop(self, *_):
        s = self.session
        if not s:
            return
        self.status("Stopping and writing the report...", AMBER)
        dpg.configure_item("btn_stop", enabled=False)

        def work():
            r = s.stop(self.branding())
            self.later(lambda: self._show_result(r, s.run_dir, s.error))

        threading.Thread(target=work, daemon=True).start()

    def _show_result(self, r: dict, run_dir: str, err: Optional[str] = None) -> None:
        self.session = None
        self.last_result, self.last_run_dir = r, run_dir
        dpg.configure_item("btn_stop", show=False, enabled=True)
        dpg.configure_item("btn_start", show=True)
        v = r["verdict"]
        dpg.set_value("verdict", v["label"])
        dpg.configure_item("verdict", color=VERDICT_COLOURS.get(v["label"], GREY))
        dpg.set_value("verdict_conf", f"confidence: {v['confidence']}   ·   {r['capture']['packets']:,} frames, "
                                      f"{r['capture']['duration_s']:.0f} s")
        lines = []
        for f in v["findings"][:8]:
            lines.append(f"[{f['severity'].upper()}] {f['title']}\n    {f['observed']}")
        lines.append("\nNext steps:\n" + "\n".join(f"  - {x}" for x in v["next_steps"]))
        dpg.set_value("findings", "\n".join(lines))
        dpg.configure_item("result_group", show=True)
        self.status(("Capture error: " + err) if err else f"Report saved in {run_dir}", RED if err else GREEN)

    # ----------------------------------------------------------------- marks
    def add_mark(self, *_):
        if not self.session:
            return
        label = dpg.get_value("mark_text").strip() or f"Mark {len(self.session.marks()) + 1}"
        m = self.session.add_mark(label)
        dpg.set_value("mark_text", "")
        n = len(self.session.marks())
        dpg.set_value("marks_list", dpg.get_value("marks_list") +
                      f"{n}. {time.strftime('%H:%M:%S', time.localtime(m['ts']))}  {m['label']}\n")
        dpg.focus_item("mark_text")

    # ----------------------------------------------------------------- probe
    def ask_probe(self, *_):
        if not self.session:
            self.status("Start a capture before sending the probe.", AMBER)
            return
        dpg.configure_item("probe_modal", show=True)

    def run_probe(self, *_):
        dpg.configure_item("probe_modal", show=False)
        s = self.session
        if not s:
            return
        dpg.configure_item("btn_probe", enabled=False)
        self.status("Sending probe (max 3 frames)...", AMBER)

        def work():
            try:
                res = s.run_probe(log=lambda m: self.later(lambda m=m: self.status(m, AMBER)))
                msg = ("Probe came back: LOOP CONFIRMED on this port." if res["loop_confirmed"]
                       else "Probe did not come back (no loop seen from this port).")
                self.later(lambda: self.status(msg, RED if res["loop_confirmed"] else GREEN))
            except Exception as e:  # noqa: BLE001
                self.later(lambda e=e: self.status(f"Probe not available: {e}", RED))
            finally:
                self.later(lambda: dpg.configure_item("btn_probe", enabled=True))

        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------- open file
    def open_file(self, sender, app_data):
        path = app_data.get("file_path_name") if app_data else None
        if not path or not os.path.isfile(path):
            return
        self.status(f"Analysing {os.path.basename(path)}...", AMBER)

        def work():
            from ..cli import analyze_file, write_outputs

            try:
                r = analyze_file(path)
                run = self.runs_dir()
                os.makedirs(run, exist_ok=True)
                write_outputs(r, os.path.join(run, "result.json"), os.path.join(run, "report.html"), self.branding())
                self.later(lambda: self._show_result(r, run))
            except Exception as e:  # noqa: BLE001
                self.later(lambda e=e: self.status(f"Could not analyse file: {e}", RED))

        threading.Thread(target=work, daemon=True).start()

    # -------------------------------------------------------------- settings
    def save_details(self, *_):
        for k in BRANDING_KEYS:
            self.settings[k] = dpg.get_value(f"set_{k}")
        self.settings["runs_dir"] = dpg.get_value("set_runs_dir")
        save_settings(self.settings)
        dpg.configure_item("details_win", show=False)
        self.status("Report details saved.", GREEN)

    # ---------------------------------------------------------------- update
    def tick(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, []
        for fn in pending:
            fn()
        now = time.time()
        if not self.session or now - self._last_ui < 0.5:
            return
        self._last_ui = now
        snap = self.session.snapshot()
        rep = snap["copies"]
        dpg.set_value("big_number", f"{rep:,}")
        dpg.configure_item("big_number", color=GREEN if rep == 0 else (AMBER if rep < 50 else RED))
        dpg.set_value("stats", f"Broadcast+multicast/s: {snap['flooded']:,}    All frames/s: {snap['total']:,}    "
                               f"Topology changes: {snap['tc_total']}    Elapsed: {snap['elapsed']:.0f} s    "
                               f"Saved: {snap['saved_mb']:.0f} MB")
        series = self.session.series(300)
        if series:
            t0 = series[-1]["t"]
            xs = [float(s["t"] - t0) for s in series]
            dpg.set_value("s_flood", [xs, [float(s["flooded"]) for s in series]])
            dpg.set_value("s_copy", [xs, [float(s["copies"]) for s in series]])
            marks = [float(m["ts"] - t0) for m in self.session.marks() if m["ts"] - t0 >= xs[0]]
            dpg.set_value("s_marks", [marks])
            dpg.fit_axis_data("x_axis")
            dpg.fit_axis_data("y_axis")

    # ---------------------------------------------------------------- layout
    def build(self) -> None:
        with dpg.font_registry():
            path = next((p for p in _font_candidates() if os.path.isfile(p)), None)
            if path:
                default = dpg.add_font(path, 16)
                self.mid_font = dpg.add_font(path, 26)
                self.big_font = dpg.add_font(path, 96)
                dpg.bind_font(default)

        with dpg.file_dialog(directory_selector=False, show=False, callback=self.open_file, tag="file_dlg",
                             width=700, height=420, modal=True):
            dpg.add_file_extension("Captures (*.pcap *.pcapng *.cap){.pcap,.pcapng,.cap}")
            dpg.add_file_extension(".*")

        with dpg.window(label="Wireshark needed", modal=True, show=False, tag="missing_tool", width=520,
                        no_resize=True, pos=(180, 160)):
            dpg.add_text("No capture tool was found on this computer.", wrap=480)
            dpg.add_text("Install Wireshark (it includes dumpcap and, on Windows, Npcap), then press Refresh.",
                         wrap=480)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Open download page", callback=lambda: webbrowser.open(WIRESHARK_URL))
                dpg.add_button(label="Close", callback=lambda: dpg.configure_item("missing_tool", show=False))

        with dpg.window(label="Send loop probe?", modal=True, show=False, tag="probe_modal", width=560,
                        no_resize=True, pos=(160, 160)):
            dpg.add_text("The probe sends at most 3 broadcast test frames, one per second, from this computer's "
                         "own network address, and stops as soon as one comes back. If a frame comes back, "
                         "this port is part of a loop.", wrap=520)
            dpg.add_text("Only use it with the site owner's permission.", color=AMBER)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Send probe", callback=self.run_probe)
                dpg.add_button(label="Cancel", callback=lambda: dpg.configure_item("probe_modal", show=False))

        with dpg.window(label="Report details", show=False, tag="details_win", width=560, pos=(160, 100)):
            dpg.add_text("Shown on the report. Leave blank for a neutral report.", color=GREY)
            for k, label in (("company", "Company"), ("logo_path", "Logo file (PNG/JPG)"),
                             ("engineer", "Engineer"), ("case_ref", "Case reference"), ("site", "Site / location")):
                dpg.add_input_text(label=label, tag=f"set_{k}", default_value=self.settings.get(k, ""), width=340)
            dpg.add_input_text(label="Save runs in", tag="set_runs_dir",
                               default_value=self.settings.get("runs_dir", DEFAULT_RUNS), width=340)
            dpg.add_button(label="Save", callback=self.save_details)

        with dpg.window(tag="main"):
            with dpg.group(horizontal=True):
                dpg.add_text("Network adapter")
                dpg.add_combo([], tag="iface", width=420)
                dpg.add_button(label="Refresh", callback=self.refresh_interfaces)
                dpg.add_button(label="  Start  ", tag="btn_start", callback=self.start)
                dpg.add_button(label="  Stop  ", tag="btn_stop", callback=self.stop, show=False)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Open capture file...", callback=lambda: dpg.show_item("file_dlg"))
                dpg.add_button(label="Report details...", callback=lambda: dpg.show_item("details_win"))
            dpg.add_text("", tag="status", wrap=1000)
            dpg.add_separator()

            with dpg.group(tag="live_group"):
                with dpg.group(horizontal=True):
                    with dpg.group():
                        dpg.add_text("REPEATED FRAMES PER SECOND", color=GREY)
                        dpg.add_text("-", tag="big_number", color=GREY)
                        if self.big_font:
                            dpg.bind_item_font("big_number", self.big_font)
                        dpg.add_text("0 = no frames circulating. When you unplug the looped cable this drops to 0.",
                                     color=GREY, wrap=330)
                    with dpg.group():
                        dpg.add_text("Add a mark each time you change something:")
                        dpg.add_input_text(tag="mark_text", hint="e.g. unplugged 2/F uplink", width=360,
                                           on_enter=True, callback=self.add_mark)
                        with dpg.group(horizontal=True):
                            dpg.add_button(label="Add mark", callback=self.add_mark)
                            dpg.add_button(label="Send loop probe...", tag="btn_probe", callback=self.ask_probe)
                        dpg.add_input_text(tag="marks_list", multiline=True, readonly=True, width=520, height=110)
                dpg.add_text("", tag="stats")
                with dpg.plot(label="Last 5 minutes", height=260, width=-1):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="seconds (0 = now)", tag="x_axis")
                    with dpg.plot_axis(dpg.mvYAxis, label="frames/s", tag="y_axis"):
                        dpg.add_line_series([], [], label="Broadcast+multicast/s", tag="s_flood")
                        dpg.add_line_series([], [], label="Repeated/s (loop)", tag="s_copy")
                        dpg.add_inf_line_series([], label="Marks", tag="s_marks")

            with dpg.group(tag="result_group", show=False):
                dpg.add_separator()
                dpg.add_text("", tag="verdict")
                if self.mid_font:
                    dpg.bind_item_font("verdict", self.mid_font)
                dpg.add_text("", tag="verdict_conf", color=GREY)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Open report", callback=lambda: self.last_run_dir and open_path(
                        os.path.join(self.last_run_dir, "report.html")))
                    dpg.add_button(label="Open folder", callback=lambda: self.last_run_dir and open_path(self.last_run_dir))
                dpg.add_input_text(tag="findings", multiline=True, readonly=True, width=-1, height=220)

        with dpg.theme() as th:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 4)
                dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 8, 5)
                dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 8, 8)
        dpg.bind_theme(th)


def run_gui(screenshot: Optional[str] = None, frames: int = 0) -> int:
    dpg.create_context()
    app = App()
    app.build()
    dpg.create_viewport(title=f"l2-loopcheck {__version__}", width=1120, height=860)
    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window("main", True)
    app.refresh_interfaces()
    n = 0
    try:
        while dpg.is_dearpygui_running():
            app.tick()
            dpg.render_dearpygui_frame()
            n += 1
            if screenshot and n == frames:
                dpg.output_frame_buffer(file=screenshot)
            if screenshot and n > frames + 5:
                break
    finally:
        if app.session:
            app.session.stop(app.branding())
        dpg.destroy_context()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_gui())
