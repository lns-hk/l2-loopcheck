"""Command-line interface.

    l2loopcheck analyze capture.pcapng [--json out.json] [--html out.html]
    l2loopcheck live -i <interface> [--duration 10m] [--active]
    l2loopcheck interfaces
    l2loopcheck demo <scenario> [-o demo.pcap]
    l2loopcheck gui
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .engine import Analyzer
from .pcapio import CaptureFormatError, CaptureReader


def _duration(s: str) -> float:
    s = s.strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600}.get(s[-1:], None)
    return float(s[:-1]) * mult if mult else float(s)


def analyze_file(path: str, vantage: str | None = None, engagement: dict | None = None) -> dict:
    a = Analyzer(source=os.path.basename(path))
    a.declared_vantage = vantage
    a.engagement = engagement or {}
    with open(path, "rb") as f:
        reader = CaptureReader(f)
        a.feed_all(reader)
        a.capture_stats = reader.stats
        a.capture_truncated = reader.truncated
    return a.finish()


def write_outputs(result: dict, json_path: str | None, html_path: str | None, branding: dict | None = None) -> None:
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
    if html_path:
        from .report.html import render_html

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(render_html(result, branding or {}))


def print_summary(r: dict, out=sys.stdout) -> None:
    v, cap = r["verdict"], r["capture"]
    w = out.write
    w(f"\nl2-loopcheck {r['tool']['version']}  ·  {cap['source'] or cap['interface']}\n")
    w(f"{cap['packets']} frames over {cap['duration_s']:.1f} s"
      + (f", {cap['drops']} dropped" if cap.get("drops") else "") + "\n\n")
    w(f"VERDICT: {v['label']}  (confidence: {v['confidence']})\n")
    for reason in v["reasons"]:
        w(f"  - {reason}\n")
    sec = v.get("security")
    if sec:
        c = sec["counts"]
        w(f"SECURITY: {sec['posture']}  (critical {c['critical']}, high {c['high']}, medium {c['warning']}, "
          f"low {c['low']}, info {c['info']})\n")
        if sec["checks_limited"]:
            w(f"  {sec['checks_limited']} checks were limited by where this capture was taken; see the report.\n")
    w("\nFindings:\n")
    for f in v["findings"]:
        w(f"  [{f['severity'].upper():8}] {f['title']}\n")
        w(f"      Observed: {f['observed']}\n")
        if f.get("hypothesis"):
            w(f"      Hypothesis: {f['hypothesis']}\n")
        if f.get("frames"):
            w(f"      Frames: {', '.join(str(x) for x in f['frames'][:8])}\n")
    if r["neighbours"]:
        w("\nConnected to (LLDP/CDP):\n")
        for n in r["neighbours"][:5]:
            w(f"  {n['protocol']}: {n['system_name'] or n['chassis']} port {n['port']}"
              + (f" mgmt {n['mgmt_ip']}" if n["mgmt_ip"] else "") + "\n")
    w("\nNext steps:\n")
    for s in v["next_steps"]:
        w(f"  - {s}\n")
    w("\n")


VANTAGES = ["access", "span", "trunk"]


def _run_preflight(args) -> int:
    from .capture import CaptureToolMissing
    from .preflight import adapter_label, blocking, discover_adapters, run_preflight, suggest

    try:
        adapters = discover_adapters()
    except (CaptureToolMissing, RuntimeError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    pick, reasons = suggest(adapters)
    if args.interface:
        wanted = args.interface.lower()
        pick = next((a for a in adapters if wanted in (a["name"].lower(), a["title"].lower())), None)
    print("Adapter: " + (adapter_label(pick) if pick else "none"))
    if not args.interface:
        for x in reasons:
            print(f"  {x}")
    checks = run_preflight(pick, os.path.join(os.getcwd(), "runs"))
    for c in checks:
        print(f"[{c['status'].upper():7}] {c['title']}: {c['detail']}")
    return 1 if blocking(checks) else 0


def _safe_stdio() -> None:
    """Never crash on a non-UTF-8 console or redirect (e.g. cp932/cp950 on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _safe_stdio()
    p = argparse.ArgumentParser(prog="l2loopcheck", description="Layer-2 loop and broadcast-storm health check.")
    p.add_argument("--version", action="version", version=f"l2-loopcheck {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("analyze", help="analyse a pcap/pcapng file")
    pa.add_argument("file")
    pa.add_argument("--json", help="write full results as JSON")
    pa.add_argument("--html", help="write the HTML report")
    pa.add_argument("--quiet", action="store_true", help="no terminal summary")
    pa.add_argument("--vantage", choices=VANTAGES, help="where the capture was taken (default: inferred from the traffic)")

    pl = sub.add_parser("live", help="capture and analyse live (uses dumpcap or tcpdump)")
    pl.add_argument("-i", "--interface", required=True)
    pl.add_argument("--duration", type=_duration, help="stop after e.g. 90s, 10m, 1h (default: until Ctrl-C)")
    pl.add_argument("--backend", choices=["auto", "dumpcap", "tcpdump"], default="auto")
    pl.add_argument("--out", default=None, help="run folder (default: ./runs/<timestamp>)")
    pl.add_argument("--max-total-mb", type=int, default=2048, help="ring buffer size for saved captures")
    pl.add_argument("--vantage", choices=VANTAGES, help="where this port sits (default: inferred from the traffic)")
    pl.add_argument("--active", action="store_true", help="enable the loop probe (sends at most 3 test frames)")
    pl.add_argument("--yes", action="store_true", help="skip the probe confirmation prompt")

    sub.add_parser("interfaces", help="list capture interfaces")

    pf = sub.add_parser("preflight", help="check this computer and an adapter before capturing")
    pf.add_argument("-i", "--interface", help="adapter (default: the suggested one)")

    pr = sub.add_parser("report", help="render a saved result.json again")
    pr.add_argument("result")
    pr.add_argument("-o", "--out", required=True, help="HTML file to write")
    pr.add_argument("--redact", action="store_true", help="hide addresses, names and site details for sharing")

    pd = sub.add_parser("demo", help="write a synthetic capture for a scenario")
    pd.add_argument("scenario", nargs="?", default="loop")
    pd.add_argument("-o", "--out", default=None)

    sub.add_parser("gui", help="start the graphical interface")

    args = p.parse_args(argv)

    if args.cmd == "analyze":
        try:
            r = analyze_file(args.file, args.vantage)
        except (OSError, CaptureFormatError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        write_outputs(r, args.json, args.html)
        if not args.quiet:
            print_summary(r)
        return 0

    if args.cmd == "demo":
        from .synth import SCENARIOS, write_pcap

        if args.scenario not in SCENARIOS:
            print("scenarios: " + ", ".join(SCENARIOS), file=sys.stderr)
            return 2
        out = args.out or f"demo-{args.scenario}.pcap"
        write_pcap(out, SCENARIOS[args.scenario]())
        print(out)
        return 0

    if args.cmd == "interfaces":
        from .capture import list_interfaces

        try:
            for name, desc in list_interfaces():
                print(f"{name}\t{desc}")
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        return 0

    if args.cmd == "preflight":
        return _run_preflight(args)

    if args.cmd == "report":
        with open(args.result, encoding="utf-8") as f:
            r = json.load(f)
        if args.redact:
            from .report.redact import redact

            r = redact(r)
        write_outputs(r, None, args.out)
        print(args.out)
        return 0

    if args.cmd == "live":
        from .live_cli import run_live

        return run_live(args)

    if args.cmd == "gui":
        try:
            from .gui.app import run_gui
        except ImportError as e:
            print(f"The GUI needs PySide6: pip install 'l2-loopcheck[gui]' ({e})", file=sys.stderr)
            return 2
        return run_gui()
    return 1
