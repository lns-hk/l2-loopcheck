"""Terminal live view: big repeat counter, marks typed as lines, probe on demand."""

from __future__ import annotations

import os
import sys
import threading
import time

from .capture import CaptureToolMissing
from .live import LiveSession

HELP = "Type a note + Enter to add a mark (e.g. 'unplugged SW-2F uplink'), 'p' + Enter to probe, 'q' + Enter to stop."


def confirm_probe(interface: str) -> bool:
    print(f"\nThe probe sends at most 3 broadcast test frames (1 per second) from {interface},\n"
          "using this computer's own MAC address, and stops as soon as one comes back.")
    return input("Send the probe now? [y/N] ").strip().lower() in ("y", "yes")


def _resolve_windows_interface(args) -> None:
    """Accept '-i Ethernet' or '-i 3' on Windows instead of the long NPF device name."""
    if os.name != "nt" or args.interface.startswith("\\"):
        return
    from .capture import list_interfaces, resolve_interface

    try:
        args.interface = resolve_interface(args.interface, list_interfaces(args.backend))
    except (RuntimeError, OSError, CaptureToolMissing):
        pass  # LiveSession reports a missing tool; dumpcap reports an unknown interface


def run_live(args) -> int:
    _resolve_windows_interface(args)
    try:
        s = LiveSession(args.interface, args.backend, args.out, args.max_total_mb, vantage=args.vantage)
    except CaptureToolMissing as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"Capturing on {args.interface} with {s.cap.backend}. Run folder: {s.run_dir}")
    print(HELP)
    s.start()
    stop = threading.Event()

    def ticker():
        while not stop.is_set() and not s.ended.is_set():
            snap = s.snapshot()
            line = (f"\r[{snap['elapsed']:6.0f}s] REPEATS/s {snap['copies']:6d} | flooded/s {snap['flooded']:6d} | "
                    f"total/s {snap['total']:6d} | TC {snap['tc_total']:3d} | saved {snap['saved_mb']:.0f} MB ")
            sys.stdout.write(line)
            sys.stdout.flush()
            if args.duration and snap["elapsed"] >= args.duration:
                stop.set()
            time.sleep(1.0)

    threading.Thread(target=ticker, daemon=True).start()
    probe_used = False
    try:
        if args.active:
            time.sleep(3)
            if args.yes or confirm_probe(args.interface):
                s.run_probe()
                probe_used = True
        while not stop.is_set() and not s.ended.is_set():
            if args.duration:
                stop.wait(0.5)
                continue
            line = sys.stdin.readline()
            if not line:
                break
            cmd = line.strip()
            if cmd.lower() in ("q", "quit", "stop"):
                break
            if cmd.lower() == "p":
                if probe_used and not confirm_probe(args.interface):
                    continue
                if not probe_used and not (args.yes or confirm_probe(args.interface)):
                    continue
                s.run_probe()
                probe_used = True
                continue
            if cmd:
                m = s.add_mark(cmd)
                print(f"\nMark added at {time.strftime('%H:%M:%S', time.localtime(m['ts']))}: {m['label']}")
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    print("\nStopping capture and writing the report...")
    r = s.stop()
    if s.error:
        print(f"Capture error: {s.error}", file=sys.stderr)
    from .cli import print_summary

    print_summary(r)
    print(f"Report: {os.path.join(s.run_dir, 'report.html')}")
    return 0 if not s.error else 1
