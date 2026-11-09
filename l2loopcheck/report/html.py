"""Self-contained HTML report (no external assets; prints cleanly to PDF).

Layout: page 1 is for a non-technical reader (verdict, impact, what to do);
the following sections are evidence for IT, with frame numbers that can be
checked in Wireshark. Observed facts and hypotheses are visually distinct.
"""

from __future__ import annotations

import base64
import html
import time
from typing import Optional

SEV_LABEL = {"critical": "Critical", "high": "High", "warning": "Medium", "low": "Low", "info": "Info"}
POSTURE_CLASS = {"Action needed": "bad", "Review": "warn", "No exposure seen": "good", "Not assessed": "neutral"}
POSTURE_TEXT = {
    "Action needed": "The capture shows weaknesses or suspicious activity that should be dealt with now.",
    "Review": "The capture shows weaknesses worth reviewing.",
    "No exposure seen": "Nothing of concern was seen. This covers only what could be observed from this capture point; "
                        "see the list of checks that were limited.",
    "Not assessed": "No frames were captured, so security could not be assessed.",
}
COVERAGE_LABEL = {"performed": "Performed", "limited": "Limited", "not_performed": "Not performed"}
VANTAGE_LABEL = {"access": "Access port", "span": "SPAN / mirror port", "trunk": "Trunk port"}
VERDICT_CLASS = {
    "Loop likely": "bad", "STP unstable": "warn", "Storm without clear loop": "warn",
    "Inconclusive": "neutral", "Healthy": "good",
}
SUMMARY_TEXT = {
    "Loop likely": "The capture shows strong signs of a Layer-2 loop: network frames are circulating "
                   "endlessly between switches. A loop can take the whole network down intermittently and "
                   "will keep recurring until the looped cable or device is found and removed.",
    "STP unstable": "Spanning tree, the protocol that prevents loops, is unstable. Each change briefly disrupts "
                    "traffic and can cause intermittent outages.",
    "Storm without clear loop": "The network carries an unusually high volume of broadcast/multicast traffic, "
                                "but there is no clear sign of a loop. The likely source is one or more "
                                "devices sending too much.",
    "Inconclusive": "This capture is not sufficient to reach a conclusion. The reasons and the next capture to "
                    "take are listed below.",
    "Healthy": "No loop, storm or spanning-tree instability was found during this capture.",
}


def e(x) -> str:
    return html.escape("" if x is None else str(x))


def fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _chart(series: list[dict], marks: list[dict], start: Optional[float]) -> str:
    """Inline SVG timeline: flooded frames/s and repeat copies/s, with marks."""
    if not series:
        return "<p class='muted'>No data.</p>"
    W, H, L, R, T, B = 900, 260, 56, 12, 14, 34
    n = len(series)
    ymax = max(max(s["flooded"] for s in series), max(s["copies"] for s in series), 10)
    ymax = _nice(ymax)
    xs = lambda i: L + (W - L - R) * (i / max(1, n - 1))  # noqa: E731
    ys = lambda v: T + (H - T - B) * (1 - v / ymax)  # noqa: E731

    def path(key):
        pts = " ".join(f"{xs(i):.1f},{ys(s[key]):.1f}" for i, s in enumerate(series))
        return pts

    grid = []
    for k in range(5):
        v = ymax * k / 4
        y = ys(v)
        grid.append(f"<line x1='{L}' x2='{W - R}' y1='{y:.1f}' y2='{y:.1f}' class='grid'/>"
                    f"<text x='{L - 6}' y='{y + 4:.1f}' class='ax' text-anchor='end'>{int(v):,}</text>")
    t0 = series[0]["t"]
    ticks = []
    step = max(1, n // 8)
    for i in range(0, n, step):
        x = xs(i)
        ticks.append(f"<text x='{x:.1f}' y='{H - 12}' class='ax' text-anchor='middle'>"
                     f"{time.strftime('%H:%M:%S', time.localtime(series[i]['t']))}</text>")
    mk = []
    for j, m in enumerate(marks):
        i = (m["ts"] - t0)
        if 0 <= i <= n:
            x = xs(min(n - 1, i))
            mk.append(f"<line x1='{x:.1f}' x2='{x:.1f}' y1='{T}' y2='{H - B}' class='mark'/>"
                      f"<text x='{x + 3:.1f}' y='{T + 10 + 12 * (j % 3)}' class='marklbl'>{j + 1}</text>")
    return f"""<svg viewBox='0 0 {W} {H}' class='chart' role='img' aria-label='Timeline of flooded and repeated frames per second'>
{''.join(grid)}{''.join(ticks)}
<polyline points='{path("flooded")}' class='l-flood'/>
<polyline points='{path("copies")}' class='l-copy'/>
{''.join(mk)}
</svg>
<div class='legend'><span class='k k-flood'></span>Broadcast + multicast frames/s
<span class='k k-copy'></span>Repeated copies/s (loop indicator)<span class='k k-mark'></span>Engineer's marks</div>"""


def _nice(v: float) -> float:
    import math

    p = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * p:
            return m * p
    return 10 * p


def _table(rows: list[list], head: list[str], cls: str = "") -> str:
    if not rows:
        return "<p class='muted'>None.</p>"
    th = "".join(f"<th>{e(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table class='{cls}'><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def render_html(r: dict, branding: dict | None = None) -> str:
    b = branding or {}
    v, cap, tr, stp, dup = r["verdict"], r["capture"], r["traffic"], r["stp"], r["duplicates"]
    vclass = VERDICT_CLASS.get(v["label"], "neutral")
    logo = ""
    if b.get("logo_path"):
        try:
            with open(b["logo_path"], "rb") as f:
                data = base64.b64encode(f.read()).decode()
            mime = "image/png" if b["logo_path"].lower().endswith(".png") else "image/jpeg"
            logo = f"<img class='logo' src='data:{mime};base64,{data}' alt=''>"
        except OSError:
            logo = ""
    org = e(b.get("company") or "")
    title = "Network Health and Security Check"
    eng = r.get("engagement") or {}
    b = {**{k: eng.get(k) for k in ("company", "site", "case_ref", "engineer", "logo_path")}, **{k: x for k, x in b.items() if x}}
    org = e(b.get("company") or eng.get("org") or "")
    client = eng.get("client")
    meta = [
        ("Site / location", b.get("site") or "-"), ("Case reference", b.get("case_ref") or "-"),
        ("Engineer", b.get("engineer") or "-"),
        ("Captured", f"{fmt_ts(cap['start'])} - {fmt_ts(cap['end'])} ({cap['duration_s']:.0f} s)"),
        ("Capture point", cap.get("interface") or cap.get("source") or "-"),
    ]
    if client:
        meta.insert(0, ("Client", client))
    if cap.get("vantage"):
        meta.append(("Observation point", VANTAGE_LABEL.get(cap["vantage"], cap["vantage"]) +
                     ("" if cap.get("vantage_declared") else " (inferred from the traffic)")))
    neigh = r.get("neighbours") or []
    if neigh:
        n0 = neigh[0]
        meta.append(("Connected to", f"{n0['system_name'] or n0['chassis']} port {n0['port']} ({n0['protocol']})"))
    meta_html = "".join(f"<div><dt>{e(k)}</dt><dd>{e(val)}</dd></div>" for k, val in meta)
    top_findings = [f for f in v["findings"] if f["severity"] in ("critical", "high")][:6]
    key_points = "".join(f"<li>{e(f['title'])}</li>" for f in top_findings) or "<li>No significant issues.</li>"
    steps = "".join(f"<li>{e(s)}</li>" for s in v["next_steps"])

    # Findings
    fhtml = []
    shtml = []
    for i, f in enumerate(v["findings"], 1):
        frames = ", ".join(str(x) for x in f["frames"][:10])
        (shtml if f.get("category") == "security" else fhtml).append(f"""<section class='finding sev-{e(f['severity'])}'>
<h3><span class='sev'>{e(SEV_LABEL.get(f['severity'], f['severity']))}</span> {i}. {e(f['title'])}</h3>
<p class='obs'><b>Observed</b> {e(f['observed'])}</p>
{f"<p class='hyp'><b>Hypothesis</b> {e(f['hypothesis'])}</p>" if f.get('hypothesis') else ''}
{f"<p class='rec'><b>Recommendation</b> {e(f['recommendation'])}</p>" if f.get('recommendation') else ''}
{f"<p class='frames'>Frames (Wireshark No.): {e(frames)}</p>" if frames else ''}
</section>""")

    sec = v.get("security") or {}
    counts = sec.get("counts") or {}
    tiles = "".join(f"<div class='tile sev-{k}'><b>{counts.get(k, 0)}</b><span>{SEV_LABEL[k]}</span></div>"
                    for k in ("critical", "high", "warning", "low", "info"))
    posture = sec.get("posture", "Not assessed")
    coverage_rows = [[c["check"], COVERAGE_LABEL.get(c["status"], c["status"]), c["reason"]] for c in r.get("coverage", [])]
    s = r.get("security") or {}
    hosts = [[h["mac"] + (" (random/local)" if h["local_admin"] else ""), ", ".join(h["ips"][:3]) or "-",
              ", ".join(h["names"][:2]) or "-", ", ".join(h["vlans"]), ", ".join(h["roles"]) or "-",
              ", ".join(h["protocols"]), f"{h['frames']:,}"] for h in s.get("hosts", [])[:200]]
    services = [[x["service"], x["server"], x.get("port") or "-", x["vlan"], len(x["clients"]), x["first_frame"]]
                for x in s.get("services", [])[:100]]
    scope_rows = [["Site", eng.get("site") or "-"], ["Client", client or "-"],
                  ["Engineer", eng.get("engineer") or "-"], ["Organisation", eng.get("org") or "-"],
                  ["Authorisation confirmed", (f"Yes, by {eng.get('authorised_by') or 'the engineer'}" if eng.get("authorised") else "Not recorded")],
                  ["Traffic sent by this tool", "Loop probe only (see below)" if r.get("probes") else "None: passive capture"]]
    pre_rows = [[c["title"], c["status"].upper(), c["detail"]] for c in eng.get("preflight", [])]
    redacted_banner = ("<p class='redacted'>Redacted for sharing: addresses, device names, site details and notes have been "
                       "replaced.</p>" if r.get("redacted") else "")
    marks = r.get("marks") or []
    marks_rows = [[i + 1, time.strftime("%H:%M:%S", time.localtime(m["ts"])), m["label"]] for i, m in enumerate(marks)]

    talkers = [[t["mac"], ", ".join(t["ips"]) or "-", f"{t['share']:.1%}", f"{t['pps']:.0f}", f"{t['copy_share']:.0%}",
                ", ".join(p for p, _ in t["top_protocols"]), ", ".join(t["names"][:2]) or "-", t["first_frame"]]
               for t in tr["top_talkers"][:10]]
    protos = [[p["proto"], p["frames"], f"{p['share']:.1%}", f"{p['pps']:.1f}"] for p in tr["by_protocol"][:12]]
    rep = [[x["proto"], x["src"], x.get("name") or "-", x["copies"], x["median_gap_us"],
            ", ".join(map(str, x["vlans"])) or "-", ", ".join(map(str, x["example_frames"]))]
           for x in dup["examples"]]
    cp = dup.get("common_period")
    cp_html = ""
    if cp:
        cp_html = (f"<p>Most common repeat period: <b>{cp['period_us']:.0f} µs</b>, shared by "
                   f"<b>{cp['groups']}</b> frames from <b>{cp['distinct_sources']}</b> distinct sources "
                   f"({e(', '.join(cp['protocols'][:6]))}).</p>")
    roots = []
    for scope, lst in stp["roots"].items():
        for x in lst:
            roots.append([scope, x["root_id"], x["count"], ", ".join(x["announced_by"][:3]), x["first_frame"]])
    senders = [[s["mac"], s["bridge_id"] or "-", ", ".join(s["kinds"]), s["count"], s["root_cost"]]
               for s in stp["senders"][:10]]
    tcs = [[time.strftime("%H:%M:%S", time.localtime(t["ts"])), t["kind"], t["sender"], t["frame"]]
           for t in stp["tc_examples"][:15]]
    nrows = [[n["protocol"], n["system_name"] or n["chassis"], n["port"], n["mgmt_ip"] or "-",
              n.get("platform") or "-", n["native_vlan"] or "-", n["first_frame"]] for n in neigh]
    dips = [[d["ip"], ", ".join(m["mac"] for m in d["macs"]), ", ".join(str(m["first_frame"]) for m in d["macs"])]
            for d in r["duplicate_ips"]]
    probes = [[p["nonce"], p["sent"], ", ".join(fmt_ts(t)[11:] for t in p["sent_at"]),
               "Yes" if p["loop_confirmed"] else ("Ambiguous" if p["ambiguous"] else "No")] for p in r.get("probes", [])]
    drops = cap.get("drops")
    integrity = [
        ["Frames analysed", f"{cap['packets']:,}"], ["Duration", f"{cap['duration_s']:.1f} s"],
        ["Dropped by capture", "unknown" if drops is None else f"{drops:,}"],
        ["Frames truncated by snaplen", cap["snaplen_truncated"]], ["Undecoded frames", cap["undecoded"]],
        ["Capture tool", cap.get("tool") or "-"], ["Source", cap.get("source") or "-"],
    ]
    if cap.get("saved_files"):
        integrity.append(["Saved capture files", ", ".join(cap["saved_files"][:6]) +
                          (" ..." if len(cap["saved_files"]) > 6 else "")])
    limitations = "".join(f"<li>{e(x)}</li>" for x in v["limitations"])
    footer = f"Generated by l2-loopcheck {e(r['tool']['version'])} on {time.strftime('%Y-%m-%d %H:%M')}"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} - {e(v['label'])}</title>
<style>
:root{{--ink:#1d232b;--muted:#5d6875;--line:#d9dee4;--bg:#fff;--soft:#f4f6f8;
--bad:#b42318;--bad-bg:#fdecea;--warn:#a15c00;--warn-bg:#fff4e0;--good:#1e7a46;--good-bg:#e7f6ec;--neutral:#46505c;--neutral-bg:#eef1f4;
--flood:#3367d6;--copy:#c4320a}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}}
main{{max-width:960px;margin:0 auto;padding:32px 28px}}
header.top{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;border-bottom:2px solid var(--ink);padding-bottom:12px}}
h1{{font-size:24px;margin:0}}h2{{font-size:18px;margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:4px}}
h3{{font-size:15px;margin:0 0 6px}}.org{{color:var(--muted);font-size:13px}}.logo{{max-height:48px;max-width:180px}}
dl.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 20px;margin:16px 0}}dl.meta dt{{color:var(--muted);font-size:12px}}dl.meta dd{{margin:0;font-weight:600}}
.verdict{{border-radius:8px;padding:18px 20px;margin:18px 0;border-left:8px solid}}
.verdict.bad{{background:var(--bad-bg);border-color:var(--bad)}}.verdict.warn{{background:var(--warn-bg);border-color:var(--warn)}}
.verdict.good{{background:var(--good-bg);border-color:var(--good)}}.verdict.neutral{{background:var(--neutral-bg);border-color:var(--neutral)}}
.verdict .label{{font-size:26px;font-weight:700}}.verdict .conf{{color:var(--muted);margin-left:8px}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
.finding{{border:1px solid var(--line);border-left:5px solid var(--neutral);border-radius:6px;padding:12px 14px;margin:10px 0;break-inside:avoid}}
.sev-critical{{border-left-color:var(--bad)}}.sev-high{{border-left-color:#d4541b}}.sev-warning{{border-left-color:var(--warn)}}.sev-low{{border-left-color:#2f6fa8}}.sev-info{{border-left-color:#8a94a0}}
.tiles{{display:flex;gap:10px;margin:12px 0}}.tile{{flex:1;border:1px solid var(--line);border-top:5px solid var(--neutral);border-radius:6px;padding:10px;text-align:center}}.tile b{{display:block;font-size:26px}}.tile span{{color:var(--muted);font-size:12px}}
.tile.sev-critical{{border-top-color:var(--bad)}}.tile.sev-high{{border-top-color:#d4541b}}.tile.sev-warning{{border-top-color:#e0a100}}.tile.sev-low{{border-top-color:#2f6fa8}}.tile.sev-info{{border-top-color:#8a94a0}}
.redacted{{background:var(--warn-bg);border:1px solid #e9b44c;border-radius:6px;padding:8px 12px}}
.sev{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;background:var(--soft);padding:2px 6px;border-radius:4px;margin-right:4px}}
.finding p{{margin:4px 0}}.finding b{{display:inline-block;min-width:110px;color:var(--muted);font-weight:600}}
.hyp{{font-style:italic}}.frames{{color:var(--muted);font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0}}th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{background:var(--soft);font-weight:600}}td{{font-variant-numeric:tabular-nums}}
.muted{{color:var(--muted)}}.chart{{width:100%;height:auto;border:1px solid var(--line);border-radius:6px}}
.grid{{stroke:#e6e9ed}}.ax{{font-size:10px;fill:var(--muted)}}.l-flood{{fill:none;stroke:var(--flood);stroke-width:1.5}}
.l-copy{{fill:none;stroke:var(--copy);stroke-width:1.5}}.mark{{stroke:#111;stroke-dasharray:3 3}}.marklbl{{font-size:10px;font-weight:700}}
.legend{{font-size:12px;color:var(--muted);margin:6px 0}}.k{{display:inline-block;width:14px;height:3px;margin:0 6px 3px 14px;vertical-align:middle}}
.k-flood{{background:var(--flood)}}.k-copy{{background:var(--copy)}}.k-mark{{border-top:2px dashed #111;height:0}}
footer{{margin-top:36px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding-top:8px}}
.page-break{{break-before:page}}
@media print{{main{{padding:0}}@page{{size:A4;margin:14mm}}body{{font-size:12px}}.finding,table,svg{{break-inside:avoid}}}}
@media (max-width:700px){{dl.meta,.cols{{grid-template-columns:1fr}}}}
</style></head><body><main>
<header class="top"><div><h1>{e(title)}</h1><div class="org">{org}</div></div>{logo}</header>
{redacted_banner}<dl class="meta">{meta_html}</dl>

<section class="verdict {vclass}"><div><span class="label">{e(v['label'])}</span><span class="conf">Network health. Confidence: {e(v['confidence'])}</span></div>
<p>{e(SUMMARY_TEXT.get(v['label'], ''))}</p></section>
<section class="verdict {POSTURE_CLASS.get(posture, 'neutral')}"><div><span class="label">{e(posture)}</span><span class="conf">Security</span></div>
<p>{e(POSTURE_TEXT.get(posture, ''))}</p><div class="tiles">{tiles}</div></section>

<div class="cols"><div><h2>Key points</h2><ul>{key_points}</ul></div>
<div><h2>What to do next</h2><ol>{steps}</ol></div></div>

<h2>Timeline</h2>{_chart(r["timeline"], marks, cap["start"])}
{('<h3>Engineer marks</h3>' + _table(marks_rows, ['#', 'Time', 'Note'])) if marks else ''}

<div class="page-break"></div>
<h2>Security findings</h2>
<p class="muted">Credentials, community strings and payloads are never stored or shown. Severity is a category, not a score.</p>
{''.join(shtml) or "<p class='muted'>No security findings from this capture point.</p>"}

<h2>What this capture could not check</h2>
<p class="muted">A check that was limited or skipped says nothing about the network. Do not read its absence from the findings as a pass.</p>
{_table(coverage_rows, ['Check', 'Status', 'Why'])}

<h2>Network findings (evidence for IT)</h2>
<p class="muted">"Observed" is what the capture shows; "Hypothesis" is an interpretation to verify on site. Frame numbers match Wireshark's "No." column in the saved capture.</p>
{''.join(fhtml) or "<p class='muted'>No findings.</p>"}

<h2>Devices seen</h2>
<p>{s.get('hosts_total', 0):,} source MAC addresses seen{' (showing the busiest 200)' if s.get('hosts_total', 0) > 200 else ''}.</p>
{_table(hosts, ['MAC', 'IP', 'Name', 'VLAN', 'Role', 'Protocols', 'Frames'])}
{('<h3>Clear-text, web and OT services seen</h3>' + _table(services, ['Service', 'Server', 'Port', 'VLAN', 'Clients seen', 'First frame'])) if services else ''}

<h2>Repeated frames</h2>
<p>{dup['copies']:,} of {dup['frames']:,} frames ({dup['copy_ratio']:.1%}) were copies of a frame seen less than 200 ms earlier.</p>
{cp_html}
{_table(rep, ['Protocol', 'Source MAC', 'Name', 'Copies', 'Median gap (µs)', 'VLANs', 'Frames'])}

<h2>Broadcast and multicast</h2>
<p>Broadcast {tr['broadcast']:,} frames, multicast {tr['multicast']:,} frames, average {tr['flooded_pps']:.0f} flooded frames/s.</p>
<div class="cols"><div><h3>By protocol</h3>{_table(protos, ['Protocol', 'Frames', 'Share', 'Per s'])}</div>
<div><h3>VLANs seen</h3>{_table([[k, n] for k, n in tr['vlans'].items()], ['VLAN', 'Frames'])}</div></div>
<h3>Top senders</h3>{_table(talkers, ['MAC', 'IP', 'Share', 'Per s', 'Repeats', 'Protocols', 'Names', 'First frame'])}

<h2>Spanning tree</h2>
<p>{stp['bpdus']:,} BPDUs ({e(', '.join(f'{k} x{n}' for k, n in stp['kinds'].items()) or 'none')}).
Topology changes: {stp['tc_events']} ({stp['tc_per_minute']}/min). Root changes: {stp['root_changes']}.</p>
<h3>Root bridges announced</h3>{_table(roots, ['Scope', 'Root ID', 'BPDUs', 'Announced by', 'First frame'])}
<h3>BPDU senders</h3>{_table(senders, ['Sender MAC', 'Bridge ID', 'Types', 'BPDUs', 'Root path cost'])}
{('<h3>Topology change events</h3>' + _table(tcs, ['Time', 'Type', 'Sender', 'Frame'])) if tcs else ''}

<h2>Neighbours (LLDP / CDP)</h2>{_table(nrows, ['Protocol', 'Device', 'Port', 'Mgmt IP', 'Platform', 'Native VLAN', 'First frame'])}
<h2>Duplicate IP addresses</h2>{_table(dips, ['IP', 'MACs', 'First frames'])}
{('<h2>Loop probe</h2>' + _table(probes, ['Nonce', 'Frames sent', 'Sent at', 'Came back'])) if probes else ''}

<h2>Scope and authorisation</h2>{_table(scope_rows, ['Item', 'Value'])}
{('<h3>Pre-flight checks</h3>' + _table(pre_rows, ['Check', 'Result', 'Detail'])) if pre_rows else ''}

<h2>Capture integrity and limitations</h2>{_table(integrity, ['Item', 'Value'])}
<ul>{limitations}</ul>
<footer>{footer}</footer>
</main></body></html>"""
