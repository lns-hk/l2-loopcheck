"""Turn detector output into findings and one overall verdict.

Every finding separates what was *observed* (facts from the capture, with
frame numbers) from any *hypothesis* (an interpretation the engineer should
verify). Thresholds are initial values, documented in docs/DETECTION.md, and
are to be calibrated against lab captures.
"""

from __future__ import annotations

from .detect.security import security_findings

LOOP_LIKELY = "Loop likely"
STP_UNSTABLE = "STP unstable"
STORM = "Storm without clear loop"
HEALTHY = "Healthy"
INCONCLUSIVE = "Inconclusive"

# Initial thresholds (see docs/DETECTION.md).
MIN_DURATION_S = 10.0
MIN_PACKETS = 200
DROP_RATIO_WARN = 0.05
DROP_RATIO_INCONCLUSIVE = 0.20
LOOP_MIN_COPY_RATIO = 0.05
STORM_FLOODED_PPS = 1000.0
TALKER_SHARE = 0.5
TALKER_PPS = 200.0
TC_PER_MINUTE = 2.0
TC_MIN_EVENTS = 3


def _f(severity, code, title, observed, hypothesis=None, recommendation=None, frames=None):
    return {
        "severity": severity, "code": code, "title": title, "observed": observed,
        "hypothesis": hypothesis, "recommendation": recommendation, "frames": frames or [],
        "category": "network", "confidence": "inferred" if hypothesis else "observed",
    }


def judge(r: dict) -> dict:
    cap, dup, tr, stp = r["capture"], r["duplicates"], r["traffic"], r["stp"]
    findings = []
    integrity_problems = []
    if not cap["packets"]:
        integrity_problems.append("no frames were captured")
        findings.append(_f(
            "high", "no-frames", "Nothing was captured",
            "The capture contains no frames, so nothing about this network can be concluded.",
            recommendation="Check the cable and the selected adapter, then capture again."))

    # ------------------------------------------------------ capture integrity
    dur, pk = cap["duration_s"], cap["packets"]
    drops = cap.get("drops")
    drop_ratio = (drops / (drops + pk)) if drops and pk else 0.0
    if dur < MIN_DURATION_S or pk < MIN_PACKETS:
        integrity_problems.append(f"capture is short ({dur:.1f} s, {pk} frames)")
    if drop_ratio >= DROP_RATIO_WARN:
        findings.append(_f(
            "warning", "capture-drops", "Capture lost frames",
            f"{drops} frames were dropped by the capture ({drop_ratio:.1%}). Rates in this report are lower bounds.",
            recommendation="Capture on a faster interface or with a larger buffer, or shorten the capture."))
        if drop_ratio >= DROP_RATIO_INCONCLUSIVE:
            integrity_problems.append(f"{drop_ratio:.0%} of frames were dropped")
    if cap.get("file_truncated"):
        findings.append(_f("info", "file-truncated", "Capture file ends mid-frame",
                           "The last record is incomplete; it was ignored."))
    if 1 in cap.get("linktypes", []) and not tr["vlans"]:
        pass  # untagged access port: normal
    if dup["span_artefact_suspected"]:
        integrity_problems.append("ordinary unicast traffic appears twice (SPAN mirroring both directions?)")
        findings.append(_f(
            "warning", "span-duplication", "Frames duplicated by the capture setup",
            f"{dup['unicast_l4_copy_ratio']:.0%} of unicast TCP/UDP frames appear twice within 100 µs. "
            "A loop only repeats flooded frames, so this pattern points to the mirror session.",
            hypothesis="The SPAN/mirror session copies both ingress and egress of the same traffic.",
            recommendation="Mirror one direction only, or capture on an access port, and re-run."))

    # ----------------------------------------------------------------- loop
    loop_level = None
    cp = dup.get("common_period")
    probes = r.get("probes", [])
    confirmed_probe = next((p for p in probes if p["loop_confirmed"]), None)
    if confirmed_probe:
        loop_level = "high"
        findings.append(_f(
            "critical", "probe-returned", "Test frame came back: loop confirmed on this port",
            f"Probe {confirmed_probe['nonce']} was sent {confirmed_probe['sent']} time(s); copies seen per frame: "
            f"{confirmed_probe['copies_by_seq']}.",
            recommendation="A frame sent from this port returned to it, so this port's broadcast domain contains a loop.",
            frames=[confirmed_probe["first_return_frame"]] if confirmed_probe["first_return_frame"] else []))
    if cp and cp["loop_fingerprint"] and dup["copy_ratio"] >= LOOP_MIN_COPY_RATIO:
        loop_level = loop_level or "high"
        findings.append(_f(
            "critical", "common-period", "Frames from many sources repeat with the same period",
            f"{cp['groups']} distinct frames from {cp['distinct_sources']} different source MACs each reappeared "
            f"every ~{cp['period_us']:.0f} µs ({', '.join(cp['protocols'][:5])}). "
            f"{dup['copies']} of {dup['frames']} frames ({dup['copy_ratio']:.1%}) were repeat copies.",
            hypothesis=f"These frames are circulating in a Layer-2 loop; ~{cp['period_us']:.0f} µs is the time for one trip round it.",
            recommendation="Find the loop: in live mode, disconnect uplinks or suspect cables one at a time and add a mark; "
                           "the repeat counter drops to zero when the loop is broken.",
            frames=cp["example_frames"]))
    elif dup["groups_repeated_3plus"] >= 20 and dup["copy_ratio"] >= 0.2 and len(dup["top_sources"]) >= 2:
        loop_level = loop_level or "medium"
        findings.append(_f(
            "high", "replays", "Many frames repeated several times",
            f"{dup['groups_repeated_3plus']} frames were seen 3 or more times within 200 ms; "
            f"{dup['copy_ratio']:.1%} of all frames were repeat copies.",
            hypothesis="A loop is likely, but repeats do not share one clear period.",
            recommendation="Run a probe or capture longer to confirm.",
            frames=[e["first_frame"] for e in dup["examples"][:5]]))
    elif (real_repeats := [x for x in dup["examples"] if len(x["vlans"]) < 2]) and not dup["span_artefact_suspected"]:
        ex = real_repeats[0]
        findings.append(_f(
            "info", "few-replays", "A few frames were repeated",
            f"{dup['groups_repeated_3plus']} frame(s) were seen 3 or more times within 200 ms, "
            f"e.g. {ex['proto']} from {ex['src']} x{ex['copies']}.",
            hypothesis="Could be a short-lived loop, a sender retransmitting, or normal protocol behaviour.",
            frames=[e["first_frame"] for e in real_repeats[:5]]))
    negative_probes = [p for p in probes if not p["loop_confirmed"] and not p["ambiguous"] and p["sent"]]
    if negative_probes and not confirmed_probe:
        findings.append(_f(
            "info", "probe-negative", "Test frames did not come back",
            f"{negative_probes[0]['sent']} test frame(s) were sent and none returned, so this port's broadcast "
            "domain showed no loop while the probe ran."))
    if dup["cross_vlan_count"] and dup.get("cross_vlan_sources", 2) < 2:
        ex = dup["cross_vlan"][0]
        findings.append(_f(
            "info", "multi-vlan-host", "One device sends the same frame into several VLANs",
            f"{ex['proto']} from {ex['src']} appeared in VLANs {ex['vlans']}. No other device crossed VLANs.",
            hypothesis="A host with an interface in each VLAN, such as a NAS, router or hypervisor. A real bridge "
                       "between VLANs would leak frames from many devices.",
            frames=ex["example_frames"]))
    elif dup["cross_vlan_count"]:
        ex = dup["cross_vlan"][0]
        # A path between two VLANs on a trunk closes a loop through the trunk itself.
        if not negative_probes:
            loop_level = loop_level or "medium"
        findings.append(_f(
            "high", "cross-vlan", "The same frame appears in more than one VLAN",
            f"{dup['cross_vlan_count']} frame(s) were seen with different VLAN tags, e.g. {ex['proto']} from "
            f"{ex['src']} in VLANs {ex['vlans']}.",
            hypothesis="Two VLANs are bridged together, for example by an unmanaged switch or a cable between two access ports in different VLANs.",
            recommendation="Check for cables joining ports of different VLANs and for unmanaged switches.",
            frames=ex["example_frames"]))

    # ------------------------------------------------------------------ STP
    stp_unstable = False
    if not stp["seen"]:
        findings.append(_f(
            "warning", "no-bpdu", "No spanning-tree BPDUs seen",
            f"No STP/RSTP/MSTP/PVST+ BPDUs were received in {dur:.0f} s.",
            hypothesis="Spanning tree is disabled, filtered on this port, or a switch in the path drops BPDUs. "
                       "Without it, nothing blocks a redundant link.",
            recommendation="Enable RSTP/MSTP on managed switches, BPDU guard on edge ports, and loop protection "
                           "where the switch supports it."))
    else:
        if stp["tc_events"] >= TC_MIN_EVENTS and stp["tc_per_minute"] >= TC_PER_MINUTE:
            stp_unstable = True
            findings.append(_f(
                "high", "tc-storm", "Frequent topology changes",
                f"{stp['tc_events']} topology changes in {dur:.0f} s ({stp['tc_per_minute']}/min).",
                hypothesis="A port is flapping, or edge ports are not configured as edge/portfast, so every link change floods the MAC tables.",
                recommendation="Identify the bridges sending TC (listed below); configure edge ports and check flapping links.",
                frames=[e["frame"] for e in stp["tc_examples"][:5]]))
        if stp["root_changes"]:
            stp_unstable = True
            findings.append(_f(
                "high", "root-change", "Root bridge changed during the capture",
                f"The announced root bridge changed {stp['root_changes']} time(s).",
                recommendation="Set explicit bridge priorities so the intended core switch is always root."))
        if stp["split_trees"]:
            stp_unstable = True
            s = stp["split_trees"][0]
            findings.append(_f(
                "high", "split-tree", "More than one root bridge announced at the same time",
                f"In {s['scope']}, roots {', '.join(s['roots'])} were both announced over the same period.",
                hypothesis="The tree is split: a device between them drops or does not run STP, so each side elects its own root and a loop between them is not blocked.",
                recommendation="Find the device between the two STP domains (often an unmanaged switch) and remove or replace it."))
        if len(stp["mst_regions"]) > 1:
            stp_unstable = True
            findings.append(_f(
                "warning", "mst-regions", "Different MST region configurations",
                f"{len(stp['mst_regions'])} MST configurations seen: " +
                "; ".join(f"name '{x['name']}' rev {x['revision']}" for x in stp["mst_regions"]),
                hypothesis="Switches meant to be one MST region disagree on name, revision or VLAN mapping, so they act as separate regions.",
                recommendation="Align MST region name, revision and VLAN-to-instance mapping on all switches."))
        if stp["mixed_versions"]:
            findings.append(_f(
                "info", "mixed-stp", "Mixed spanning-tree versions",
                "BPDU types seen: " + ", ".join(f"{k} x{v}" for k, v in stp["kinds"].items()),
                hypothesis="Mixed STP/RSTP/MSTP interoperates but falls back to slower behaviour at boundaries."))

    # ---------------------------------------------------------------- storm
    storm = False
    top = tr["top_talkers"][0] if tr["top_talkers"] else None
    if tr["flooded_pps"] >= STORM_FLOODED_PPS:
        storm = True
        findings.append(_f(
            "high", "flood-rate", "High broadcast/multicast rate",
            f"Flooded traffic averaged {tr['flooded_pps']:.0f} frames/s. Top protocols: " +
            ", ".join(f"{p['proto']} {p['share']:.0%}" for p in tr["by_protocol"][:4]) + ".",
            recommendation="Configure storm control on access ports and find the dominant sender below."))
    if top and top["share"] >= TALKER_SHARE and top["pps"] >= TALKER_PPS:
        storm = True
        names = f" (names: {', '.join(top['names'][:3])})" if top["names"] else ""
        findings.append(_f(
            "high", "top-talker", "One device dominates flooded traffic",
            f"{top['mac']} {', '.join(top['ips'])} sent {top['share']:.0%} of all broadcast/multicast frames "
            f"({top['pps']:.0f}/s), mostly {top['top_protocols'][0][0]}{names}. "
            f"{top['copy_share']:.0%} of them were byte-identical repeats of an earlier frame.",
            hypothesis=("Frames from many sources are circulating (see the loop findings), so a loop is most likely "
                        "multiplying this device's frames rather than the device sending them all."
                        if loop_level and top["copy_share"] >= 0.5 else
                        "This device itself is sending this volume; check it (driver, firmware, misconfigured "
                        "discovery or casting software)."),
            recommendation="Locate the port this MAC is learned on and check the device.",
            frames=[top["first_frame"]]))
    sc = r["storm_control"]
    if sc["suspected"]:
        storm = True
        findings.append(_f(
            "warning", "storm-control", "Saw-tooth pattern typical of storm control",
            f"Flooded traffic collapsed from ≥500/s to near zero {sc['cliff_count']} times (peak {sc['peak_pps']}/s).",
            hypothesis="Storm control is cutting a recurring storm. It limits the damage but the source is still there.",
            recommendation="Treat storm control as a safety net; find the source with the loop findings and top talkers."))

    for d in r["duplicate_ips"]:
        findings.append(_f(
            "warning", "duplicate-ip", f"Duplicate IP address {d['ip']}",
            f"{d['ip']} is claimed by {len(d['macs'])} MACs: " + ", ".join(m["mac"] for m in d["macs"]) + ".",
            hypothesis="Two devices are configured with the same address (or a device has two interfaces bridged).",
            recommendation="Find both devices by MAC and correct the addressing.",
            frames=[m["first_frame"] for m in d["macs"]]))

    if len(tr.get("subnets_by_vlan", {}).get("untagged", [])) > 1 or any(
            len(v) > 1 for k, v in tr.get("subnets_by_vlan", {}).items() if k != "untagged"):
        multi = {k: v for k, v in tr["subnets_by_vlan"].items() if len(v) > 1}
        findings.append(_f(
            "info", "multiple-subnets", "Several IP ranges share one broadcast domain",
            "ARP senders from different ranges in the same VLAN: " + "; ".join(f"{k}: {', '.join(v)}" for k, v in multi.items()),
            hypothesis="Could be intended (secondary addressing) or two networks bridged together."))

    # -------------------------------------------------------------- verdict
    reasons = [f["title"] for f in findings if f["severity"] in ("critical", "high")]
    security_list = security_findings(r["security"], r["duplicate_ips"], r["neighbours"], stp,
                                      cap.get("vantage") or "access", cap.get("vantage_declared")) if r.get("security") else []
    if loop_level:
        label, conf = LOOP_LIKELY, loop_level
    elif stp_unstable:
        label, conf = STP_UNSTABLE, "medium"
    elif storm:
        label, conf = STORM, "medium"
    elif integrity_problems:
        label, conf = INCONCLUSIVE, "low"
        reasons = integrity_problems
    else:
        label, conf = HEALTHY, "medium" if dur >= 60 else "low"
        reasons = ["No loop, storm or STP instability found in this capture."]
    if integrity_problems and label != INCONCLUSIVE:
        conf = "medium" if conf == "high" else "low"
    next_steps = _next_steps(label, integrity_problems, stp)
    findings += security_list
    order = {"critical": 0, "high": 1, "warning": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order[f["severity"]])
    counts = {k: sum(1 for f in security_list if f["severity"] == k) for k in order}
    limited = [c for c in r.get("coverage", []) if c["status"] != "performed"]
    posture = ("Not assessed" if not cap["packets"] else
               "Action needed" if counts["critical"] or counts["high"] else
               "Review" if counts["warning"] else "No exposure seen")
    return {"label": label, "security": {"posture": posture, "counts": counts, "checks_limited": len(limited)},
             "confidence": conf, "reasons": reasons, "limitations": integrity_problems + [
        "Captured from one port: only flooded traffic and traffic addressed to this host is visible.",
    ], "next_steps": next_steps, "findings": findings}


def _next_steps(label: str, problems: list, stp: dict) -> list:
    if label == INCONCLUSIVE:
        return ["Capture for at least 10 minutes, ideally while the problem occurs.",
                "If possible, send a probe (Probe button / --active) to test this port directly."]
    if label == LOOP_LIKELY:
        return ["Use live mode to isolate the loop: disconnect one uplink or suspect cable at a time and add a mark each time.",
                "Enable loop protection / BPDU guard on access ports once the loop is removed."]
    if label == STP_UNSTABLE:
        return ["Check the bridges listed as sending topology changes and their port logs.",
                "Set root bridge priorities explicitly and configure edge ports."]
    if label == STORM:
        return ["Locate the top talker's switch port and inspect the device.",
                "Configure storm control on access ports."]
    return ["If outages are intermittent, capture again while the problem occurs."]
