# l2-loopcheck: notes for contributors and coding agents

**Goal:** an open-source Layer-2 loop, broadcast-storm and passive security health check. An engineer plugs a laptop
into an access or SPAN port on a network with intermittent outages, captures traffic, and gets evidence and a report.

**Working mode:** discuss scope and design before large changes, and build in small steps that can be reviewed.

## Rules
- Never name any employer, client, building or customer. Use documentation/private ranges and locally administered
  MACs in samples.
- The tool is passive by default. The loop probe is the only thing it transmits, it is opt-in, and its limits in
  `l2loopcheck/probe/__init__.py` are fixed. Never send a probe on a network without the owner's explicit permission.
- Never store or report credentials, community strings or payloads.
- Engine and CLI stay stdlib-only at runtime (Python 3.10+). The GUI uses PySide6.
- Per-frame code must stay linear: a real loop delivers hundreds of thousands of frames.
