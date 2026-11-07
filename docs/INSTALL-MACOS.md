# Installing on macOS

1. Install **Wireshark** from https://www.wireshark.org/download.html and, when
   asked, also install **ChmodBPF**. This lets l2-loopcheck capture without an
   administrator password. Log out and in again afterwards.
2. Download `l2-loopcheck-<version>-macos-<arch>.zip` from the GitHub release,
   unzip it and move **l2-loopcheck.app** to Applications.
3. The app is not signed yet. The first time, macOS blocks it:
   * open **System Settings → Privacy & Security**, scroll down to
     "l2-loopcheck was blocked", click **Open Anyway**, then **Open**.
   * (or right-click the app → **Open** → **Open**.)

## Using it

1. Plug the laptop into the switch port (an access port, or a SPAN port).
2. Open l2-loopcheck, pick the adapter (e.g. "USB 10/100/1000 LAN [en7]") and
   press **Start**.
3. Watch **REPEATED FRAMES PER SECOND**. Anything above 0 that does not go
   away means frames are circulating.
4. To find the loop, unplug one suspect cable or uplink at a time. After each
   change, type what you did in the mark box and press Enter. When the number
   drops to 0, the last mark tells you which cable closed the loop.
5. Optional: **Send loop probe...** (with the site owner's permission).
6. Press **Stop**, then **Open report**. Fill in **Report details...** once to
   put your company, logo and case reference on reports.

Runs are saved in `~/Documents/l2-loopcheck/<date-time>/` (capture files,
marks, `result.json`, `report.html`). The capture is limited to 2 GB; files
around your marks are always kept.

Command line: `/Applications/l2-loopcheck.app/Contents/MacOS/cli/l2loopcheck --help`.
