# Installing on Windows

Windows 10 or 11, 64-bit.

## 1. Install Wireshark (with Npcap)

l2-loopcheck captures with Wireshark's `dumpcap` and the Npcap driver. They are
not bundled.

1. Download Wireshark from https://www.wireshark.org/download.html
   ("Windows x64 Installer") and run it.
2. On the **Packet Capture** page keep **Install Npcap** ticked. In the Npcap
   installer:
   * leave **Restrict Npcap driver's access to Administrators only**
     *unticked*, so you can capture without running as administrator;
   * the other options can stay at their defaults.
3. Finish the installation. No restart is usually needed.

l2-loopcheck finds `dumpcap.exe` in `C:\Program Files\Wireshark` by itself.

## 2. Install l2-loopcheck

1. Download `l2-loopcheck-windows.zip` from the GitHub release.
2. Right-click the zip → **Extract All...** and pick a folder you can write to,
   for example `Documents\l2-loopcheck-app` or `C:\Tools`. The program does not
   need an installer or administrator rights.
3. Open the extracted `l2-loopcheck` folder and double-click
   **l2loopcheck-gui.exe**. You can pin it to Start or the taskbar.

### "Windows protected your PC" (SmartScreen)

The program is not code-signed yet, so the first start shows a blue
**Windows protected your PC** box:

1. Click **More info**.
2. Check that the app is `l2loopcheck-gui.exe`, then click **Run anyway**.

Windows remembers this, so you only do it once per version. If **Smart App
Control** is switched on (Windows 11, *Windows Security → App & browser
control*), it blocks unsigned programs and offers no "Run anyway". In that case
run l2-loopcheck from source instead (see the end of this page).

## 3. Start a capture in the GUI

1. Plug the laptop into the switch port: an access port in the VLAN with the
   problem, or a SPAN/mirror port. Use a wired adapter; Wi-Fi only sees a
   fraction of the traffic.
2. In **Network adapter**, pick the adapter by its Windows name, for example
   `Ethernet 2  [\Device\NPF_{...}]`. USB Ethernet adapters usually appear as
   `Ethernet 2`, `Ethernet 3` and so on. Ignore VPN, Hyper-V (`vEthernet`) and
   loopback adapters. Press **Refresh** after plugging in a USB adapter.
3. Press **Start**.
4. Watch **REPEATED FRAMES PER SECOND**. Anything above 0 that does not go
   away means frames are circulating.
5. To find the loop, unplug one suspect cable or uplink at a time. After each
   change, type what you did in the mark box (e.g. `unplugged 2/F uplink`)
   and press Enter. When the number drops to 0, the last mark tells you which
   cable closed the loop.
6. Optional: **Send loop probe...**. It sends at most 3 broadcast test frames
   and stops as soon as one comes back. Use it only with the site owner's
   permission. If Npcap was installed in administrator-only mode, start
   l2-loopcheck with **Run as administrator** to use the probe.
7. Press **Stop**, then **Open report** (opens in your browser) or **Open
   folder**. Use **Report details...** once to put your company, logo and case
   reference on reports.

Runs are saved in `Documents\l2-loopcheck\<date-time>\`: the capture files,
`marks.json`, `result.json` and `report.html`. The saved capture is limited to
2 GB. Files around your marks are always kept. Open the `.pcap` files in
Wireshark to check the frame numbers quoted in the report.

To analyse an existing capture, use **Open capture file...**.

## Command line

`l2loopcheck.exe` in the same folder is the command-line version. Open a
terminal in the folder (in Explorer: right-click → **Open in Terminal**):

```powershell
.\l2loopcheck.exe interfaces                       # adapters with their Windows names
.\l2loopcheck.exe live -i "Ethernet 2" --duration 10m
.\l2loopcheck.exe analyze capture.pcapng --html report.html
```

`-i` accepts the Windows name (`"Ethernet 2"`), the number from `interfaces`
or the full `\Device\NPF_{...}` name. Type a note and press Enter to add a mark
while capturing. Type `q` and press Enter (or press Ctrl+C) to stop.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| "Wireshark needed" / "No capture tool found" | Install Wireshark as in step 1, then press **Refresh**. |
| The adapter list is empty | Npcap is missing or not running. Re-run the Wireshark installer with **Install Npcap** ticked, or check `sc query npcap` in a terminal. |
| "Access is denied" when starting or probing | Npcap is in administrator-only mode: run l2-loopcheck as administrator, or reinstall Npcap without that option. |
| The USB adapter is missing | Plug it in, wait until Windows shows it in *Settings → Network*, then press **Refresh**. |
| Antivirus quarantines the .exe | Unsigned PyInstaller programs sometimes trigger false positives. Restore the file and add an exclusion for the folder, or run from source. |

## Running from source

With Python 3.10 or newer from python.org:

```powershell
py -m pip install "l2-loopcheck[gui] @ git+https://github.com/lns-hk/l2-loopcheck"
l2loopcheck gui
```

To build the zip yourself: `powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1`
(in a virtual environment with `pip install ".[gui,build]"`). The result is
`dist\l2-loopcheck-windows.zip`.
