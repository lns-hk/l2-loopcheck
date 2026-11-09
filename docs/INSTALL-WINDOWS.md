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

## 3. Run a check in the GUI

Choose **Run a check** on the home screen. The guide has five steps, and **Next** stays disabled until each step is
complete.

1. **Site and authorisation.** Enter the site and your name, and confirm that you are authorised to capture on this
   network. These go on the report.
2. **Network adapter.** Plug into the switch: an access port, or a SPAN/mirror port if you want to see other hosts'
   traffic. The tool suggests a wired adapter with a live link and explains why. VPN and loopback adapters are refused.
   Wi-Fi and virtual adapters (Hyper-V `vEthernet`) raise a warning. Say how the port is connected, then confirm.
3. **Pre-flight checks.** Checks Wireshark, Npcap, disk space and the link, and runs a 3-second test capture. It only
   listens. Problems block the next step. Warnings must be acknowledged.
4. **Plan.** Choose how long to capture. Ten minutes is the recommended minimum. The loop probe is off by default; it is
   the only thing this tool ever transmits, and it needs the site owner's agreement.
5. **Capture.** Watch **repeated frames per second**. To find a loop, unplug one suspect cable at a time and add a mark
   each time. When the number drops to 0, your last mark names the cable.

Capture stops at the planned time or when you press **Stop**, and goes straight to the results page, with **Open full
report in browser** at the top right. From there you can also save the HTML, save the JSON, save a **redacted** copy for
sharing, or open the folder.

Everything is saved in `Documents\l2-loopcheck\<date-time>\`: the capture files, `marks.json`, `result.json` and
`report.html`. The saved capture is limited to 2 GB by default, and files around your marks are always kept.

Check the list of **checks that were limited** in the report. An access port only sees flooded traffic and this
computer's own traffic, so clear-text logins between other hosts need a SPAN port. A missing finding there is not a pass.

**Analyse a capture file** runs the same analysis on a `.pcap` or `.pcapng` you already have. **Open a saved result**
reopens an earlier `result.json`.

## Command line

`l2loopcheck.exe` in the same folder is the command-line version. Open a
terminal in the folder (in Explorer: right-click → **Open in Terminal**):

```powershell
.\l2loopcheck.exe preflight                        # check this computer and suggest an adapter
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
