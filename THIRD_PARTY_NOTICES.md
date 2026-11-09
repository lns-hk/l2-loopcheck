# Third-party notices

l2-loopcheck is released under the MIT licence. The command-line tool has no third-party runtime dependencies. The
graphical interface and the release builds include the components below. Licence texts are in the `licenses/` folder of
the release.

| Component | Licence |
|---|---|
| Qt (Qt Core, Qt GUI, Qt Widgets and plugins) | LGPL-3.0 |
| PySide6 and shiboken6 (Qt for Python) | LGPL-3.0 |
| Python | PSF License Agreement |
| PyInstaller bootloader | GPL-2.0-or-later with the PyInstaller bootloader exception |

Qt, PySide6 and shiboken6 are used unmodified under the LGPL-3.0, which supplements the GPL-3.0. The release builds are
one-folder builds: every Qt library is a separate file in `_internal/PySide6/` that you may replace with your own
interface-compatible build. The source code is available from The Qt Company at <https://download.qt.io/official_releases/>
and from the Qt for Python project at <https://code.qt.io/cgit/pyside/pyside-setup.git/>.

Wireshark, dumpcap and Npcap are not included. Install them separately under their own licences.
