# Build the Windows release zip with PyInstaller (one-folder).
#
#   dist\l2-loopcheck-windows.zip
#     l2-loopcheck\l2loopcheck-gui.exe   windowed GUI
#     l2-loopcheck\l2loopcheck.exe       console CLI
#     l2-loopcheck\_internal\...         shared Python runtime and libraries
#
# Usage (from anywhere; Windows PowerShell 5.1 or PowerShell 7):
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Python C:\path\to\python.exe
#
# The Python used needs the "gui" and "build" extras: pip install ".[gui,build]".
# By default the repo's .venv is used when it exists. Unsigned in v1.

[CmdletBinding()]
param(
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

if (-not $Python) {
    $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) { $Python = $venvPy } else { $Python = "python" }
}

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

$Version = (& $Python -c "import l2loopcheck; print(l2loopcheck.__version__)").Trim()
if ($LASTEXITCODE -ne 0) { throw "Cannot import l2loopcheck with $Python" }
& $Python -c "import PySide6, PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) { throw "$Python needs PySide6 and PyInstaller: $Python -m pip install "".[gui,build]""" }
Write-Host "Building l2-loopcheck $Version with $Python"

foreach ($d in @("build", "dist")) {
    if (Test-Path $d) { Remove-Item -Recurse -Force $d }
}

# Icon: wrap the 256x256 PNG in an .ico container (PNG-in-ICO, Windows Vista+).
$Png = Join-Path $Root "packaging\linux\l2-loopcheck.png"
$Ico = Join-Path $Root "packaging\windows\l2-loopcheck.ico"
if (-not (Test-Path $Ico)) {
    Invoke-Checked $Python @("-c", @"
import struct, sys
png = open(sys.argv[1], 'rb').read()
w, h = struct.unpack('>II', png[16:24])
hdr = struct.pack('<HHH', 0, 1, 1)
entry = struct.pack('<BBBBHHII', w % 256, h % 256, 0, 0, 1, 32, len(png), 6 + 16)
open(sys.argv[2], 'wb').write(hdr + entry + png)
"@, $Png, $Ico)
}

$Common = @(
    "-m", "PyInstaller", "--noconfirm", "--clean",
    "--paths", ".",
    "--collect-submodules", "l2loopcheck",
    "--icon", $Ico,
    "--add-data", "$Ico;.",
    "--specpath", "build\spec",
    "--workpath", "build\work",
    "--distpath", "build\out"
)
Invoke-Checked $Python ($Common + @("--windowed", "--name", "l2loopcheck-gui", "packaging\entry_gui.py"))
Invoke-Checked $Python ($Common + @("--console", "--name", "l2loopcheck", "packaging\entry_cli.py"))

# Merge the two one-folder builds: same Python runtime, the CLI needs a subset of the GUI's files.
$App = Join-Path $Root "dist\l2-loopcheck"
New-Item -ItemType Directory -Force $App | Out-Null
Copy-Item -Recurse -Force "build\out\l2loopcheck-gui\*" $App
Copy-Item -Recurse -Force "build\out\l2loopcheck\*" $App
Copy-Item -Force "LICENSE" (Join-Path $App "LICENSE.txt")
Copy-Item -Force "THIRD_PARTY_NOTICES.md" (Join-Path $App "THIRD_PARTY_NOTICES.md")
Copy-Item -Recurse -Force "packaging\licenses" (Join-Path $App "licenses")
@"
l2-loopcheck $Version for Windows
===================================

Layer-2 loop and broadcast-storm health check.

1. Install Wireshark first (https://www.wireshark.org/download.html) and keep
   "Install Npcap" ticked. l2-loopcheck uses Wireshark's dumpcap to capture.
2. Start l2loopcheck-gui.exe. If Windows SmartScreen says "Windows protected
   your PC", click "More info" and then "Run anyway" (the program is not
   code-signed yet).
3. Pick the network adapter plugged into the switch and press Start.

Command line: open a terminal in this folder and run  l2loopcheck.exe --help

Guide: https://github.com/lns-hk/l2-loopcheck/blob/main/docs/INSTALL-WINDOWS.md
"@ | Out-File -Encoding ascii (Join-Path $App "README.txt")

# Qt's software OpenGL fallback (about 20 MB) and translations are not used by a widgets-only app.
Get-ChildItem -Recurse $App -Include "opengl32sw.dll" | Remove-Item -Force
Get-ChildItem -Recurse -Directory $App -Filter "translations" | Remove-Item -Recurse -Force

# Smoke test the console build before zipping.
$Cli = Join-Path $App "l2loopcheck.exe"
Invoke-Checked $Cli @("--version")
$Demo = Join-Path $Root "build\demo-loop.pcap"
Invoke-Checked $Cli @("demo", "loop", "-o", $Demo)
Invoke-Checked $Cli @("analyze", $Demo, "--quiet", "--html", (Join-Path $Root "build\demo-loop.html"))

$Zip = Join-Path $Root "dist\l2-loopcheck-windows.zip"
Compress-Archive -Path $App -DestinationPath $Zip -Force
$SizeMb = [math]::Round((Get-Item $Zip).Length / 1MB, 1)
Write-Host "dist\l2-loopcheck-windows.zip ($SizeMb MB, version $Version)"
