#!/usr/bin/env bash
# Build release bundles with PyInstaller (macOS .app zip or Linux AppImage + tarball).
# Usage: bash packaging/build.sh   (run from the repo root, inside a venv with .[gui,build])
set -euo pipefail
VERSION=$(python -c "import l2loopcheck; print(l2loopcheck.__version__)")
rm -rf build dist
COMMON=(--noconfirm --clean --paths . --collect-submodules l2loopcheck)
case "$(uname -s)" in
  Darwin)
    pyinstaller "${COMMON[@]}" --windowed --name "l2-loopcheck" \
      --osx-bundle-identifier hk.lns.l2loopcheck packaging/entry_gui.py
    pyinstaller "${COMMON[@]}" --console --name l2loopcheck packaging/entry_cli.py
    cp -R dist/l2loopcheck "dist/l2-loopcheck.app/Contents/MacOS/cli"
    (cd dist && ditto -c -k --keepParent "l2-loopcheck.app" "l2-loopcheck-${VERSION}-macos-$(uname -m).zip")
    echo "dist/l2-loopcheck-${VERSION}-macos-$(uname -m).zip"
    ;;
  Linux)
    pyinstaller "${COMMON[@]}" --name l2loopcheck-gui packaging/entry_gui.py
    pyinstaller "${COMMON[@]}" --name l2loopcheck packaging/entry_cli.py
    cp -R dist/l2loopcheck/. dist/l2loopcheck-gui/
    APPDIR=dist/l2-loopcheck.AppDir
    mkdir -p "$APPDIR/usr/bin"
    cp -R dist/l2loopcheck-gui/. "$APPDIR/usr/bin/"
    cp packaging/linux/AppRun packaging/linux/l2-loopcheck.desktop packaging/linux/l2-loopcheck.png "$APPDIR/"
    chmod +x "$APPDIR/AppRun"
    tar -C dist -czf "dist/l2-loopcheck-${VERSION}-linux-$(uname -m).tar.gz" l2loopcheck-gui
    if command -v appimagetool >/dev/null; then
      ARCH=$(uname -m) appimagetool "$APPDIR" "dist/l2-loopcheck-${VERSION}-linux-$(uname -m).AppImage"
    else
      echo "appimagetool not found: only the tarball was built" >&2
    fi
    ;;
  *) echo "Use packaging/windows/build.ps1 on Windows" >&2; exit 1 ;;
esac
