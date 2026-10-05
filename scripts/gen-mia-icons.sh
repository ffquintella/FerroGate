#!/usr/bin/env bash
# Regenerate the FerroGate MIA application icons from the SVG master:
#
#   crates/mia-tray/dist/icons/ferrogate-mia.svg    master (hand-edited)
#   crates/mia-tray/dist/icons/ferrogate-mia.png    256 px (Linux hicolor)
#   crates/mia-tray/dist/icons/ferrogate-mia.icns   macOS bundle icon
#   crates/mia-tray/dist/icons/ferrogate-mia.ico    Windows (16–256 px, PNG frames)
#
# The generated files are committed so packaging never needs an SVG renderer;
# run this (`make icons`) only after editing the SVG. Rasterises with
# rsvg-convert when present, else macOS QuickLook (qlmanage) + sips. The .icns
# needs macOS iconutil; elsewhere it is left untouched with a warning.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=crates/mia-tray/dist/icons
SVG="$DIR/ferrogate-mia.svg"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# render <px> <out.png>
render() {
  if command -v rsvg-convert >/dev/null; then
    rsvg-convert -w "$1" -h "$1" -o "$2" "$SVG"
  elif command -v qlmanage >/dev/null && command -v sips >/dev/null; then
    [ -f "$TMP/master.png" ] || {
      qlmanage -t -s 1024 -o "$TMP" "$SVG" >/dev/null 2>&1
      mv "$TMP/$(basename "$SVG").png" "$TMP/master.png"
    }
    sips -z "$1" "$1" "$TMP/master.png" --out "$2" >/dev/null
  else
    echo "ERROR: need rsvg-convert (librsvg) or macOS qlmanage+sips" >&2
    exit 1
  fi
}

for px in 16 32 48 64 128 256 512 1024; do
  render "$px" "$TMP/$px.png"
done

cp "$TMP/256.png" "$DIR/ferrogate-mia.png"

# Windows .ico with PNG-compressed frames (supported since Vista).
python3 - "$TMP" "$DIR/ferrogate-mia.ico" <<'EOF'
import struct, sys
tmp, out = sys.argv[1], sys.argv[2]
sizes = [16, 32, 48, 256]
frames = [open(f"{tmp}/{s}.png", "rb").read() for s in sizes]
header = struct.pack("<HHH", 0, 1, len(sizes))
offset = len(header) + 16 * len(sizes)
entries, data = b"", b""
for s, png in zip(sizes, frames):
    dim = 0 if s >= 256 else s  # 0 means 256 in the ICO directory
    entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(data))
    data += png
open(out, "wb").write(header + entries + data)
EOF

if command -v iconutil >/dev/null; then
  SET="$TMP/ferrogate-mia.iconset"
  mkdir "$SET"
  for px in 16 32 128 256 512; do
    cp "$TMP/$px.png" "$SET/icon_${px}x${px}.png"
    cp "$TMP/$((px * 2)).png" "$SET/icon_${px}x${px}@2x.png"
  done
  iconutil -c icns -o "$DIR/ferrogate-mia.icns" "$SET"
else
  echo "WARNING: iconutil not found (macOS only); $DIR/ferrogate-mia.icns not regenerated" >&2
fi

echo "==> icons written under $DIR/"
