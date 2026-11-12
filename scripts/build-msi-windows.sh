#!/usr/bin/env bash
# Build the FerroGate MIA Windows artifacts NATIVELY on a Windows host — no
# Docker. `make pkg-win` runs this on Windows (under Git for Windows' bash, see
# the Makefile) and scripts/build-msi-amd64.sh (containers) everywhere else.
# Both produce the same artifacts from the same sources:
#
#   target/wix/ferrogate-mia-<ver>-x64.msi   MSI (crates/mia/wix/mia.wxs)
#   target/nuget/ferrogate-mia.<ver>.nupkg   Chocolatey/NuGet package wrapping the MSI
#
# Prerequisites (all native Windows tools):
#   - Rust with the x86_64-pc-windows-msvc target and the MSVC build tools
#     (Visual Studio / Build Tools "Desktop development with C++").
#   - protoc on PATH (or PROTOC=...): winget install Google.Protobuf
#   - The WiX Toolset, either generation:
#       v4+ : dotnet tool install --global wix --version 4.0.6
#       v3  : winget install WiXToolset.WiXToolset   (candle.exe / light.exe)
#     mia.wxs is WiX v3 source (it is shared with wixl); with v4+ a converted
#     temporary copy is built, the checked-in file is never modified.
#
# Optional Authenticode signing, same variables as the container build:
#   WIN_SIGN_PFX=C:/path/codesign.pfx  WIN_SIGN_PASS=...  WIN_SIGN_TS=http://timestamp.digicert.com
# Signs with signtool.exe (Windows SDK) or, failing that, osslsigncode.
#
# MIA_TRAY=0 omits the tray, MIA_TRAY_ADMIN=0 the admin client (as in the
# container build).
#
# Usage: scripts/build-msi-windows.sh [version]   (version defaults to Cargo.toml)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(awk '/^\[workspace.package\]/{p=1} p&&/^version/{gsub(/[" ]/,"",$3); print $3; exit}' Cargo.toml)}"
[ -n "$VERSION" ] || { echo "ERROR: could not determine the workspace version from Cargo.toml" >&2; exit 1; }
MIA_TRAY="${MIA_TRAY:-1}"
MIA_TRAY_ADMIN="${MIA_TRAY_ADMIN:-1}"
WIN_SIGN_PFX="${WIN_SIGN_PFX:-}"
TARGET=x86_64-pc-windows-msvc
BINDIR="target/$TARGET/release"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) ;;
  *) echo "ERROR: $0 runs on Windows; use scripts/build-msi-amd64.sh elsewhere" >&2; exit 1 ;;
esac

die() { echo "ERROR: $*" >&2; exit 1; }

# ── Tool discovery ────────────────────────────────────────────────────────────
command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust (https://rustup.rs)"
if [ -z "${PROTOC:-}" ] && ! command -v protoc >/dev/null 2>&1; then
  die "protoc not found — winget install Google.Protobuf (or set PROTOC=path\\to\\protoc.exe)"
fi

# WiX: prefer v4+ (`wix`), else v3 (candle/light) from PATH or %WIX%.
WIX_MODE=""
# dotnet global tools land here; a fresh install is not on PATH until a new shell.
if [ -n "${USERPROFILE:-}" ] && [ -x "$(cygpath -u "$USERPROFILE")/.dotnet/tools/wix.exe" ]; then
  PATH="$PATH:$(cygpath -u "$USERPROFILE")/.dotnet/tools"
fi
if command -v wix >/dev/null 2>&1; then
  WIX_MODE=v4
else
  for d in "${WIX:+$(cygpath -u "$WIX")/bin}" /c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3*/bin; do
    if [ -n "$d" ] && [ -x "$d/candle.exe" ] && [ -x "$d/light.exe" ]; then
      PATH="$d:$PATH"; WIX_MODE=v3; break
    fi
  done
  if [ -z "$WIX_MODE" ] && command -v candle >/dev/null 2>&1 && command -v light >/dev/null 2>&1; then
    WIX_MODE=v3
  fi
fi
[ -n "$WIX_MODE" ] || die "WiX Toolset not found. Install one of:
         dotnet tool install --global wix --version 4.0.6
         winget install WiXToolset.WiXToolset"

# Signing tool, only looked up when signing was asked for.
SIGNTOOL=""
if [ -n "$WIN_SIGN_PFX" ]; then
  [ -f "$WIN_SIGN_PFX" ] || die "WIN_SIGN_PFX=$WIN_SIGN_PFX does not exist"
  if command -v signtool >/dev/null 2>&1; then
    SIGNTOOL=signtool
  else
    SIGNTOOL="$(ls -1d /c/Program\ Files\ \(x86\)/Windows\ Kits/10/bin/10.*/x64/signtool.exe 2>/dev/null | sort -V | tail -1 || true)"
  fi
  if [ -z "$SIGNTOOL" ] && command -v osslsigncode >/dev/null 2>&1; then SIGNTOOL=osslsigncode; fi
  [ -n "$SIGNTOOL" ] || die "WIN_SIGN_PFX is set but neither signtool.exe (Windows SDK) nor osslsigncode was found"
fi

# Authenticode-sign a PE/MSI in place. The password is never echoed, but both
# tools take it on the command line, so it is visible to other processes of
# this user while signing runs (as in the container build).
sign_file() {
  echo "==> signing $1…"
  if [ "$SIGNTOOL" = osslsigncode ]; then
    osslsigncode sign -pkcs12 "$WIN_SIGN_PFX" \
      ${WIN_SIGN_PASS:+-pass "$WIN_SIGN_PASS"} \
      ${WIN_SIGN_TS:+-ts "$WIN_SIGN_TS"} \
      -h sha256 -n "FerroGate Machine Identity Agent" \
      -i "https://github.com/ffquintella/FerroGate" \
      -in "$1" -out "$1.signed"
    mv "$1.signed" "$1"
  else
    MSYS2_ARG_CONV_EXCL='*' "$SIGNTOOL" sign /fd sha256 \
      /f "$(cygpath -w "$WIN_SIGN_PFX")" \
      ${WIN_SIGN_PASS:+/p "$WIN_SIGN_PASS"} \
      ${WIN_SIGN_TS:+/tr "$WIN_SIGN_TS" /td sha256} \
      /d "FerroGate Machine Identity Agent" \
      /du "https://github.com/ffquintella/FerroGate" \
      "$(cygpath -w "$1")"
  fi
}

echo "==> building FerroGate MIA Windows artifacts v$VERSION (native, WiX $WIX_MODE)"

# ── Stage 1: compile mia.exe (and the tray) natively ──────────────────────────
echo "==> [1/2] compiling for $TARGET…"
rustup target list --installed 2>/dev/null | grep -qx "$TARGET" || rustup target add "$TARGET"
cargo build --release -p mia --bin mia --target "$TARGET"
rm -f "$BINDIR/mia-tray.exe" "$BINDIR/mia-tray-admin.exe"
if [ "$MIA_TRAY" != 0 ]; then
  cargo build --release -p mia-tray --features gui --bin mia-tray --target "$TARGET" \
    || echo "WARNING: mia-tray.exe did not build; the MSI will ship without the tray"
  # The admin client (F22) is a separate build so its dependencies never
  # unify into the tray binary.
  if [ "$MIA_TRAY_ADMIN" != 0 ] && [ -f "$BINDIR/mia-tray.exe" ]; then
    cargo build --release -p mia-tray --features admin --bin mia-tray-admin --target "$TARGET" \
      || echo "WARNING: mia-tray-admin.exe did not build; the MSI will ship without the admin client"
  fi
fi
[ -f "$BINDIR/mia.exe" ] || die "$BINDIR/mia.exe was not produced"

# Same checks as the container build: the tray and admin client must be
# Windows-GUI subsystem (2) and must not ask for elevation.
for exe in mia-tray.exe mia-tray-admin.exe; do
  [ -f "$BINDIR/$exe" ] || continue
  pe_off=$(od -An -tu4 -j60 -N4 "$BINDIR/$exe" | tr -d ' ')
  subsystem=$(od -An -tu2 -j$((pe_off + 92)) -N2 "$BINDIR/$exe" | tr -d ' ')
  [ "$subsystem" = 2 ] || die "$BINDIR/$exe has PE subsystem $subsystem, expected 2 (Windows GUI)"
  if grep -aqE 'requireAdministrator|highestAvailable' "$BINDIR/$exe"; then
    die "$BINDIR/$exe asks Windows for elevation (requireAdministrator/highestAvailable); it must run asInvoker"
  fi
done

# ── Stage 2: MSI + Chocolatey/NuGet package ──────────────────────────────────
echo "==> [2/2] building MSI + NuGet package…"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Sign the binaries BEFORE the MSI embeds them, so the installed mia.exe passes
# the helper API's default-on Authenticode caller check.
[ -z "$WIN_SIGN_PFX" ] || sign_file "$BINDIR/mia.exe"

WXS="$WORK/mia.wxs"
STRIP=()
if [ -f "$BINDIR/mia-tray.exe" ]; then
  [ -z "$WIN_SIGN_PFX" ] || sign_file "$BINDIR/mia-tray.exe"
  if [ -f "$BINDIR/mia-tray-admin.exe" ]; then
    [ -z "$WIN_SIGN_PFX" ] || sign_file "$BINDIR/mia-tray-admin.exe"
  else
    STRIP+=(-e "/<!-- ADMIN-BEGIN/,/<!-- ADMIN-END -->/d" -e "/<!-- ADMIN-FEATURE-BEGIN/,/<!-- ADMIN-FEATURE-END -->/d")
    echo "NOTE: building the MSI without the admin client (mia-tray-admin.exe not built)"
  fi
else
  STRIP+=(-e "/<!-- TRAY-BEGIN/,/<!-- TRAY-END -->/d" -e "/<!-- TRAY-REF -->/d")
  STRIP+=(-e "/<!-- ADMIN-BEGIN/,/<!-- ADMIN-END -->/d" -e "/<!-- ADMIN-FEATURE-BEGIN/,/<!-- ADMIN-FEATURE-END -->/d")
  echo "NOTE: building the MSI without mia-tray (mia-tray.exe not built)"
fi
# (sed without any -e would take the file name as its script, hence the cp.)
if [ ${#STRIP[@]} -gt 0 ]; then
  sed "${STRIP[@]}" crates/mia/wix/mia.wxs > "$WXS"
else
  cp crates/mia/wix/mia.wxs "$WXS"
fi

mkdir -p target/wix
MSI="target/wix/ferrogate-mia-${VERSION}-x64.msi"
rm -f "$MSI"
# The .wxs refers to its sources relative to the repository root (the cwd).
if [ "$WIX_MODE" = v4 ]; then
  # `wix convert` exits with the number of conversions it applied, so a
  # nonzero status is the expected case; check the result instead.
  wix convert "$(cygpath -w "$WXS")" >/dev/null 2>&1 || true
  grep -q 'http://wixtoolset.org/schemas/v4/wxs' "$WXS" || die "wix convert did not produce WiX v4 source"
  # wixl schedules RemoveExistingProducts for the <Upgrade> table implicitly;
  # WiX v4 needs it spelled out. afterInstallValidate is MajorUpgrade's default:
  # the old version (and its service) is removed before the new one goes in.
  # mia.wxs already has an <InstallExecuteSequence> (the MiaSecureConfig
  # custom action): add the action to it rather than declaring a second one.
  if grep -q '<InstallExecuteSequence>' "$WXS"; then
    sed -i '0,/<InstallExecuteSequence>/s||<InstallExecuteSequence><RemoveExistingProducts After="InstallValidate" />|' "$WXS"
  else
    grep -q '</Package>' "$WXS" || die "unexpected WiX v4 layout (no </Package>)"
    sed -i 's|</Package>|<InstallExecuteSequence><RemoveExistingProducts After="InstallValidate" /></InstallExecuteSequence></Package>|' "$WXS"
  fi
  MSYS2_ARG_CONV_EXCL='*' wix build -arch x64 \
    -d "Version=$VERSION" -d "BinDir=$BINDIR" \
    -o "$(cygpath -w "$MSI")" "$(cygpath -w "$WXS")"
else
  MSYS2_ARG_CONV_EXCL='*' candle.exe -nologo -arch x64 \
    "-dVersion=$VERSION" "-dBinDir=$BINDIR" \
    -out "$(cygpath -w "$WORK/mia.wixobj")" "$(cygpath -w "$WXS")"
  MSYS2_ARG_CONV_EXCL='*' light.exe -nologo -spdb \
    -out "$(cygpath -w "$MSI")" "$(cygpath -w "$WORK/mia.wixobj")"
fi
[ -f "$MSI" ] || die "$MSI was not produced"
[ -z "$WIN_SIGN_PFX" ] || sign_file "$MSI"

echo "==> assembling Chocolatey/NuGet package…"
STAGE="$WORK/nupkg"
mkdir -p "$STAGE/tools" "$STAGE/_rels" "$STAGE/package/services/metadata/core-properties"
sed "s/__VERSION__/${VERSION}/g" crates/mia/nuget/ferrogate-mia.nuspec > "$STAGE/ferrogate-mia.nuspec"
cp crates/mia/nuget/tools/chocolateyInstall.ps1   "$STAGE/tools/"
cp crates/mia/nuget/tools/chocolateyUninstall.ps1 "$STAGE/tools/"
cp "$MSI" "$STAGE/tools/ferrogate-mia.msi"

cat > "$STAGE/[Content_Types].xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="psmdcp" ContentType="application/vnd.openxmlformats-package.core-properties+xml" />
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="ps1" ContentType="application/octet" />
  <Default Extension="msi" ContentType="application/octet" />
</Types>
EOF

cat > "$STAGE/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/ferrogate-mia.nuspec" Id="R1" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/package/services/metadata/core-properties/coreprops.psmdcp" Id="R2" />
</Relationships>
EOF

cat > "$STAGE/package/services/metadata/core-properties/coreprops.psmdcp" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>FerroGate contributors</dc:creator>
  <dc:description>FerroGate Machine Identity Agent (MIA) Windows installer.</dc:description>
  <dc:identifier>ferrogate-mia</dc:identifier>
  <version>${VERSION}</version>
  <keywords>ferrogate mia machine-identity</keywords>
  <lastModifiedBy>FerroGate native Windows build</lastModifiedBy>
</coreProperties>
EOF

mkdir -p target/nuget
NUPKG="target/nuget/ferrogate-mia.${VERSION}.nupkg"
rm -f "$NUPKG"
# Windows' bundled bsdtar writes a zip with forward-slash entry names (a .nupkg
# is a zip); Git's GNU tar, first on PATH here, cannot write zips.
WINTAR="$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")/System32/tar.exe"
[ -x "$WINTAR" ] || die "$WINTAR not found (bundled with Windows 10 1803+)"
NUPKG_W="$(cygpath -w "$PWD/$NUPKG")"
( cd "$STAGE" && "$WINTAR" -a -c -f "$NUPKG_W" \
    "[Content_Types].xml" _rels package tools ferrogate-mia.nuspec )
[ -f "$NUPKG" ] || die "$NUPKG was not produced"

echo ""
echo "==> Windows artifacts (v$VERSION):"
echo "    MSI:   $MSI"
echo "    nupkg: $NUPKG"
if [ -z "$WIN_SIGN_PFX" ]; then
  echo ""
  echo "NOTE: mia.exe and the MSI are UNSIGNED (no WIN_SIGN_PFX given). On Windows the"
  echo "      helper API's default-on Authenticode caller check (helper.require_authenticode)"
  echo "      refuses unsigned callers — 'mia test' step 5 will fail with 'untrusted-binary'."
  echo "      Sign the build (WIN_SIGN_PFX=C:/path/codesign.pfx) or set"
  echo "      helper.require_authenticode = false in mia.toml on the target hosts."
fi
