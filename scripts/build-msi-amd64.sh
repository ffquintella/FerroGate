#!/usr/bin/env bash
# Build the FerroGate MIA Windows artifacts in containers — no Windows host
# required:
#
#   target/wix/ferrogate-mia-<ver>-x64.msi   MSI (built with msitools / wixl)
#   target/nuget/ferrogate-mia.<ver>.nupkg   Chocolatey/NuGet package wrapping the MSI
#
# Two stages, each in its own container (both mount the repo at /work):
#   1. rust:bookworm — cross-compile mia.exe to x86_64-pc-windows-msvc with
#      cargo-xwin (clang + the xwin-provided MSVC CRT). The rustls/aws-lc-rs
#      crypto backend needs nasm + cmake at build time.
#   2. fedora       — build the MSI with wixl (Debian/Ubuntu msitools no longer
#      ships wixl; Fedora's does) and assemble the Chocolatey/NuGet package.
#
# The MSI installs mia.exe and registers + starts the mia service. The nupkg
# additionally creates the FerroGateClients group and adds the install dir to
# PATH before invoking the MSI (see crates/mia/nuget/ and crates/mia/wix/).
#
# Optional Authenticode signing: mia's helper API refuses unsigned caller
# binaries by default on Windows (`helper.require_authenticode`), so an
# unsigned mia.exe fails its own `mia test` out of the box. Set
#
#   WIN_SIGN_PFX=/path/to/codesign.pfx   PKCS#12 code-signing bundle
#   WIN_SIGN_PASS=...                    its password (optional)
#   WIN_SIGN_TS=http://timestamp.digicert.com   RFC 3161 timestamp URL (optional)
#
# to sign mia.exe (before the MSI embeds it) and the MSI with osslsigncode.
# Without WIN_SIGN_PFX the artifacts are built unsigned and a NOTE is printed.
#
# Usage: scripts/build-msi-amd64.sh [version]   (version defaults to Cargo.toml)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(awk '/^\[workspace.package\]/{p=1} p&&/^version/{gsub(/[" ]/,"",$3); print $3; exit}' Cargo.toml)}"
[ -n "$VERSION" ] || { echo "ERROR: could not determine the workspace version from Cargo.toml" >&2; exit 1; }
echo "==> building FerroGate MIA Windows artifacts v$VERSION"

WIN_SIGN_PFX="${WIN_SIGN_PFX:-}"
SIGN_MOUNT=()
if [ -n "$WIN_SIGN_PFX" ]; then
  [ -f "$WIN_SIGN_PFX" ] || { echo "ERROR: WIN_SIGN_PFX=$WIN_SIGN_PFX does not exist" >&2; exit 1; }
  SIGN_MOUNT=(
    -v "$(cd "$(dirname "$WIN_SIGN_PFX")" && pwd)/$(basename "$WIN_SIGN_PFX")":/signing.pfx:ro
    -e WIN_SIGN=1
    -e WIN_SIGN_PASS="${WIN_SIGN_PASS:-}"
    -e WIN_SIGN_TS="${WIN_SIGN_TS:-}"
  )
fi

# ── Stage 1: cross-compile mia.exe (x86_64-pc-windows-msvc) ───────────────────
echo "==> [1/2] cross-compiling mia.exe in rust:bookworm…"
docker run --rm --platform linux/amd64 \
  -v "$PWD":/work -w /work \
  -e CARGO_TERM_COLOR=always \
  rust:bookworm bash -euo pipefail -c '
    echo "==> installing cross toolchain (clang/lld/nasm/cmake)…"
    apt-get update -qq
    apt-get install -y -qq clang lld llvm nasm cmake pkg-config protobuf-compiler ca-certificates >/dev/null
    rustup target add x86_64-pc-windows-msvc
    cargo install cargo-xwin --quiet
    cargo xwin build --release -p mia --bin mia --target x86_64-pc-windows-msvc
  '
BINDIR=target/x86_64-pc-windows-msvc/release
[ -f "$BINDIR/mia.exe" ] || { echo "ERROR: $BINDIR/mia.exe was not produced" >&2; exit 1; }

# ── Stage 2: build the MSI (wixl) and the Chocolatey/NuGet package ────────────
echo "==> [2/2] building MSI + NuGet package in fedora…"
docker run --rm --platform linux/amd64 \
  -v "$PWD":/work -w /work \
  -e VERSION="$VERSION" -e BINDIR="$BINDIR" \
  ${SIGN_MOUNT[@]+"${SIGN_MOUNT[@]}"} \
  fedora:41 bash -euo pipefail -c '
    dnf install -y -q msitools zip ${WIN_SIGN:+osslsigncode} >/dev/null

    # Authenticode-sign a PE/MSI in place with the mounted PKCS#12 bundle.
    sign_file() {
      echo "==> signing $1 with osslsigncode…"
      osslsigncode sign -pkcs12 /signing.pfx \
        ${WIN_SIGN_PASS:+-pass "$WIN_SIGN_PASS"} \
        ${WIN_SIGN_TS:+-ts "$WIN_SIGN_TS"} \
        -h sha256 \
        -n "FerroGate Machine Identity Agent" \
        -i "https://github.com/ffquintella/FerroGate" \
        -in "$1" -out "$1.signed"
      mv "$1.signed" "$1"
    }

    # Sign mia.exe BEFORE wixl embeds it, so the installed binary passes the
    # helper API'\''s default-on Authenticode caller check.
    [ -z "${WIN_SIGN:-}" ] || sign_file "$BINDIR/mia.exe"

    echo "==> building MSI with wixl…"
    mkdir -p target/wix
    MSI="target/wix/ferrogate-mia-${VERSION}-x64.msi"
    wixl --arch x64 -D Version="$VERSION" -D BinDir="$BINDIR" -o "$MSI" crates/mia/wix/mia.wxs
    [ -z "${WIN_SIGN:-}" ] || sign_file "$MSI"

    echo "==> assembling Chocolatey/NuGet package…"
    STAGE="$(mktemp -d)"
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
  <lastModifiedBy>FerroGate build container</lastModifiedBy>
</coreProperties>
EOF

    mkdir -p target/nuget
    NUPKG="$PWD/target/nuget/ferrogate-mia.${VERSION}.nupkg"
    rm -f "$NUPKG"
    ( cd "$STAGE" && zip -q -X -r "$NUPKG" "[Content_Types].xml" _rels package tools ferrogate-mia.nuspec )
    rm -rf "$STAGE"

    echo "==> wrote $MSI"
    echo "==> wrote target/nuget/ferrogate-mia.${VERSION}.nupkg"
  '

echo ""
echo "==> Windows artifacts (v$VERSION):"
echo "    MSI:   target/wix/ferrogate-mia-${VERSION}-x64.msi"
echo "    nupkg: target/nuget/ferrogate-mia.${VERSION}.nupkg"
if [ -z "$WIN_SIGN_PFX" ]; then
  echo ""
  echo "NOTE: mia.exe and the MSI are UNSIGNED (no WIN_SIGN_PFX given). On Windows the"
  echo "      helper API's default-on Authenticode caller check (helper.require_authenticode)"
  echo "      refuses unsigned callers — 'mia test' step 5 will fail with 'untrusted-binary'."
  echo "      Sign the build (WIN_SIGN_PFX=/path/to/codesign.pfx) or set"
  echo "      helper.require_authenticode = false in mia.toml on the target hosts."
fi
