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
# Usage: scripts/build-msi-amd64.sh [version]   (version defaults to Cargo.toml)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(awk '/^\[workspace.package\]/{p=1} p&&/^version/{gsub(/[" ]/,"",$3); print $3; exit}' Cargo.toml)}"
[ -n "$VERSION" ] || { echo "ERROR: could not determine the workspace version from Cargo.toml" >&2; exit 1; }
echo "==> building FerroGate MIA Windows artifacts v$VERSION"

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
  fedora:41 bash -euo pipefail -c '
    dnf install -y -q msitools zip >/dev/null

    echo "==> building MSI with wixl…"
    mkdir -p target/wix
    MSI="target/wix/ferrogate-mia-${VERSION}-x64.msi"
    wixl --arch x64 -D Version="$VERSION" -D BinDir="$BINDIR" -o "$MSI" crates/mia/wix/mia.wxs

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
