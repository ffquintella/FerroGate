#!/usr/bin/env bash
#
# ferrogate-ca.sh — manage the bundled TPM vendor root CAs that the attestation
# verifier (`ferro-attest`) chains EK certificates to.
#
# Roots live under crates/ferro-attest/vendor-roots/<vendor>/ as PEM files and
# are embedded into the binary at build time (see that crate's build.rs).
# Trusting a new root is therefore a deliberate, reviewable act: add the PEM,
# confirm its fingerprint against the vendor's published value, rebuild.
#
# Commands:
#   fingerprint <file.pem>
#       Print the subject, issuer, and SHA-256 fingerprint of a certificate so
#       you can compare it against the vendor's published value before trusting.
#
#   add <vendor> <file.pem> [--fingerprint sha256:AA:BB:...] [--name NAME]
#       Validate that <file.pem> is a self-signed CA certificate, optionally
#       check its SHA-256 fingerprint matches the expected value, then install
#       it under vendor-roots/<vendor>/. Refuses to overwrite without --force.
#
#   list
#       List every installed root, grouped by vendor, with fingerprints.
#
#   verify
#       Re-check that every installed root still parses and is a CA cert.
#
# <vendor> is one of: infineon nuvoton st intel
#
# Requires: openssl.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOTS_DIR="$REPO_ROOT/crates/ferro-attest/vendor-roots"
VENDORS=(infineon nuvoton st intel)

die() {
    printf 'error: ' >&2
    printf '%b\n' "$*" >&2
    exit 1
}

need_openssl() {
    command -v openssl >/dev/null 2>&1 || die "openssl not found on PATH"
}

is_vendor() {
    local v="$1"
    for known in "${VENDORS[@]}"; do
        [ "$v" = "$known" ] && return 0
    done
    return 1
}

# Normalize an openssl fingerprint line ("SHA256 Fingerprint=AA:BB:..") to the
# uppercase colon-separated hex, stripping any "sha256:" prefix on input.
fp_of() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 \
        | sed 's/.*=//' | tr 'a-f' 'A-F'
}

normalize_fp() {
    echo "$1" | sed 's/^sha256://I' | tr 'a-f' 'A-F'
}

assert_self_signed_ca() {
    local pem="$1"
    openssl x509 -in "$pem" -noout >/dev/null 2>&1 \
        || die "$pem is not a valid X.509 certificate (PEM)"
    local subject issuer
    subject="$(openssl x509 -in "$pem" -noout -subject)"
    issuer="$(openssl x509 -in "$pem" -noout -issuer)"
    [ "${subject#subject=}" = "${issuer#issuer=}" ] \
        || die "$pem is not self-signed (subject != issuer); supply the ROOT, not an intermediate"
    # Best-effort CA basic-constraints check (older openssl lacks -ext).
    if openssl x509 -in "$pem" -noout -ext basicConstraints >/dev/null 2>&1; then
        openssl x509 -in "$pem" -noout -ext basicConstraints 2>/dev/null \
            | grep -qi "CA:TRUE" \
            || die "$pem does not assert basicConstraints CA:TRUE"
    fi
}

cmd_fingerprint() {
    [ $# -eq 1 ] || die "usage: fingerprint <file.pem>"
    need_openssl
    local pem="$1"
    [ -f "$pem" ] || die "no such file: $pem"
    echo "subject : $(openssl x509 -in "$pem" -noout -subject | sed 's/subject=//')"
    echo "issuer  : $(openssl x509 -in "$pem" -noout -issuer | sed 's/issuer=//')"
    echo "sha256  : $(fp_of "$pem")"
}

cmd_add() {
    need_openssl
    local vendor="" pem="" expected="" name="" force=0
    [ $# -ge 2 ] || die "usage: add <vendor> <file.pem> [--fingerprint sha256:..] [--name NAME] [--force]"
    vendor="$1"; shift
    pem="$1"; shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --fingerprint) expected="$2"; shift 2 ;;
            --name) name="$2"; shift 2 ;;
            --force) force=1; shift ;;
            *) die "unknown option: $1" ;;
        esac
    done

    is_vendor "$vendor" || die "unknown vendor '$vendor' (one of: ${VENDORS[*]})"
    [ -f "$pem" ] || die "no such file: $pem"
    assert_self_signed_ca "$pem"

    local actual
    actual="$(fp_of "$pem")"
    if [ -n "$expected" ]; then
        local want
        want="$(normalize_fp "$expected")"
        [ "$want" = "$actual" ] \
            || die "fingerprint mismatch:\n  expected $want\n  actual   $actual"
        echo "fingerprint OK: $actual"
    else
        echo "WARNING: no --fingerprint supplied; trusting on faith." >&2
        echo "         verify this matches the vendor's published value:" >&2
        echo "         $actual" >&2
    fi

    local dest_dir="$ROOTS_DIR/$vendor"
    mkdir -p "$dest_dir"
    local base
    if [ -n "$name" ]; then
        base="$name"
    else
        base="$(basename "$pem")"
    fi
    base="${base%.pem}.pem"
    local dest="$dest_dir/$base"

    if [ -e "$dest" ] && [ "$force" -ne 1 ]; then
        die "$dest already exists (pass --force to overwrite)"
    fi
    # Re-emit through openssl so we store a clean, canonical PEM.
    openssl x509 -in "$pem" -outform PEM > "$dest"
    echo "installed: ${dest#"$REPO_ROOT"/}"
    echo "rebuild ferro-attest for the new root to take effect."
}

cmd_list() {
    need_openssl
    local any=0
    for vendor in "${VENDORS[@]}"; do
        local dir="$ROOTS_DIR/$vendor"
        shopt -s nullglob
        local pems=("$dir"/*.pem)
        shopt -u nullglob
        echo "[$vendor]"
        if [ ${#pems[@]} -eq 0 ]; then
            echo "  (none)"
            continue
        fi
        any=1
        for pem in "${pems[@]}"; do
            echo "  $(basename "$pem")"
            echo "    subject: $(openssl x509 -in "$pem" -noout -subject | sed 's/subject=//')"
            echo "    sha256 : $(fp_of "$pem")"
        done
    done
    [ "$any" -eq 1 ] || echo "(no vendor roots installed yet)"
}

cmd_verify() {
    need_openssl
    local fail=0
    for vendor in "${VENDORS[@]}"; do
        shopt -s nullglob
        local pems=("$ROOTS_DIR/$vendor"/*.pem)
        shopt -u nullglob
        [ ${#pems[@]} -eq 0 ] && continue
        for pem in "${pems[@]}"; do
            if assert_self_signed_ca "$pem" 2>/dev/null; then
                echo "ok   $vendor/$(basename "$pem")"
            else
                echo "FAIL $vendor/$(basename "$pem")"
                fail=1
            fi
        done
    done
    [ "$fail" -eq 0 ] || die "one or more roots failed validation"
    echo "all installed roots valid."
}

main() {
    [ $# -ge 1 ] || die "usage: $(basename "$0") {fingerprint|add|list|verify} ..."
    local cmd="$1"; shift
    case "$cmd" in
        fingerprint) cmd_fingerprint "$@" ;;
        add)         cmd_add "$@" ;;
        list)        cmd_list "$@" ;;
        verify)      cmd_verify "$@" ;;
        -h|--help|help) sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
        *) die "unknown command '$cmd' (use: fingerprint, add, list, verify)" ;;
    esac
}

main "$@"
