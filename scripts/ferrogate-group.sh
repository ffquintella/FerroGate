#!/usr/bin/env bash
#
# ferrogate-group.sh — create a dedicated MIA OS group, enroll the invoking
# user when present, then print the group's numeric gid to stdout.
#
# For the helper-client group, the installer passes this group's numeric gid to
# the daemon via FERROGATE_HELPER_SOCKET_GID. The operators group is used by the
# Linux Polkit rule to limit lifecycle control to mia.service.
#
# Idempotent: a second run reuses the existing group. The invoking user (taken
# from $SUDO_USER when run under sudo) is added to the group as a convenience.
#
# Usage:   ferrogate-group.sh <group-name>
# Output:  the group's numeric gid on stdout (everything else goes to stderr)
# Must run as root (dscl / groupadd are privileged).

set -euo pipefail

GROUP="${1:?usage: ferrogate-group.sh <group-name>}"

log() { printf '%s\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  log "error: must run as root (try: sudo $0 $GROUP)"
  exit 1
fi

uname_s="$(uname -s)"
case "$uname_s" in
  Darwin)
    if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
      # Pick the first free gid at/above 500 (the service-account range).
      gid=500
      while dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$gid"; do
        gid=$((gid + 1))
      done
      dscl . -create "/Groups/$GROUP"
      dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
      dscl . -create "/Groups/$GROUP" RealName "FerroGate MIA operators"
      dscl . -create "/Groups/$GROUP" Password "*"
      log "==> created group $GROUP (gid $gid)"
    fi
    gid="$(dscl . -read "/Groups/$GROUP" PrimaryGroupID | awk '{print $2}')"
    if [ -n "${SUDO_USER:-}" ]; then
      dscl . -append "/Groups/$GROUP" GroupMembership "$SUDO_USER" 2>/dev/null || true
      log "==> added $SUDO_USER to $GROUP (re-login for it to take effect)"
    fi
    ;;
  Linux)
    if ! getent group "$GROUP" >/dev/null 2>&1; then
      groupadd --system "$GROUP"
      log "==> created system group $GROUP"
    fi
    gid="$(getent group "$GROUP" | cut -d: -f3)"
    if [ -n "${SUDO_USER:-}" ]; then
      usermod -aG "$GROUP" "$SUDO_USER" 2>/dev/null || true
      log "==> added $SUDO_USER to $GROUP (re-login for it to take effect)"
    fi
    ;;
  *)
    log "error: unsupported OS '$uname_s' (this helper handles macOS and Linux)"
    exit 1
    ;;
esac

printf '%s\n' "$gid"
