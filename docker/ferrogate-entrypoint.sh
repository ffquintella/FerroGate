#!/bin/sh
# FerroGate container entrypoint.
#
# Usage: ferrogate-entrypoint.sh [cmis] [args...]
#   The only server shipped in this image is `cmis`. The `mia` host agent is
#   installed directly on each machine from its OS package, not run here.
#
# Tees the server's stdout/stderr to both the container stdout (for the docker
# log driver) and a file under $FERROGATE_LOG_DIR (a mountable volume). The
# server is exec'd as the foreground process so tini delivers signals straight
# to it; tee runs in the background reading from a FIFO and exits when the
# server closes the pipe.
set -eu

SERVER="${1:-cmis}"
case "$SERVER" in
    cmis) shift ;;
    -*|"") SERVER="cmis" ;;               # only flags given: default server
    *) echo "ferrogate: unknown server '$SERVER' (this image ships cmis only)" >&2
       exit 64 ;;
esac

LOG_DIR="${FERROGATE_LOG_DIR:-/opt/ferrogate/logs}"
LOG_FILE="${LOG_DIR}/${SERVER}.log"
mkdir -p "$LOG_DIR"

# Route output through a FIFO so `exec` can replace this shell with the server
# (preserving signal handling) while tee mirrors to stdout + the log file.
PIPE="$(mktemp -u)"
mkfifo "$PIPE"
tee -a "$LOG_FILE" < "$PIPE" &
exec "$SERVER" "$@" > "$PIPE" 2>&1
