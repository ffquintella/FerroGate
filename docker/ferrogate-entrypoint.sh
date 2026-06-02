#!/bin/sh
# FerroGate container entrypoint.
#
# Usage: ferrogate-entrypoint.sh [cmis|ferrogate] [args...]
#   The only server shipped in this image is `cmis`. The `ferrogate` operator
#   CLI is also bundled — it is exec'd directly (not tee'd into a server log),
#   so `docker run ... ferrogate status` works just like `docker exec`. The
#   `mia` host agent is installed directly on each machine from its OS package,
#   not run here.
#
# For `cmis`, tees stdout/stderr to both the container stdout (for the docker
# log driver) and a file under $FERROGATE_LOG_DIR (a mountable volume). The
# server is exec'd as the foreground process so tini delivers signals straight
# to it; tee runs in the background reading from a FIFO and exits when the
# server closes the pipe.
set -eu

# The bundled operator CLI is short-lived and writes to stdout — exec it
# straight through, bypassing the server log-tee below.
if [ "${1:-}" = "ferrogate" ]; then
    shift
    exec ferrogate "$@"
fi

SERVER="${1:-cmis}"
case "$SERVER" in
    cmis) shift ;;
    -*|"") SERVER="cmis" ;;               # only flags given: default server
    *) echo "ferrogate: unknown command '$SERVER' (this image ships the cmis server and the ferrogate CLI)" >&2
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
