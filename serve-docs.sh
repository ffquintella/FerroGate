#!/usr/bin/env bash
#
# serve-docs.sh — serve the FerroGate documentation site locally with Docsify.
#
# The docs under docs/ are rendered by Docsify (docs/index.html) entirely in the
# browser; this script just needs to serve that directory over HTTP. It prefers
# the docsify-cli (live reload) and falls back to any available static server.
#
# Usage:
#   ./serve-docs.sh [PORT]
#
# Environment:
#   PORT   Port to listen on (default 3000). Positional arg overrides this.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS_DIR="$SCRIPT_DIR/docs"
PORT="${1:-${PORT:-3000}}"

if [[ ! -f "$DOCS_DIR/index.html" ]]; then
  echo "error: $DOCS_DIR/index.html not found — is Docsify set up?" >&2
  exit 1
fi

url="http://localhost:$PORT"

if command -v docsify >/dev/null 2>&1; then
  echo "Serving docs with docsify-cli at $url (live reload enabled)"
  exec docsify serve "$DOCS_DIR" --port "$PORT"
elif command -v npx >/dev/null 2>&1; then
  echo "Serving docs with 'npx docsify-cli' at $url (live reload enabled)"
  exec npx -y docsify-cli serve "$DOCS_DIR" --port "$PORT"
elif command -v python3 >/dev/null 2>&1; then
  echo "docsify-cli not found; serving with python3 http.server at $url (no live reload)"
  exec python3 -m http.server "$PORT" --directory "$DOCS_DIR"
else
  echo "error: need one of docsify-cli, npx, or python3 to serve the docs" >&2
  exit 1
fi
