#!/usr/bin/env bash
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PLUGIN_DIR/.venv"
REQS_FILE="$PLUGIN_DIR/requirements.txt"
DEPS_SENTINEL="$VENV_DIR/.deps-installed"

# Compute a hash of requirements.txt to detect changes.
REQS_HASH=""
if command -v sha256sum >/dev/null 2>&1; then
    REQS_HASH="$(sha256sum "$REQS_FILE" 2>/dev/null | cut -d ' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    REQS_HASH="$(shasum -a 256 "$REQS_FILE" 2>/dev/null | cut -d ' ' -f1)"
fi

NEEDS_INSTALL=0
if [ ! -f "$DEPS_SENTINEL" ]; then
    NEEDS_INSTALL=1
elif [ -n "$REQS_HASH" ]; then
    STORED_HASH="$(cat "$DEPS_SENTINEL" 2>/dev/null || true)"
    if [ "$STORED_HASH" != "$REQS_HASH" ]; then
        NEEDS_INSTALL=1
    fi
fi

if [ "$NEEDS_INSTALL" -eq 1 ]; then
    python3 -m venv "$VENV_DIR" || { echo "ERROR: python3 -m venv failed. Is python3 installed?" >&2; exit 1; }
    "$VENV_DIR/bin/pip" install -r "$REQS_FILE" --quiet || { echo "ERROR: pip install failed. Check requirements.txt and network connectivity." >&2; exit 1; }
    if [ -n "$REQS_HASH" ]; then
        printf '%s\n' "$REQS_HASH" > "$DEPS_SENTINEL"
    else
        touch "$DEPS_SENTINEL"
    fi
fi

exec "$VENV_DIR/bin/python" "$PLUGIN_DIR/server.py"
