#!/usr/bin/env bash
# TriageScript launcher (bash)
# Installs dependencies on first run, then starts the local web UI, which opens
# your browser automatically. Pass extra args through, e.g.:  ./start.sh --port 9000
set -e
cd "$(dirname "$0")"

# Locate a Python interpreter: prefer a local .venv, then a shared repo .venv,
# then system Python.
if [ -f ".venv/Scripts/python.exe" ]; then
    PY=".venv/Scripts/python.exe"            # local venv (Windows / Git Bash)
elif [ -f ".venv/bin/python" ]; then
    PY=".venv/bin/python"                    # local venv (Linux / macOS)
elif [ -f "../../../.venv/Scripts/python.exe" ]; then
    PY="../../../.venv/Scripts/python.exe"   # shared repo venv (Windows)
elif [ -f "../../../.venv/bin/python" ]; then
    PY="../../../.venv/bin/python"           # shared repo venv (POSIX)
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
else
    PY="python"
fi

echo "Using Python: $PY"

# Install dependencies only if oletools is missing.
if ! "$PY" -c "import oletools" 2>/dev/null; then
    echo "Installing dependencies..."
    "$PY" -m pip install -q -r requirements.txt
fi

echo "Starting TriageScript web UI (a browser tab will open)..."
exec "$PY" -m triagescript.web "$@"
