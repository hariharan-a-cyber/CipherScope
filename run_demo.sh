#!/usr/bin/env bash
# One command to run the demo. Sets up the path and starts the web dashboard.
set -e
cd "$(dirname "$0")"
export PYTHONPATH=src
echo "CypherScope demo starting on http://127.0.0.1:8000"
echo "Open that address in your browser. Press Ctrl+C to stop."
python -m cypherscope serve --port 8000
