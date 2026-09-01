@echo off
REM One command to run the demo on Windows. Starts the web dashboard.
cd /d "%~dp0"
set PYTHONPATH=src
echo CypherScope demo starting on http://127.0.0.1:8000
echo Open that address in your browser. Press Ctrl+C to stop.
python -m cypherscope serve --port 8000
