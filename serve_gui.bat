@echo off
cd /d "%~dp0gui"
echo Open http://localhost:8765/abliteration_gui.html
start "" http://localhost:8765/abliteration_gui.html
"%~dp0.venv\Scripts\python.exe" -m http.server 8765 --bind 127.0.0.1
