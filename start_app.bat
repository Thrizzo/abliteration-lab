@echo off
cd /d "%~dp0"
"%~dp0.venv\Scripts\python.exe" app\server.py --open --project "%~dp0."
