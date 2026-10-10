@echo off
rem Michael-V1 live demo: starts the dashboard (it also starts the private Owner Vault)
rem and opens both pages. Needs GROQ_API_KEY in .env for the live AI runs.
cd /d "%~dp0"
start "Michael-V1 server" python -m michael.server
echo Starting Michael-V1...
timeout /t 8 /nobreak >nul
start "" http://localhost:8000
start "" http://127.0.0.1:8765
echo Dashboard: http://localhost:8000   Owner Vault: http://127.0.0.1:8765
echo Close the "Michael-V1 server" window to stop.
