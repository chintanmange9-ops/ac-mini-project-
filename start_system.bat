@echo off
REM start_system.bat - starts the whole mini project (BD + FD) on Windows.
REM Double-click this file. Close the two server windows to stop everything.
cd /d %~dp0

echo [1/4] Installing requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo FAILED to install requirements. Is Python on PATH?
  pause
  exit /b 1
)

echo [2/4] Starting BD server (API + Database) on port 5001...
start "BD server :5001" python bd_server.py
timeout /t 5 /nobreak >nul

echo [3/4] Starting FD server (Frontend pages) on port 5000...
start "FD server :5000" python fd_server.py
timeout /t 4 /nobreak >nul

echo [4/4] Opening portal in browser...
start http://127.0.0.1:5000

echo.
echo Both servers are running in their own windows.
echo   Portal: http://127.0.0.1:5000  (Student Portal + Database View tabs)
echo   BD API: http://127.0.0.1:5001  (health + api)
echo Close the two server windows to stop the system.
pause
