@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PYEXE=C:\Users\27380\AppData\Local\Programs\Python\Python39\python.exe"
if not exist "%PYEXE%" set "PYEXE=python"
set "HOST=0.0.0.0"
echo ============================================================
echo   Starting Shi Ci backend in LAN mode (multi-device sync)
echo.
echo   Other devices on the SAME Wi-Fi can open the "LAN" URL
echo   printed below and log into the same account to sync.
echo.
echo   Only run this on a network you trust.
echo   Keep this window open while using the app.
echo ============================================================
"%PYEXE%" server.py
pause
