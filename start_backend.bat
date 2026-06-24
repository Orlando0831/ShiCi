@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PYEXE=C:\Users\27380\AppData\Local\Programs\Python\Python39\python.exe"
if not exist "%PYEXE%" set "PYEXE=python"
echo ============================================================
echo   Starting Shi Ci (vocabulary) backend ...
echo   When it says "running", open:  http://localhost:8000/
echo   Keep this window open while using the app.
echo ============================================================
"%PYEXE%" server.py
pause
