@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
"%~dp0venv\Scripts\python.exe" "%~dp0launch_manager.py"
if errorlevel 1 (
    pause
    exit /b 1
)
exit /b 0
