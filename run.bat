@echo off
rem ============================================================
rem  crybabyforu - Windows launcher for the BLE lab runner
rem
rem  Usage (same flags as on Linux):
rem    run.bat --list
rem    run.bat --hw-check
rem    run.bat --profile safe --target C0:00:00:41:73:AC
rem    run.bat -l
rem
rem  It uses, in order:
rem    1. this folder's own venv   (crybabyforu\venv\Scripts\python.exe)
rem    2. the parent lab venv      (..\venv\Scripts\python.exe)
rem    3. "python" on PATH
rem ============================================================
setlocal
set "HERE=%~dp0"
set "PY="

if exist "%HERE%venv\Scripts\python.exe" set "PY=%HERE%venv\Scripts\python.exe"
if not defined PY if exist "%HERE%..\venv\Scripts\python.exe" set "PY=%HERE%..\venv\Scripts\python.exe"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERROR] No Python found. Install Python 3.10+ from python.org
    echo         or run setup-venv.bat after installing it.
    exit /b 2
)

"%PY%" "%HERE%scripts\run_all_ble.py" %*
endlocal
