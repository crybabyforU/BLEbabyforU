@echo off
rem ============================================================
rem  crybabyforu - create a self-contained venv on Windows
rem
rem  Usage:
rem    setup-venv.bat            minimal requirements (recommended)
rem    setup-venv.bat --full     exact package list from the lab venv
rem    setup-venv.bat --windows  Windows-specific requirements
rem
rem  Requires: Python 3.10+ on PATH (or set PYTHON=C:\Path\python.exe)
rem ============================================================
setlocal enabledelayedexpansion
set "HERE=%~dp0"
set "REQ=%HERE%requirements.txt"
if "%~1"=="--full" set "REQ=%HERE%requirements-freeze.txt"
if "%~1"=="--windows" set "REQ=%HERE%requirements-windows.txt"

set "PYTHON_BIN=%PYTHON%"
if not defined PYTHON_BIN (
    where python >nul 2>nul && set "PYTHON_BIN=python"
)
if not defined PYTHON_BIN (
    where py >nul 2>nul && set "PYTHON_BIN=py -3"
)
if not defined PYTHON_BIN (
    echo [ERROR] No Python found. Install Python 3.10+ from python.org,
    echo         tick "Add to PATH", then run this script again.
    exit /b 2
)

echo Using interpreter: %PYTHON_BIN%
%PYTHON_BIN% -m venv "%HERE%venv"
if errorlevel 1 (
    echo [ERROR] venv creation failed.
    exit /b 1
)
"%HERE%venv\Scripts\python.exe" -m pip install --upgrade pip
"%HERE%venv\Scripts\python.exe" -m pip install -r "%REQ%"
if errorlevel 1 (
    echo [ERROR] pip install failed. See the messages above.
    exit /b 1
)

echo.
echo Done. Local venv: %HERE%venv
echo Run:            %HERE%run.bat -l
endlocal
