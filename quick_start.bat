@echo off
REM Quick Start Script for Windows
REM This batch file runs the Python quick_start.py script

echo.
echo ========================================
echo   IDPS - Quick Start (Windows)
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.9+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Run the Python script
python quick_start.py %*

REM Pause if there was an error
if %errorlevel% neq 0 (
    echo.
    echo Script exited with error code %errorlevel%
    pause
)



