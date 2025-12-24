# Quick Start Script for Windows PowerShell
# This script runs the Python quick_start.py script

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  IDPS - Quick Start (Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Python 3.9+ from https://www.python.org/" -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Run the Python script with all arguments
python quick_start.py $args

# Check exit code
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Script exited with error code $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}



