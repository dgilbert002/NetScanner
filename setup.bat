@echo off
title NetScanner Setup
color 0B

echo.
echo ================================================================================
echo                           NETSCANNER SETUP
echo ================================================================================
echo.
echo  Initial Setup - One Time Only
echo.

REM Check if Python is installed
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Please install Python 3.8+ from https://python.org
    echo.
    pause
    exit /b 1
)

echo Python found!

REM Create virtual environment
echo Creating virtual environment...
if exist "venv" (
    echo Virtual environment already exists. Skipping...
) else (
    py -3 -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo Virtual environment created!
)

REM Install dependencies
echo Installing dependencies...
venv\Scripts\python -m pip install --upgrade pip
venv\Scripts\python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies!
    pause
    exit /b 1
)

echo Dependencies installed!

REM Download and install Npcap for real packet capture
echo.
echo Installing Npcap for real packet capture...
if not exist "npcap-installer.exe" (
    echo Downloading Npcap...
    powershell -Command "Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.79.exe' -OutFile 'npcap-installer.exe'"
)

if exist "npcap-installer.exe" (
    echo.
    echo IMPORTANT: Npcap installer downloaded!
    echo Please run npcap-installer.exe as Administrator and choose "WinPcap API-compatible Mode"
    echo After installation, the app will capture real network traffic.
    echo.
) else (
    echo WARNING: Could not download Npcap. Real packet capture may not work.
)

REM Create necessary directories
echo Creating directories...
if not exist "scripts" mkdir scripts
if not exist "docs" mkdir docs
if not exist "src\database" mkdir src\database

echo Directories created!

echo.
echo Setup complete! You can now run start.bat
echo.
echo Next steps:
echo   1. Double-click start.bat to launch NetScanner
echo   2. Open http://127.0.0.1:5000 in your browser
echo   3. Click "Start Real Monitoring" to begin
echo.
pause
