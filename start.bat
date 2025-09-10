@echo off
title NetScanner - Network Monitoring Dashboard
color 0A

echo.
echo ================================================================================
echo                    NETSCANNER - NETWORK MONITORING DASHBOARD
echo ================================================================================
echo.
echo  Enhanced Network Monitor with Real-Time Packet Capture
echo  Live Dashboard - Traffic Analysis - Device Discovery
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    echo.
    echo Please run setup first:
    echo   1. Open Command Prompt as Administrator
    echo   2. Run: py -3 -m venv venv
    echo   3. Run: venv\Scripts\python -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

REM Check if requirements are installed
echo Checking dependencies...
venv\Scripts\python -c "import flask, scapy" 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    venv\Scripts\python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies!
        pause
        exit /b 1
    )
)

REM Clear any existing demo data
echo Preparing for real monitoring...
venv\Scripts\python scripts\clear_demo_data.py

REM Fix network interface for Windows
echo Configuring network interface...
venv\Scripts\python scripts\fix_interface.py

echo.
echo Setup complete! Starting NetScanner...
echo.
echo Access your dashboard at:
echo    Local:  http://127.0.0.1:5002
echo    Network: http://192.168.50.45:5002
echo.
echo Instructions:
echo    1. Monitoring starts AUTOMATICALLY when app launches
echo    2. Browse some websites to generate traffic  
echo    3. Watch live data appear in real-time!
echo    4. Dashboard refreshes every 2 seconds
echo.
echo Note: Run as Administrator if packet capture fails
echo.

REM Start the Flask application in background and open browser
echo Launching NetScanner Dashboard...
echo Opening web browser...
echo.

REM Start the Flask application in background
start /B venv\Scripts\python src\main.py

REM Wait a moment for the server to start
timeout /t 3 /nobreak >nul

REM Open the web browser
start http://127.0.0.1:5002

REM Wait for user to press a key before stopping
echo.
echo NetScanner is running! Press any key to stop the server...
pause >nul

REM Stop the Python process
taskkill /f /im python.exe >nul 2>&1

echo.
echo NetScanner stopped. Press any key to exit...
pause >nul
