@echo off
echo 🚀 Starting NetScanner with REAL Network Monitoring...
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    pause
    exit /b 1
)

echo ✅ Demo data cleared - ready for real monitoring
echo ✅ Real packet capture enabled with scapy
echo ✅ Interface set to WiFi for Windows
echo.
echo Starting NetScanner with REAL network data capture...
echo.
echo Access the application at:
echo   Local:  http://127.0.0.1:5000
echo   Network: http://192.168.50.45:5000
echo.
echo IMPORTANT: 
echo - Click "Start Real Monitoring" in the dashboard
echo - Browse some websites to generate real traffic
echo - Watch the dashboard update with live data
echo.
echo Press Ctrl+C to stop the application
echo.

REM Start the application
venv\Scripts\python.exe src\main.py

pause
