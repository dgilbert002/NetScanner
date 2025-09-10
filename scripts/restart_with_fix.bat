@echo off
echo 🔧 Restarting NetScanner with Windows Interface Fix...
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    pause
    exit /b 1
)

echo ✅ Interface has been updated to use WiFi instead of eth0
echo.
echo Starting NetScanner with corrected network interface...
echo.
echo Access the application at:
echo   Local:  http://127.0.0.1:5000
echo   Network: http://192.168.50.45:5000
echo.
echo The app should now capture real network data from your WiFi interface!
echo.

REM Start the application
venv\Scripts\python.exe src\main.py

pause
