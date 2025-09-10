@echo off
echo Starting NetScanner Application...
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    echo Please run the setup first or create venv manually.
    pause
    exit /b 1
)

REM Check if requirements are installed
echo Checking dependencies...
venv\Scripts\python.exe -c "import flask" 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    venv\Scripts\python.exe -m pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies!
        pause
        exit /b 1
    )
)

echo.
echo Starting NetScanner with base features...
echo.
echo Access the application at:
echo   Local:  http://127.0.0.1:5000
echo   Network: http://192.168.50.45:5000
echo.
echo Press Ctrl+C to stop the application
echo.

REM Start the application
venv\Scripts\python.exe src\main.py

pause
