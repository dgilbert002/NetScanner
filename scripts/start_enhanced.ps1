# NetScanner Application Launcher with Enhanced Features
# PowerShell script to start the NetScanner application with enhanced features

Write-Host "Starting NetScanner Application with Enhanced Features..." -ForegroundColor Green
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path "venv\Scripts\python.exe")) {
    Write-Host "ERROR: Virtual environment not found!" -ForegroundColor Red
    Write-Host "Please run the setup first or create venv manually." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if requirements are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow
try {
    & "venv\Scripts\python.exe" -c "import flask" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Flask not found"
    }
} catch {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    & "venv\Scripts\python.exe" -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies!" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Write-Host "Starting NetScanner with ENHANCED features..." -ForegroundColor Green
Write-Host ""
Write-Host "Access the application at:" -ForegroundColor Cyan
Write-Host "  Local:  http://127.0.0.1:5000" -ForegroundColor White
Write-Host "  Network: http://192.168.50.45:5000" -ForegroundColor White
Write-Host ""
Write-Host "Enhanced features enabled:" -ForegroundColor Magenta
Write-Host "  - Advanced device management" -ForegroundColor White
Write-Host "  - Detailed traffic analysis" -ForegroundColor White
Write-Host "  - Website analytics" -ForegroundColor White
Write-Host "  - Content analysis" -ForegroundColor White
Write-Host "  - User activity timeline" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

# Set environment variable for enhanced features
$env:ENABLE_ENHANCED = "1"

# Start the application
& "venv\Scripts\python.exe" "src\main.py"

Read-Host "Press Enter to exit"
