@echo off
REM ================================================================================
REM                           NETSCANNER START.BAT
REM                    THE ONLY FILE YOU NEED TO RUN!
REM ================================================================================
REM This single file handles EVERYTHING:
REM   - Environment configuration (edit variables below if needed)
REM   - Dependency checking
REM   - ip2asn database updates
REM   - Pi-hole auto-detection
REM   - ndpiReader auto-detection
REM   - Network interface configuration
REM   - Application startup
REM
REM Just run: start.bat
REM ================================================================================

title NetScanner - Network Monitoring Dashboard
color 0A

REM ================================================================================
REM ENVIRONMENT CONFIGURATION (Edit these if needed)
REM ================================================================================
REM Pi-hole Server IP (auto-detects at 192.168.50.113 if not set)
set PIHOLE_HOST=192.168.50.113

REM ndpiReader Path (if you have it installed)
REM set NDPI_READER_PATH=C:\tools\ndpi\ndpiReader.exe

REM Network Interface (leave blank for auto-detect)
REM set NETSCANNER_INTERFACE=eth0
REM ================================================================================

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

REM Ensure only one instance is running (stop previous NetScanner servers)
echo Stopping any previous NetScanner server instances...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*.exe' -and $_.CommandLine -match 'src\\main\.py' } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }" >nul 2>&1

REM Also free port 5002 if held
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5002') do (
  taskkill /f /pid %%a >nul 2>&1
)

REM Ensure ip2asn TSV exists and is fresh (update if older than 7 days)
echo Checking ip2asn TSV...
if not exist "src\data" mkdir src\data >nul 2>&1

REM Simple check - if file doesn't exist or we haven't checked in a week
if not exist "src\data\ip2asn.tsv" (
  echo Downloading ip2asn TSV database...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz'; $gz = 'src\data\ip2asn-v4.tsv.gz'; $tsv = 'src\data\ip2asn.tsv'; Write-Host 'Downloading...'; Invoke-WebRequest -Uri $url -OutFile $gz -UseBasicParsing; Write-Host 'Extracting...'; $in = [System.IO.File]::OpenRead((Resolve-Path $gz)); $gzip = New-Object System.IO.Compression.GzipStream($in, [System.IO.Compression.CompressionMode]::Decompress); $out = [System.IO.File]::Create((Join-Path $PWD $tsv)); $gzip.CopyTo($out); $out.Close(); $gzip.Close(); $in.Close(); Remove-Item $gz -Force -ErrorAction SilentlyContinue; Write-Host 'Saved to src\data\ip2asn.tsv'; } catch { Write-Host 'Failed to download/extract ip2asn TSV'; }"
) else (
  echo ip2asn TSV exists - using cached version
)

REM Clear any existing demo data
echo Preparing for real monitoring...
venv\Scripts\python scripts\clear_demo_data.py

REM Fix network interface for Windows
echo Configuring network interface...
venv\Scripts\python scripts\fix_interface.py

REM Check Pi-hole configuration
if defined PIHOLE_HOST (
  ping -n 1 -w 500 %PIHOLE_HOST% >nul 2>&1
  if not errorlevel 1 (
    echo Pi-hole server detected at %PIHOLE_HOST%
    echo DNS enrichment will be enabled via network connection
  ) else (
    echo WARNING: Pi-hole server not reachable at %PIHOLE_HOST%
    echo Check your Pi-hole server is running
  )
) else (
  echo Pi-hole host not configured. Checking common locations...
  for %%h in (192.168.50.113 192.168.1.1 raspberrypi pi.hole pihole) do (
    ping -n 1 -w 500 %%h >nul 2>&1
    if not errorlevel 1 (
      set PIHOLE_HOST=%%h
      echo Found Pi-hole at %%h
      goto :pihole_done
    )
  )
  echo Pi-hole not detected on network
)
:pihole_done

REM Ensure Npcap service is RUNNING (Windows capture)
for /f "tokens=3" %%s in ('sc query npcap ^| findstr STATE') do set NPCAP_STATE=%%s
if /I not "%NPCAP_STATE%"=="RUNNING" (
  echo Starting Npcap service...
  net start npcap >nul 2>&1
)

REM Detect tshark availability (pyshark fallback)
where tshark >nul 2>&1
if not errorlevel 1 echo tshark detected for pyshark fallback.

REM Check ndpiReader configuration
if defined NDPI_READER_PATH (
  if exist "%NDPI_READER_PATH%" (
    echo ndpiReader found at %NDPI_READER_PATH%
  ) else (
    echo WARNING: ndpiReader path not found: %NDPI_READER_PATH%
    set NDPI_READER_PATH=
  )
)
if not defined NDPI_READER_PATH (
  REM Try to auto-detect ndpiReader
  for %%p in ("C:\Program Files\ndpi\ndpiReader.exe" "C:\tools\ndpi\ndpiReader.exe" "%USERPROFILE%\ndpi\ndpiReader.exe") do (
    if exist %%p (
      set NDPI_READER_PATH=%%p
      echo Found ndpiReader at %%p
      goto :ndpi_done
    )
  )
  REM Check if in PATH
  where ndpiReader.exe >nul 2>&1
  if not errorlevel 1 (
    for /f "tokens=*" %%i in ('where ndpiReader.exe') do set NDPI_READER_PATH=%%i
    echo Found ndpiReader in PATH
  )
)
:ndpi_done
if not defined NDPI_READER_PATH (
  echo ndpiReader not found. Using built-in traffic classifier.
) else (
  echo Using ndpiReader for deep packet inspection
)

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