@echo off
title Install Npcap for Real Packet Capture
color 0E

echo.
echo ================================================================================
echo                    INSTALLING NPCAP FOR REAL PACKET CAPTURE
echo ================================================================================
echo.
echo This will install Npcap (the modern WinPcap replacement) to enable real packet capture.
echo.
echo IMPORTANT: You need to download and install Npcap manually first!
echo.
echo Steps:
echo 1. Go to: https://npcap.com/dist/
echo 2. Download: npcap-1.79.exe (or latest version)
echo 3. Run the installer as Administrator
echo 4. Choose "Install Npcap in WinPcap API-compatible Mode"
echo 5. Come back here and press any key to continue
echo.
echo After installing Npcap, this script will install the Python bindings.
echo.
pause

echo.
echo Installing Python bindings for Npcap...
echo.

REM Try to install pypcap with pre-compiled wheels
.\venv\Scripts\python -m pip install --only-binary=all pypcap

if errorlevel 1 (
    echo.
    echo Installing from source (this may take a few minutes)...
    .\venv\Scripts\python -m pip install pypcap --no-binary=pypcap
)

if errorlevel 1 (
    echo.
    echo ERROR: Failed to install pypcap. 
    echo.
    echo Alternative: Install scapy with Npcap support:
    .\venv\Scripts\python -m pip install scapy[basic]
    echo.
    echo Then restart the application.
) else (
    echo.
    echo SUCCESS: Npcap Python bindings installed!
    echo.
    echo Now restart your application with: start.bat
)

echo.
pause
