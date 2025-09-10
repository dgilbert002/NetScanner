@echo off
title Quick Npcap Installation
color 0A

echo.
echo ================================================================================
echo                    QUICK NPCAP INSTALLATION
echo ================================================================================
echo.
echo This will install Npcap for real packet capture.
echo.
echo IMPORTANT: Run this as Administrator!
echo.
echo Right-click this file and select "Run as administrator"
echo.
echo The installer will:
echo 1. Install Npcap with WinPcap compatibility
echo 2. Enable packet capture for your application
echo 3. Restart your network monitoring
echo.
pause

echo.
echo Installing Npcap...
echo.

REM Run the installer with WinPcap compatibility mode
npcap-installer.exe /winpcap_mode=yes /npf_startup=yes /loopback_support=yes

if errorlevel 1 (
    echo.
    echo ERROR: Installation failed!
    echo Please run as Administrator and try again.
    echo.
    pause
    exit /b 1
)

echo.
echo SUCCESS: Npcap installed!
echo.
echo Installing Python bindings...
.\venv\Scripts\python -m pip install pypcap

echo.
echo Testing packet capture...
.\venv\Scripts\python -c "import scapy.all; print('Packet capture ready!')"

echo.
echo Installation complete! Now restart your app with start.bat
echo.
pause
