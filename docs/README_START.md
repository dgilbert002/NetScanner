# NetScanner Application - Quick Start Guide

## 🚀 How to Start the Application

Starting NetScanner is now super simple! Just use one file:

### Single Start Method
**Double-click `start.bat`** - This will:
- Start the NetScanner server on port 5002
- Automatically open your web browser to the dashboard
- Show you the command window (press any key to stop the server)

### Manual Command Line (Alternative)
```bash
.\venv\Scripts\python.exe .\src\main.py
```
Then manually open http://127.0.0.1:5002 in your browser.

## 🌐 Access Your Application

Once started, you can access the NetScanner application at:
- **Local**: http://127.0.0.1:5002
- **Network**: http://192.168.50.45:5002 (or your local IP)

## 📋 What Each Script Does

### Base Features Scripts (`start_app.bat` / `start_app.ps1`)
- ✅ Checks if virtual environment exists
- ✅ Verifies dependencies are installed
- ✅ Starts the app with base features only
- ✅ Shows access URLs
- ✅ Handles errors gracefully

### Enhanced Features Scripts (`start_enhanced.bat` / `start_enhanced.ps1`)
- ✅ All base features plus:
- ✅ Advanced device management
- ✅ Detailed traffic analysis
- ✅ Website analytics
- ✅ Content analysis
- ✅ User activity timeline

## 🔧 Troubleshooting

**If you get "Virtual environment not found":**
- Make sure you're in the project root directory
- The `venv` folder should exist

**If you get "Failed to install dependencies":**
- Check your internet connection
- Make sure Python is installed correctly

**If the app doesn't start:**
- Check the error messages in the terminal
- Make sure port 5002 is not being used by another application

## 📁 File Structure
```
network-monitor/
├── start_app.bat          # Windows batch - base features
├── start_enhanced.bat     # Windows batch - enhanced features
├── start_app.ps1          # PowerShell - base features
├── start_enhanced.ps1     # PowerShell - enhanced features
├── venv/                  # Virtual environment
├── src/                   # Source code
└── requirements.txt       # Dependencies
```

## 🎯 Quick Start
1. **Double-click** `start_app.bat` to start with base features
2. **Open your browser** and go to http://127.0.0.1:5002
3. **Enjoy** your NetScanner application!

For enhanced features, use `start_enhanced.bat` instead.
