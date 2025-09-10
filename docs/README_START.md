# NetScanner Application - Quick Start Guide

## 🚀 How to Start the Application

I've created several start scripts to make it easy to launch your NetScanner application. Choose the method that works best for you:

### Option 1: Windows Batch Files (Recommended)
**For Base Features (Default):**
```bash
# Double-click or run from command prompt:
start_app.bat
```

**For Enhanced Features:**
```bash
# Double-click or run from command prompt:
start_enhanced.bat
```

### Option 2: PowerShell Scripts
**For Base Features:**
```powershell
# Right-click and "Run with PowerShell" or run from command prompt:
.\start_app.ps1
```

**For Enhanced Features:**
```powershell
# Right-click and "Run with PowerShell" or run from command prompt:
.\start_enhanced.ps1
```

### Option 3: Manual Command Line
**For Base Features:**
```bash
.\venv\Scripts\python.exe .\src\main.py
```

**For Enhanced Features:**
```bash
set ENABLE_ENHANCED=1
.\venv\Scripts\python.exe .\src\main.py
```

## 🌐 Access Your Application

Once started, you can access the NetScanner application at:
- **Local**: http://127.0.0.1:5000
- **Network**: http://192.168.50.45:5000 (or your local IP)

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
- Make sure port 5000 is not being used by another application

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
2. **Open your browser** and go to http://127.0.0.1:5000
3. **Enjoy** your NetScanner application!

For enhanced features, use `start_enhanced.bat` instead.
