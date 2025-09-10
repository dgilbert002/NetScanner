# NetScanner - Enhanced Network Monitor

A real-time network monitoring dashboard with live packet capture, device discovery, and traffic analysis.

## 🚀 Quick Start

### First Time Setup
1. **Double-click `setup.bat`** - This will install everything you need
2. **Double-click `start.bat`** - This launches the server AND opens your browser automatically!

### Daily Use
Just **double-click `start.bat`** - it handles everything automatically!
- Starts the server on port 5002
- Opens your web browser to the dashboard
- Press any key in the command window to stop the server

## 📁 Project Structure

```
network-monitor/
├── start.bat              # 🚀 MAIN LAUNCHER - Double-click this!
├── setup.bat              # 🛠️ First-time setup (run once)
├── requirements.txt       # Python dependencies
│
├── src/                   # 📦 Source Code
│   ├── main.py           # Flask application entry point
│   ├── models/           # Database models
│   ├── routes/           # API endpoints
│   ├── static/           # Web dashboard files
│   └── database/         # SQLite database files
│
├── scripts/              # 🔧 Utility Scripts
│   ├── clear_demo_data.py
│   ├── fix_interface.py
│   └── [old start scripts]
│
├── docs/                 # 📚 Documentation
│   ├── ROADMAP.md
│   └── README_START.md
│
└── venv/                 # 🐍 Python Virtual Environment
```

## ✨ Features

- **🔍 Real-Time Packet Capture** - Live network traffic monitoring
- **📱 Device Discovery** - Automatically detect devices on your network
- **📊 Traffic Analysis** - Protocol breakdown, data usage, top domains
- **🌐 Web Dashboard** - Beautiful, responsive interface
- **⚡ Live Updates** - Data refreshes every 5 seconds
- **🛡️ Windows Compatible** - Optimized for Windows networks

## 🎯 How It Works

1. **Packet Capture** - Uses scapy to capture real network packets
2. **Data Processing** - Analyzes protocols, domains, and traffic patterns
3. **Database Storage** - Stores discovered devices and traffic sessions
4. **Web Dashboard** - Displays live data in an easy-to-read format

## 🔧 Technical Details

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Packet Capture**: Scapy
- **Frontend**: HTML5, CSS3, JavaScript
- **Network Interface**: Auto-detects WiFi/Ethernet

## 🚨 Troubleshooting

### Packet Capture Not Working
- **Run as Administrator** - Right-click Command Prompt → "Run as administrator"
- **Windows Firewall** - Allow the application when prompted
- **Antivirus** - May need to whitelist the application

### No Data Appearing
- **Click "Start Real Monitoring"** in the dashboard
- **Browse some websites** to generate traffic
- **Check network interface** - Should auto-detect WiFi/Ethernet

### App Won't Start
- **Run `setup.bat`** first if you haven't already
- **Check Python installation** - Need Python 3.8+
- **Check port 5002** - Make sure it's not being used by another app

## 📊 Dashboard Features

- **Live Statistics** - Packets captured, bytes transferred, active devices
- **Device List** - Discovered devices with IP addresses and hostnames
- **Traffic Summary** - Protocol breakdown and data usage
- **Top Domains** - Most visited websites
- **Recent Activity** - Live feed of network activity

## 🔒 Security & Privacy

- **Local Only** - All data stays on your computer
- **No Cloud** - No data is sent to external servers
- **Real-Time** - Data is processed and displayed locally
- **Admin Required** - Packet capture needs administrator privileges

## 📝 License

This project is for educational and personal use. Please respect your local laws regarding network monitoring.

## 🤝 Support

If you encounter any issues:
1. Check the troubleshooting section above
2. Make sure you're running as Administrator
3. Verify your network interface is detected correctly
4. Check that port 5002 is available

---

**Ready to monitor your network? Just double-click `start.bat` and go!** 🚀
