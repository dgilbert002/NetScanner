#!/bin/bash
# Cross-platform setup script for Linux/Raspberry Pi

echo "========================================"
echo "   NETSCANNER SETUP - LINUX/RASPBERRY PI"
echo "========================================"
echo ""

# Check if running as root for packet capture
if [ "$EUID" -ne 0 ]; then 
   echo "Note: Run as root (sudo) for packet capture capabilities"
fi

# Check Python version
echo "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✓ Python $PYTHON_VERSION found"
else
    echo "✗ Python 3 not found. Please install Python 3.8+"
    echo "  On Raspberry Pi: sudo apt-get install python3 python3-pip"
    exit 1
fi

# Install system dependencies for Raspberry Pi
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "raspbian" ]] || [[ "$ID" == "debian" ]] || [[ "$ID" == "ubuntu" ]]; then
        echo ""
        echo "Installing system dependencies..."
        sudo apt-get update
        sudo apt-get install -y python3-pip python3-venv libpcap-dev tcpdump
        echo "✓ System dependencies installed"
    fi
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Special handling for scapy on Raspberry Pi
echo ""
echo "Configuring packet capture..."
pip install scapy

# Set capabilities for Python to capture packets without root
if [ -f venv/bin/python ]; then
    sudo setcap cap_net_raw=eip venv/bin/python 2>/dev/null || true
    echo "✓ Packet capture capabilities configured"
fi

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p config scripts docs src/database
echo "✓ Directories created"

# Create systemd service for auto-start (optional)
if command -v systemctl &> /dev/null; then
    echo ""
    read -p "Create systemd service for auto-start? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /tmp/netscanner.service << EOF
[Unit]
Description=NetScanner Network Monitor
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python src/main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        sudo mv /tmp/netscanner.service /etc/systemd/system/
        sudo systemctl daemon-reload
        sudo systemctl enable netscanner.service
        echo "✓ Systemd service created and enabled"
        echo "  Start with: sudo systemctl start netscanner"
        echo "  Stop with: sudo systemctl stop netscanner"
        echo "  Status: sudo systemctl status netscanner"
    fi
fi

echo ""
echo "========================================"
echo "Setup complete!"
echo ""
echo "To start NetScanner:"
echo "  1. Run: ./start.sh"
echo "  2. Open browser to http://$(hostname -I | awk '{print $1}'):5002"
echo ""
echo "For packet capture, run as root:"
echo "  sudo ./start.sh"
echo "========================================"
