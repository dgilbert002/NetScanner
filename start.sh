#!/bin/bash
# Cross-platform start script for Linux/Raspberry Pi

echo "========================================"
echo "   NETSCANNER - NETWORK MONITOR"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found!"
    echo "Please run: ./setup.sh"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if running as root for better packet capture
if [ "$EUID" -eq 0 ]; then 
   echo "✓ Running as root - Full packet capture enabled"
else
   echo "⚠ Not running as root - Limited packet capture"
   echo "  For full capture, run: sudo ./start.sh"
fi

# Get IP address
IP_ADDR=$(hostname -I | awk '{print $1}')

echo ""
echo "Starting NetScanner..."
echo ""
echo "Access dashboard at:"
echo "  Local:  http://127.0.0.1:5000"
echo "  Network: http://$IP_ADDR:5000"
echo ""
echo "Features:"
echo "  ✓ Real-time packet capture"
echo "  ✓ Application categorization"
echo "  ✓ User/device analytics"
echo "  ✓ Comprehensive drill-down"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start the application
python src/main.py
