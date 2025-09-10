#!/usr/bin/env python3
"""
Automatic Npcap installation and setup for Windows
"""

import os
import sys
import subprocess
import urllib.request
import tempfile
import shutil
from pathlib import Path

def download_npcap():
    """Download Npcap installer"""
    print("🔽 Downloading Npcap installer...")
    
    # Npcap download URL (latest version)
    npcap_url = "https://npcap.com/dist/npcap-1.79.exe"
    npcap_file = "npcap-installer.exe"
    
    try:
        urllib.request.urlretrieve(npcap_url, npcap_file)
        print(f"✅ Downloaded {npcap_file}")
        return npcap_file
    except Exception as e:
        print(f"❌ Failed to download Npcap: {e}")
        return None

def install_npcap(installer_path):
    """Install Npcap with WinPcap compatibility mode"""
    print("🔧 Installing Npcap...")
    print("⚠️  This requires Administrator privileges!")
    
    try:
        # Run installer with WinPcap compatibility mode
        cmd = [
            installer_path,
            "/winpcap_mode=yes",  # Enable WinPcap compatibility
            "/npf_startup=yes",   # Start Npcap service
            "/loopback_support=yes"  # Enable loopback support
        ]
        
        print("Running installer...")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✅ Npcap installed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        print("Please run as Administrator and try again")
        return False
    except Exception as e:
        print(f"❌ Error during installation: {e}")
        return False

def install_python_bindings():
    """Install Python bindings for Npcap"""
    print("🐍 Installing Python bindings...")
    
    try:
        # Try to install pypcap
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "pypcap"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ pypcap installed successfully!")
            return True
        else:
            print("⚠️  pypcap installation failed, trying alternative...")
            
            # Try installing from source
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "https://github.com/pynetwork/pypcap/archive/master.zip"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ pypcap installed from source!")
                return True
            else:
                print("❌ Failed to install pypcap")
                return False
                
    except Exception as e:
        print(f"❌ Error installing Python bindings: {e}")
        return False

def test_packet_capture():
    """Test if packet capture is working"""
    print("🧪 Testing packet capture...")
    
    try:
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP
        
        # Try to get network interfaces
        interfaces = scapy.get_if_list()
        print(f"📡 Found {len(interfaces)} network interfaces:")
        for iface in interfaces:
            print(f"   - {iface}")
            
        if interfaces:
            print("✅ Packet capture should work now!")
            return True
        else:
            print("❌ No network interfaces found")
            return False
            
    except ImportError as e:
        print(f"❌ Scapy import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Packet capture test failed: {e}")
        return False

def main():
    print("=" * 60)
    print("           AUTOMATIC NPCAP INSTALLATION")
    print("=" * 60)
    print()
    
    # Check if already running as admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️  WARNING: Not running as Administrator!")
            print("   For best results, run this script as Administrator")
            print("   Right-click Command Prompt → 'Run as administrator'")
            print()
    except:
        pass
    
    # Step 1: Download Npcap
    installer = download_npcap()
    if not installer:
        print("❌ Cannot proceed without Npcap installer")
        return False
    
    # Step 2: Install Npcap
    if not install_npcap(installer):
        print("❌ Npcap installation failed")
        return False
    
    # Step 3: Install Python bindings
    if not install_python_bindings():
        print("⚠️  Python bindings installation failed, but Npcap is installed")
        print("   You may need to restart your application")
    
    # Step 4: Test packet capture
    if test_packet_capture():
        print()
        print("🎉 SUCCESS! Real packet capture is now enabled!")
        print("   Restart your application with: start.bat")
    else:
        print()
        print("⚠️  Installation complete, but packet capture test failed")
        print("   Try restarting your computer and running start.bat")
    
    # Cleanup
    try:
        os.remove(installer)
        print(f"🧹 Cleaned up {installer}")
    except:
        pass
    
    print()
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
