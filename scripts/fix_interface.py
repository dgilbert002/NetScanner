#!/usr/bin/env python3
"""
Quick fix script to update the network interface for Windows
"""

import os
import sys
import subprocess
import platform

def get_windows_interface():
    """Get the active network interface on Windows"""
    try:
        # Get network adapters using PowerShell
        result = subprocess.run([
            'powershell', '-Command', 
            'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1 -ExpandProperty Name'
        ], capture_output=True, text=True, check=True)
        
        interface = result.stdout.strip()
        if interface:
            print(f"Found active interface: {interface}")
            return interface
    except Exception as e:
        print(f"Error detecting interface: {e}")
    
    # Fallback to common Windows interfaces
    fallbacks = ['WiFi', 'Ethernet', 'Local Area Connection']
    for fallback in fallbacks:
        print(f"Trying fallback interface: {fallback}")
        return fallback
    
    return 'eth0'  # Ultimate fallback

def update_main_py():
    """Update main.py to use the correct interface"""
    main_py_path = 'src/main.py'
    
    if not os.path.exists(main_py_path):
        print(f"Error: {main_py_path} not found")
        return False
    
    # Read the file
    with open(main_py_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Get the correct interface
    interface = get_windows_interface()
    
    # Replace hardcoded eth0 with the detected interface
    updated_content = content.replace("interface='eth0'", f"interface='{interface}'")
    
    # Write back
    with open(main_py_path, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print(f"Updated {main_py_path} to use interface: {interface}")
    return True

def main():
    print("🔧 Fixing network interface for Windows...")
    
    if platform.system() != 'Windows':
        print("This script is designed for Windows. Skipping interface detection.")
        return
    
    if update_main_py():
        print("✅ Interface updated successfully!")
        print("\nNow restart your app to use the correct network interface.")
    else:
        print("❌ Failed to update interface")

if __name__ == '__main__':
    main()
