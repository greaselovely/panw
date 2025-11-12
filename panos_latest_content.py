#!/usr/bin/env python3
"""
PAN-OS API Management Script
This script helps manage Palo Alto Networks devices by:
- Checking device connectivity
- Retrieving system information
- Downloading and installing content updates
- Storing device information in JSON format
"""

import requests
import urllib3
import urllib.parse
import socket
import getpass
import subprocess
import os
import sys
import json
import xmltodict
from time import sleep
from pathlib import Path

# Suppress insecure connection warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Output file in JSON format
INVENTORY_FILE = "inventory.json"
COMMIT_DESCRIPTION = ""


class PanosDevice:
    """Class to handle interactions with a Palo Alto Networks device"""
    
    def __init__(self, ip, username=None, password=None, port=443):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.api_key = None
        self.hostname = None
        self.model = None
        self.sw_version = None
        self.serial = None
    
    def is_reachable(self):
        """Check if device is reachable via ping"""
        if os.name == "nt":  # Windows
            command = f"ping -n 1 -w 2000 {self.ip}".split()
        elif sys.platform == "darwin":  # macOS
            command = f"ping -c 1 -t 2 {self.ip}".split()
        else:  # Linux and others
            command = f"ping -c 1 -w 2 {self.ip}".split()
        
        return subprocess.call(command, stdout=subprocess.DEVNULL) == 0
    
    def is_port_open(self):
        """Check if management port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((self.ip, self.port))
        sock.close()
        return result == 0
    
    def get_api_key(self):
        """Generate API key from credentials"""
        encoded_password = urllib.parse.quote_plus(self.password)
        url = f"https://{self.ip}:{self.port}/api/?type=keygen&user={self.username}&password={encoded_password}"
        
        try:
            response = requests.get(url, verify=False, timeout=10)
            
            if response.status_code == 403:
                print(f"[!] Not authorized for {self.ip}")
                return None
                
            key_dict = xmltodict.parse(response.text)
            self.api_key = key_dict.get('response').get('result').get('key')
            return self.api_key
        except Exception as e:
            print(f"[!] Error getting API key for {self.ip}: {e}")
            return None
    
    def get_system_info(self):
        """Get system information including hostname"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return None
            
        url = f'https://{self.ip}:{self.port}/api/?type=op&cmd=<show><system><info></info></system></show>&key={self.api_key}'
        
        try:
            response = requests.get(url, verify=False, timeout=10)
            sys_info = xmltodict.parse(response.text)
            system_data = sys_info.get('response').get('result').get('system')
            
            # Extract relevant system information
            self.hostname = system_data.get('hostname')
            self.model = system_data.get('model')
            self.sw_version = system_data.get('sw-version')
            self.serial = system_data.get('serial')
            
            return {
                "hostname": self.hostname,
                "model": self.model,
                "sw_version": self.sw_version,
                "serial": self.serial
            }
        except Exception as e:
            print(f"[!] Error getting system info for {self.ip}: {e}")
            return None
    
    def download_content_update(self):
        """Download latest content update"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return False
            
        url = f"https://{self.ip}:{self.port}/api/?&type=op&cmd=<request><content><upgrade><download><latest></latest></download></upgrade></content></request>&key={self.api_key}"
        
        try:
            response = requests.get(url, verify=False, timeout=30)
            print(f"[i] Content Update Download for {self.ip}: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Error downloading content update for {self.ip}: {e}")
            return False
    
    def install_content_update(self):
        """Install latest content update"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return False
            
        url = f"https://{self.ip}:{self.port}/api/?&type=op&cmd=<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>&key={self.api_key}"
        
        try:
            response = requests.get(url, verify=False, timeout=30)
            print(f"[i] Content Update Installation for {self.ip}: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Error installing content update for {self.ip}: {e}")
            return False
    
    def commit(self, description=""):
        """Commit configuration changes"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return False
            
        url = f"https://{self.ip}:{self.port}/api/?type=commit&cmd=<commit><description>{description}</description></commit>&key={self.api_key}"
        
        try:
            response = requests.post(url, verify=False, timeout=30)
            print(f"[i] Commit sent to {self.ip}: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Error committing changes for {self.ip}: {e}")
            return False
    
    def to_dict(self):
        """Convert device information to dictionary"""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "model": self.model,
            "sw_version": self.sw_version,
            "serial": self.serial,
            "api_key": self.api_key
        }


class InventoryManager:
    """Class to manage device inventory"""
    
    def __init__(self, inventory_file):
        self.inventory_file = inventory_file
        self.devices = {}
        self.load_inventory()
    
    def load_inventory(self):
        """Load inventory from file if it exists"""
        if os.path.exists(self.inventory_file):
            try:
                with open(self.inventory_file, 'r') as f:
                    self.devices = json.load(f)
                print(f"[i] Loaded existing inventory with {len(self.devices)} devices")
            except json.JSONDecodeError:
                print(f"[!] Error loading inventory file, starting with empty inventory")
                self.devices = {}
    
    def add_device(self, device):
        """Add device to inventory"""
        if not device.hostname:
            print(f"[!] Cannot add device {device.ip} without hostname")
            return False
        
        # Use IP as key for the inventory
        self.devices[device.ip] = device.to_dict()
        self.save_inventory()
        return True
    
    def save_inventory(self):
        """Save inventory to file"""
        try:
            with open(self.inventory_file, 'w') as f:
                json.dump(self.devices, f, indent=4)
            return True
        except Exception as e:
            print(f"[!] Error saving inventory: {e}")
            return False
    
    def get_device_count(self):
        """Get number of devices in inventory"""
        return len(self.devices)


def clear_screen():
    """Clear terminal screen"""
    os.system("cls" if os.name == "nt" else "clear")


def get_ip_list():
    """Get IP addresses from user input"""
    ip_list = []
    
    print("\n[?] Enter IP addresses (one per line, leave blank to finish):")
    while True:
        ip = input("> ").strip()
        if not ip:
            break
        ip_list.append(ip)
    
    return ip_list


def main():
    clear_screen()
    print("=== PAN-OS Device Management Tool ===\n")
    
    # Initialize inventory manager
    inventory = InventoryManager(INVENTORY_FILE)
    
    # Get IP addresses from user
    ip_list = get_ip_list()
    if not ip_list:
        print("[!] No IP addresses entered")
        sys.exit(1)
    
    print(f"\n[i] Processing {len(ip_list)} IP addresses")
    
    # Ask if credentials are the same across all devices
    same_creds = input("\n[?] Use the same credentials for all devices? (y/n): ").lower() == 'y'
    
    if same_creds:
        # Get credentials once
        username = input("[?] Enter username: ")
        password = getpass.getpass("[?] Enter password: ")
    
    # Process each device
    for ip in ip_list:
        print(f"\n[i] Processing {ip}")
        
        if not same_creds:
            # Get credentials for each device
            print(f"[?] Enter credentials for {ip}")
            username = input("[?] Username: ")
            password = getpass.getpass("[?] Password: ")
        
        # Create device object
        device = PanosDevice(ip, username, password)
        
        # Check connectivity
        if not device.is_reachable():
            print(f"[!] Cannot ping {ip}")
            continue
            
        if not device.is_port_open():
            print(f"[!] Port {device.port} is not open on {ip}")
            continue
        
        # Get API key
        if not device.get_api_key():
            continue
        
        # Get system info
        system_info = device.get_system_info()
        if system_info:
            print(f"[i] Connected to {device.hostname} ({device.model}, {device.sw_version})")
            
            # Add to inventory
            if inventory.add_device(device):
                print(f"[i] Added {device.hostname} to inventory")
        
        # Ask user if they want to perform content updates
        perform_updates = input(f"[?] Download content updates for {ip}? (y/n): ").lower() == 'y'
        if perform_updates:
            device.download_content_update()
            
            # Ask about installation
            install_updates = input(f"[?] Install content updates for {ip}? (y/n): ").lower() == 'y'
            if install_updates:
                device.install_content_update()
        
        # Ask about committing changes
        perform_commit = input(f"[?] Commit changes to {ip}? (y/n): ").lower() == 'y'
        if perform_commit:
            commit_desc = input("[?] Enter commit description (optional): ")
            device.commit(commit_desc or COMMIT_DESCRIPTION)
    
    print(f"\n[i] Inventory saved to {INVENTORY_FILE} with {inventory.get_device_count()} devices")
    print("=== Process completed ===")


if __name__ == "__main__":
    main()