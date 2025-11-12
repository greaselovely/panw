#!/usr/bin/env python3
"""
PAN-OS DHCP Relay Configuration Script
This script configures DHCP relay servers on Palo Alto Networks devices by:
- Loading device information from inventory.json
- Identifying interfaces with DHCP configurations
- Configuring new DHCP relay servers
- Committing the changes
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
import xml.etree.ElementTree as ET
from pathlib import Path

# Suppress insecure connection warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File paths
INVENTORY_FILE = "inventory.json"
COMMIT_DESCRIPTION = "Updated DHCP relay servers"

# DHCP relay servers - configure these as needed
DHCP_SERVERS = ["10.11.12.13", "10.11.12.14"]


class PanosDevice:
    """Class to handle interactions with a Palo Alto Networks device"""
    
    def __init__(self, ip, username=None, password=None, api_key=None, port=443):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.api_key = api_key
        self.hostname = None
        self.interfaces = []
    
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
        # If we already have an API key, return it
        if self.api_key:
            return self.api_key
            
        # Otherwise generate a new one
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
            
            # Extract hostname
            self.hostname = system_data.get('hostname')
            print(f"[i] Connected to {self.hostname} ({self.ip})")
            
            return system_data
        except Exception as e:
            print(f"[!] Error getting system info for {self.ip}: {e}")
            return None
    
    def get_dhcp_config(self):
        """Get DHCP configuration"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return None
            
        url = f'https://{self.ip}:{self.port}/api/?type=op&cmd=<show><config><running><xpath>devices/entry[@name="localhost.localdomain"]/network/dhcp</xpath></running></config></show>&key={self.api_key}'
        
        try:
            response = requests.get(url, verify=False, timeout=10)
            return response.text
        except Exception as e:
            print(f"[!] Error getting DHCP config for {self.ip}: {e}")
            return None
    
    def parse_dhcp_interfaces(self, config_xml):
        """Parse DHCP configuration to extract interfaces"""
        self.interfaces = []
        
        try:
            tree = ET.fromstring(config_xml)
            for entry in tree.iter('entry'):
                interface_name = entry.attrib.get('name')
                if interface_name and "ethernet" in interface_name:
                    self.interfaces.append(interface_name)
            
            if self.interfaces:
                print(f"[i] Found {len(self.interfaces)} interfaces with DHCP configuration")
                for interface in self.interfaces:
                    print(f"    - {interface}")
            else:
                print(f"[i] No interfaces with DHCP configuration found")
                
            return self.interfaces
        except Exception as e:
            print(f"[!] Error parsing DHCP interfaces: {e}")
            return []
    
    def set_dhcp_relay_servers(self, servers):
        """Configure DHCP relay servers on interfaces"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return False
            
        if not self.interfaces:
            print(f"[!] No interfaces to configure on {self.ip}")
            return False
        
        success = True
        
        for interface in self.interfaces:
            for server in servers:
                print(f"[i] Adding DHCP relay server {server} to {interface}")
                
                url = f"https://{self.ip}:{self.port}/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/dhcp/interface/entry[@name='{interface}']/relay/ip/server&element=<member>{server}</member>&key={self.api_key}"
                
                try:
                    response = requests.post(url, verify=False, timeout=10)
                    
                    if response.status_code == 200:
                        print(f"    - Success")
                    else:
                        print(f"    - Failed: {response.status_code}")
                        success = False
                except Exception as e:
                    print(f"    - Error: {e}")
                    success = False
        
        return success
    
    def commit(self, description=""):
        """Commit configuration changes"""
        if not self.api_key:
            print(f"[!] No API key available for {self.ip}")
            return False
            
        url = f"https://{self.ip}:{self.port}/api/?type=commit&cmd=<commit><description>{description}</description></commit>&key={self.api_key}"
        
        try:
            response = requests.post(url, verify=False, timeout=30)
            
            if response.status_code == 200:
                print(f"[i] Commit sent to {self.ip}")
                return True
            else:
                print(f"[!] Commit failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[!] Error committing changes for {self.ip}: {e}")
            return False


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
                print(f"[i] Loaded inventory with {len(self.devices)} devices")
                return True
            except json.JSONDecodeError:
                print(f"[!] Error loading inventory file")
                self.devices = {}
                return False
        else:
            print(f"[!] Inventory file not found: {self.inventory_file}")
            return False
    
    def update_device(self, device):
        """Update device in inventory"""
        if not device.hostname:
            print(f"[!] Cannot update device {device.ip} without hostname")
            return False
        
        # Use IP as key for the inventory
        self.devices[device.ip] = {
            "ip": device.ip,
            "hostname": device.hostname,
            "api_key": device.api_key
        }
        
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
    
    def get_device_ips(self):
        """Get list of device IPs in inventory"""
        return list(self.devices.keys())
    
    def get_device_info(self, ip):
        """Get device info from inventory"""
        return self.devices.get(ip)


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
    print("=== PAN-OS DHCP Relay Configuration Tool ===\n")
    
    # Initialize inventory manager
    inventory = InventoryManager(INVENTORY_FILE)
    
    # Decide how to get IP addresses
    use_inventory = input("[?] Use devices from inventory.json? (y/n): ").lower() == 'y'
    
    if use_inventory:
        # Get IPs from inventory
        ip_list = inventory.get_device_ips()
        if not ip_list:
            print("[!] No devices found in inventory")
            print("[i] You'll need to enter IP addresses manually")
            use_inventory = False
        else:
            print(f"[i] Found {len(ip_list)} devices in inventory")
            for ip in ip_list:
                device_info = inventory.get_device_info(ip)
                print(f"    - {device_info.get('hostname')} ({ip})")
            
            # Ask which devices to configure
            configure_all = input("[?] Configure all devices? (y/n): ").lower() == 'y'
            if not configure_all:
                selected_ips = []
                for ip in ip_list:
                    device_info = inventory.get_device_info(ip)
                    if input(f"[?] Configure {device_info.get('hostname')} ({ip})? (y/n): ").lower() == 'y':
                        selected_ips.append(ip)
                ip_list = selected_ips
    
    if not use_inventory:
        # Get IPs manually
        ip_list = get_ip_list()
        if not ip_list:
            print("[!] No IP addresses entered")
            sys.exit(1)
    
    print(f"\n[i] Will configure {len(ip_list)} devices")
    
    # Ask if credentials are the same across all devices
    if not use_inventory:
        same_creds = input("\n[?] Use the same credentials for all devices? (y/n): ").lower() == 'y'
        
        if same_creds:
            # Get credentials once
            username = input("[?] Enter username: ")
            password = getpass.getpass("[?] Enter password: ")
    
    # Ask about DHCP servers
    custom_servers = input(f"[?] Use default DHCP servers {DHCP_SERVERS}? (y/n): ").lower() != 'y'
    if custom_servers:
        servers = []
        print("[?] Enter DHCP server IPs (one per line, leave blank to finish):")
        while True:
            server = input("> ").strip()
            if not server:
                break
            servers.append(server)
        
        if servers:
            DHCP_SERVERS.clear()
            DHCP_SERVERS.extend(servers)
    
    print(f"[i] Using DHCP servers: {', '.join(DHCP_SERVERS)}")
    
    # Ask about commit description
    commit_description = COMMIT_DESCRIPTION  # Use a local variable
    custom_desc = input(f"[?] Use default commit description? ({commit_description}) (y/n): ").lower() != 'y'
    if custom_desc:
        desc = input("[?] Enter commit description: ").strip()
        if desc:
            commit_description = desc
    
    # Process each device
    for ip in ip_list:
        print(f"\n[i] Processing {ip}")
        
        device_info = None
        if use_inventory:
            device_info = inventory.get_device_info(ip)
        
        if device_info and device_info.get('api_key'):
            # Create device with API key from inventory
            device = PanosDevice(
                ip, 
                api_key=device_info.get('api_key')
            )
            device.hostname = device_info.get('hostname')
            print(f"[i] Using API key from inventory for {device.hostname} ({ip})")
        else:
            # Need to authenticate
            if not 'username' in locals():
                username = input(f"[?] Enter username for {ip}: ")
                password = getpass.getpass(f"[?] Enter password for {ip}: ")
            
            # Create device with credentials
            device = PanosDevice(ip, username, password)
        
        # Check connectivity
        if not device.is_reachable():
            print(f"[!] Cannot ping {ip}")
            continue
            
        if not device.is_port_open():
            print(f"[!] Port {device.port} is not open on {ip}")
            continue
        
        # Get API key if needed
        if not device.api_key:
            if not device.get_api_key():
                continue
        
        # Get system info
        device.get_system_info()
        
        # Get DHCP configuration
        dhcp_config = device.get_dhcp_config()
        if not dhcp_config:
            continue
        
        # Parse interfaces
        if not device.parse_dhcp_interfaces(dhcp_config):
            continue
        
        # Configure DHCP relay servers
        if not device.interfaces:
            print(f"[i] No DHCP interfaces found on {ip}")
            continue
        
        proceed = input(f"[?] Configure DHCP relay on {len(device.interfaces)} interfaces? (y/n): ").lower() == 'y'
        if not proceed:
            continue
        
        if device.set_dhcp_relay_servers(DHCP_SERVERS):
            # Commit changes
            commit = input(f"[?] Commit changes to {device.hostname} ({ip})? (y/n): ").lower() == 'y'
            if commit:
                device.commit(commit_description)
            
            # Update inventory with API key if needed
            if not device_info or not device_info.get('api_key'):
                inventory.update_device(device)
                print(f"[i] Updated inventory with {device.hostname} ({ip})")
    
    print("\n=== Configuration completed ===")


if __name__ == "__main__":
    main()