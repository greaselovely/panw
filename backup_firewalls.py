"""
PANW NGFW Configuration Backup Script
Backs up device state from Palo Alto Networks Next-Generation Firewalls
and manages firewall configurations in JSON file.
"""

import json
import requests
import xmltodict
from datetime import datetime
import urllib3
import argparse
import sys
import os
import tarfile
import time
import getpass

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PANWBackupManager:
    def __init__(self, config_file='config.json'):
        """Initialize the backup manager with configuration from JSON file."""
        self.config_file = config_file
        self.config = self.load_config()
        self.session = requests.Session()
        self.session.verify = False
        self.backup_dir = self._get_backup_dir()
        
    def load_config(self):
        """Load configuration from JSON file."""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Configuration file '{self.config_file}' not found. Creating new one...")
            return {"firewalls": {}}
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in configuration file '{self.config_file}'.")
            return None
    
    def save_config(self):
        """Save configuration to JSON file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False

    def _get_backup_dir(self):
        """Get backup directory from config, prompting user if not set."""
        if not self.config:
            self.config = {"firewalls": {}}

        # Check if backup_dir is already in config
        if 'backup_dir' in self.config and self.config['backup_dir']:
            backup_dir = self.config['backup_dir']
            # Validate the stored path still exists or can be created
            if os.path.isdir(backup_dir):
                return backup_dir
            # Path doesn't exist, ask to create it
            print(f"Configured backup directory '{backup_dir}' does not exist.")
            create = input("Create this directory? (Y/n): ").strip().lower()
            if create != 'n':
                try:
                    os.makedirs(backup_dir)
                    print(f"Created backup directory: {backup_dir}")
                    return backup_dir
                except OSError as e:
                    print(f"Error creating directory: {e}")
            # Fall through to prompt for new path

        # Prompt user for backup directory path
        print("\n=== Backup Directory Setup ===")
        while True:
            backup_dir = input("Enter backup directory path (default: ngfw_config): ").strip()
            if not backup_dir:
                backup_dir = 'ngfw_config'

            # Validate the path
            try:
                # Check for invalid characters (basic validation)
                # Try to normalize the path to catch obvious issues
                backup_dir = os.path.normpath(backup_dir)

                if os.path.isdir(backup_dir):
                    print(f"Using existing directory: {backup_dir}")
                    self.config['backup_dir'] = backup_dir
                    self.save_config()
                    return backup_dir

                # Path doesn't exist, ask to create
                create = input(f"Directory '{backup_dir}' does not exist. Create it? (Y/n): ").strip().lower()
                if create != 'n':
                    os.makedirs(backup_dir)
                    print(f"Created backup directory: {backup_dir}")
                    self.config['backup_dir'] = backup_dir
                    self.save_config()
                    return backup_dir
                else:
                    print("Please enter a different path.")
                    continue

            except OSError as e:
                print(f"Error: Invalid path '{backup_dir}' - {e}")
                print("Please enter a valid directory path.")
                continue

    def ensure_backup_directory(self):
        """Create backup directory if it doesn't exist."""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
            print(f"Created backup directory: {self.backup_dir}")
    
    def generate_api_key(self, firewall_ip, username, password):
        """Generate API key using username and password."""
        url = f"https://{firewall_ip}/api/"
        params = {
            'type': 'keygen',
            'user': username,
            'password': password
        }
        
        print(f"Generating API key for {firewall_ip}...")
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            result = xmltodict.parse(response.content)
            status = result.get('response', {}).get('@status')
            
            if status == 'success':
                api_key = result.get('response', {}).get('result', {}).get('key')
                if api_key:
                    print("API key generated successfully!")
                    return api_key
                else:
                    print("Error: No API key in response")
                    return None
            else:
                error_msg = result.get('response', {}).get('msg', 'Unknown error')
                print(f"Error generating API key: {error_msg}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to firewall {firewall_ip}: {e}")
            return None
        except Exception as e:
            print(f"Error parsing response: {e}")
            return None
    
    def get_system_info(self, firewall_ip, api_key):
        """Get system information including hostname."""
        url = f"https://{firewall_ip}/api/"
        params = {
            'type': 'op',
            'cmd': '<show><system><info></info></system></show>',
            'key': api_key
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            result = xmltodict.parse(response.content)
            status = result.get('response', {}).get('@status')
            
            if status == 'success':
                # Navigate through the XML structure to find hostname
                system_info = result.get('response', {}).get('result', {}).get('system', {})
                hostname = system_info.get('hostname')
                
                if hostname:
                    return hostname
                else:
                    print("Warning: Could not find hostname in system info")
                    return f"fw_{firewall_ip.replace('.', '_')}"
            else:
                error_msg = result.get('response', {}).get('msg', 'Unknown error')
                print(f"Error getting system info: {error_msg}")
                return f"fw_{firewall_ip.replace('.', '_')}"
                
        except Exception as e:
            print(f"Error getting system info: {e}")
            return f"fw_{firewall_ip.replace('.', '_')}"
    
    def send_backup_summary_notification(self, total_firewalls, successful_firewalls, failed_firewalls):
        """Send a single summary notification for all firewall backups."""
        if not self.config or 'notifications' not in self.config:
            return
        
        notifications = self.config['notifications']
        if not notifications.get('enabled', False):
            return
        
        success_count = len(successful_firewalls)
        failure_count = len(failed_firewalls)
        
        # Determine notification priority and title
        if failure_count == 0:
            title = "All Firewall Backups Complete"
            priority = "default"
        elif success_count == 0:
            title = "All Firewall Backups Failed"
            priority = "high"
        else:
            title = "Firewall Backups Partially Complete"
            priority = "default"
        
        # Build message
        message_parts = [f"Backup Summary: {success_count}/{total_firewalls} successful"]
            
        message = "".join(message_parts)
        
        self.send_notification(title, message, priority)
    
    def send_notification(self, title, message, priority="default"):
        """Send notification using ntfy if enabled in config."""
        if not self.config or 'notifications' not in self.config:
            return
        
        notifications = self.config['notifications']
        if not notifications.get('enabled', False):
            return
        
        ntfy_url = notifications.get('ntfy_url')
        customer_id = notifications.get('customer_id', 'PANW')
        
        if not ntfy_url:
            return
        
        try:
            # Format the message with customer ID
            formatted_title = f"[{customer_id}] {title}"
            
            headers = {
                'Title': formatted_title,
                'Priority': priority,
                'Tags': 'backup'
            }
            
            response = requests.post(ntfy_url, data=message, headers=headers, timeout=10, verify=False)
            response.raise_for_status()
            
        except Exception as e:
            print(f"Warning: Could not send notification: {e}")
    
    def backup_device_state(self, firewall_ip, api_key, hostname):
        """Backup device state configuration."""
        url = f"https://{firewall_ip}/api/"
        params = {
            'type': 'export',
            'category': 'device-state',
            'key': api_key
        }

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{hostname}_{timestamp_str}.tgz"
        filepath = os.path.join(self.backup_dir, filename)
        
        print(f"Backing up device state from {firewall_ip} to {filename}...")
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, params=params, timeout=300, stream=True)
                response.raise_for_status()
                
                # Check if response is actually a file (binary) or an error (XML)
                content_type = response.headers.get('content-type', '').lower()
                
                if 'xml' in content_type or response.content.startswith(b'<?xml'):
                    # This is likely an error response
                    try:
                        result = xmltodict.parse(response.content)
                        error_msg = result.get('response', {}).get('msg', 'Unknown error')
                        print(f"Error from firewall: {error_msg}")
                        if attempt < max_retries - 1:
                            print(f"Retrying in 5 seconds... (attempt {attempt + 2}/{max_retries})")
                            time.sleep(5)
                            continue
                        return False
                    except Exception:
                        pass  # Not XML, continue with file save
                
                # Save the backup file
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Verify the backup file
                if self.verify_backup(filepath):
                    print(f"Backup completed successfully: {filename}")
                    return True
                else:
                    print(f"Backup verification failed for {filename}")
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    if attempt < max_retries - 1:
                        print(f"Retrying in 5 seconds... (attempt {attempt + 2}/{max_retries})")
                        time.sleep(5)
                        continue
                    return False
                    
            except Exception as e:
                print(f"Error during backup attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    print(f"Retrying in 5 seconds... (attempt {attempt + 2}/{max_retries})")
                    time.sleep(5)
                else:
                    print(f"Failed to backup {firewall_ip} after {max_retries} attempts")
                    return False
        
        return False
    
    def verify_backup(self, filepath):
        """Verify that the backup file is valid by checking for configuration files."""
        try:
            if os.path.getsize(filepath) == 0:
                print("Backup file is empty")
                return False
            
            with tarfile.open(filepath, 'r:gz') as tar:
                members = tar.getnames()
                
                # Print first few files for debugging
                print(f"Archive contains {len(members)} files. First 10:")
                for i, member in enumerate(members[:10]):
                    print(f"  {i+1}. {member}")
                if len(members) > 10:
                    print(f"  ... and {len(members) - 10} more files")
                
                # Look for common configuration files that indicate a valid backup
                config_files = [
                    'running-config.xml',
                    'config/running-config.xml', 
                    'etc/running-config.xml',
                    'configuration.xml',
                    'config.xml'
                ]
                
                found_config = False
                for config_file in config_files:
                    if config_file in members:
                        print(f"Backup verification successful (found {config_file})")
                        found_config = True
                        break
                
                if not found_config:
                    # Check if any file contains 'config' in the name
                    config_like_files = [f for f in members if 'config' in f.lower()]
                    if config_like_files:
                        print(f"Found config-like files: {config_like_files[:5]}")
                        print("Backup appears valid (contains configuration files)")
                        return True
                    else:
                        print("Backup verification failed (no configuration files found)")
                        return False
                
                return found_config
                    
        except Exception as e:
            print(f"Error verifying backup: {e}")
            return False
    
    def add_firewall(self):
        """Interactive process to add a new firewall to the configuration."""
        if not self.config:
            self.config = {"firewalls": {}}
        
        print("\n=== Add New Firewall ===")
        
        # Get firewall IP
        while True:
            firewall_ip = input("Enter firewall IP address: ").strip()
            if firewall_ip:
                break
            print("IP address cannot be empty")
        
        # Check if firewall already exists
        if firewall_ip in self.config['firewalls']:
            print(f"Firewall {firewall_ip} already exists in configuration")
            overwrite = input("Overwrite existing configuration? (y/N): ").strip().lower()
            if overwrite != 'y':
                print("Cancelled")
                return False
        
        # Get credentials
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty")
            return False
        
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty")
            return False
        
        # Test connectivity and generate API key
        print(f"\nTesting connection to {firewall_ip}...")
        api_key = self.generate_api_key(firewall_ip, username, password)
        
        if not api_key:
            print("Failed to generate API key. Please check credentials and connectivity.")
            return False
        
        # Get hostname for verification
        hostname = self.get_system_info(firewall_ip, api_key)
        print(f"Connected successfully! Hostname: {hostname}")
        
        # Add to configuration
        current_time = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        self.config['firewalls'][firewall_ip] = {
            'api_key': api_key,
            'last_timestamp': current_time
        }
        
        # Save configuration
        if self.save_config():
            print(f"Firewall {firewall_ip} added successfully!")
            return True
        else:
            print("Failed to save configuration")
            return False
    
    def backup_all_firewalls(self):
        """Backup configuration from all firewalls."""
        if not self.config or 'firewalls' not in self.config:
            print("No firewalls configured. Use --add-firewall to add firewalls.")
            return False
        
        self.ensure_backup_directory()
        
        firewalls = self.config['firewalls']
        if not firewalls:
            print("No firewalls configured. Use --add-firewall to add firewalls.")
            return False
        
        print(f"Starting backup of {len(firewalls)} firewall(s)...")
        print("=" * 40)
        
        success_count = 0
        failed_firewalls = []
        successful_firewalls = []
        current_time = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        
        for firewall_ip, fw_config in firewalls.items():
            print(f"\n--- Backing up {firewall_ip} ---")
            
            api_key = fw_config.get('api_key')
            if not api_key:
                print(f"No API key found for {firewall_ip}")
                failed_firewalls.append(f"{firewall_ip} (No API key)")
                continue
            
            # Get current hostname (fresh from firewall each time)
            hostname = self.get_system_info(firewall_ip, api_key)
            
            # Perform backup
            if self.backup_device_state(firewall_ip, api_key, hostname):
                success_count += 1
                successful_firewalls.append(f"{hostname} ({firewall_ip})")
                # Update last backup time
                fw_config['last_backup'] = current_time
            else:
                print(f"Backup failed for {firewall_ip}")
                failed_firewalls.append(f"{hostname} ({firewall_ip})")
        
        # Save updated configuration
        self.save_config()
        
        # Send single summary notification
        self.send_backup_summary_notification(
            total_firewalls=len(firewalls),
            successful_firewalls=successful_firewalls,
            failed_firewalls=failed_firewalls
        )
        
        print(f"\n=== Backup Summary ===")
        print(f"Successful backups: {len(successful_firewalls)}/{len(firewalls)}")
        print(f"Backup directory: {os.path.abspath(self.backup_dir)}")
        
        return len(successful_firewalls) > 0
    
    def list_firewalls(self):
        """List all configured firewalls."""
        if not self.config or 'firewalls' not in self.config:
            print("No firewalls configured.")
            return
        
        firewalls = self.config['firewalls']
        if not firewalls:
            print("No firewalls configured.")
            return
        
        print("Configured firewalls:")
        for firewall_ip, fw_config in firewalls.items():
            last_backup = fw_config.get('last_backup', 'Never')
            last_timestamp = fw_config.get('last_timestamp', 'Unknown')
            print(f"  - {firewall_ip}")
            print(f"    Last backup: {last_backup}")
            print(f"    Last updated: {last_timestamp}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Backup PANW NGFW configurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Backup all configured firewalls
  %(prog)s --add-firewall     # Add a new firewall to configuration
  %(prog)s --list-firewalls   # List all configured firewalls
        """
    )
    
    parser.add_argument(
        '-a', '--add-firewall',
        action='store_true',
        help='Add a new firewall to the configuration'
    )
    
    parser.add_argument(
        '--list-firewalls',
        action='store_true',
        help='List all configured firewalls and exit'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    return parser.parse_args()


def main():
    """Main function to run the backup manager."""
    args = parse_arguments()
    
    # Initialize backup manager
    backup_manager = PANWBackupManager(args.config)
    
    # Handle list-firewalls option
    if args.list_firewalls:
        backup_manager.list_firewalls()
        return
    
    # Handle add-firewall option
    if args.add_firewall:
        success = backup_manager.add_firewall()
        sys.exit(0 if success else 1)
    
    # Default action: backup all firewalls
    print("PANW NGFW Configuration Backup")
    print("=" * 40)
    
    success = backup_manager.backup_all_firewalls()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()