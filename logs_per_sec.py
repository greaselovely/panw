#!/usr/bin/env python3
"""
PAN-OS Log Analysis Script
This script retrieves logs from Palo Alto Networks firewalls and calculates 
logs per second over specific time frames, with visualization capabilities.
"""

import csv
import json
import re
import os
import time
import logging
import argparse
from getpass import getpass
from collections import defaultdict
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import xml.etree.ElementTree as ET
from pan.xapi import PanXapi

# Set up logging
logging.basicConfig(
    filename='panos_log_analysis.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Constants
DEFAULT_LOG_COUNT = 1000  # Reduced from 5000 to improve reliability
DEFAULT_LOG_TYPE = "traffic"
DEFAULT_INTERVAL_MINUTES = 15
JOB_POLL_INTERVAL = 5  # seconds
MAX_JOB_WAIT_TIME = 300  # seconds
DEFAULT_OUTPUT_FILE = "panos_logs.csv"
DEFAULT_GRAPH_FILE = "log_analysis.png"
DEFAULT_TIMEOUT = 60  # seconds for API calls
MAX_RETRIES = 3  # number of retries for API calls


class PanosLogAnalyzer:
    """Class for analyzing Palo Alto Networks firewall logs"""
    
    def __init__(self, hostname=None, username=None, password=None, use_inventory=False):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.api = None
        self.inventory_file = "inventory.json"
        self.use_inventory = use_inventory
        self.inventory = {}
        
        if use_inventory:
            self.load_inventory()
    
    def load_inventory(self):
        """Load device inventory from JSON file"""
        if os.path.exists(self.inventory_file):
            try:
                with open(self.inventory_file, 'r') as f:
                    self.inventory = json.load(f)
                logging.info(f"Loaded inventory with {len(self.inventory)} devices")
                return True
            except json.JSONDecodeError:
                logging.error("Error loading inventory file")
                return False
        else:
            logging.warning(f"Inventory file not found: {self.inventory_file}")
            return False
    
    def connect(self, hostname=None, username=None, password=None, api_key=None, timeout=30, max_retries=3):
        """Connect to PAN-OS device with retry logic"""
        if hostname:
            self.hostname = hostname
        if username:
            self.username = username
        if password:
            self.password = password
        
        retries = 0
        while retries < max_retries:
            try:
                print(f"Connecting to {self.hostname} (attempt {retries+1}/{max_retries})...")
                
                if api_key:
                    logging.info(f"Connecting to {self.hostname} using API key")
                    self.api = PanXapi(hostname=self.hostname, api_key=api_key, timeout=timeout)
                else:
                    logging.info(f"Connecting to {self.hostname} using username/password")
                    self.api = PanXapi(
                        hostname=self.hostname,
                        api_username=self.username,
                        api_password=self.password,
                        timeout=timeout
                    )
                
                # Test connection with a simple API call
                self.api.op(cmd="<show><system><info></info></system></show>")
                
                print(f"Successfully connected to {self.hostname}")
                return True
                
            except Exception as e:
                retries += 1
                logging.warning(f"Connection attempt {retries} failed: {str(e)}")
                print(f"Connection attempt {retries} failed: {str(e)}")
                
                if retries < max_retries:
                    wait_time = retries * 5  # Increasing backoff
                    print(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logging.error(f"Failed to connect to {self.hostname} after {max_retries} attempts")
                    print(f"Failed to connect to {self.hostname} after {max_retries} attempts")
                    return False
    
    def connect_from_inventory(self, ip):
        """Connect to device using credentials from inventory"""
        if not self.inventory:
            logging.error("No inventory loaded")
            return False
            
        device = self.inventory.get(ip)
        if not device:
            logging.error(f"Device {ip} not found in inventory")
            return False
            
        api_key = device.get('api_key')
        if not api_key:
            logging.error(f"No API key found for {ip} in inventory")
            return False
            
        return self.connect(hostname=ip, api_key=api_key)
    
    def submit_log_query(self, log_type="traffic", nlogs=1000, query=None, time_frame=None, max_retries=3):
        """Submit log query job to PAN-OS with retry logic"""
        if not self.api:
            logging.error("Not connected to firewall")
            return None
        
        retries = 0
        while retries < max_retries:
            try:
                # Build query parameters
                params = {}
                
                if query:
                    params["query"] = query
                    
                if time_frame:
                    params["dir"] = "backward"
                    params["time-generated"] = time_frame
                
                # Submit the log query job
                print(f"Submitting log query (attempt {retries+1}/{max_retries})...")
                logging.info(f"Submitting log query for {log_type} logs (count: {nlogs})")
                self.api.log(log_type=log_type, nlogs=str(nlogs), **params)
                response = self.api.xml_result()
                
                # Save raw response for debugging
                with open('log_query_response.xml', 'w') as f:
                    f.write(response)
                    
                # Extract job ID
                try:
                    root = ET.fromstring(response)
                    job_id = root.find('.//job').text
                    logging.info(f"Log query job submitted. Job ID: {job_id}")
                    return job_id
                except (ET.ParseError, AttributeError) as e:
                    # Fallback to regex if XML parsing fails
                    match = re.search(r'<job>(.*?)</job>', response)
                    if match:
                        job_id = match.group(1)
                        logging.info(f"Log query job submitted. Job ID: {job_id}")
                        return job_id
                    else:
                        logging.error("Failed to extract job ID from response")
                        raise ValueError("Cannot extract job ID from response")
                    
            except Exception as e:
                retries += 1
                logging.warning(f"Query submission attempt {retries} failed: {str(e)}")
                print(f"Query attempt {retries} failed: {str(e)}")
                
                if retries < max_retries:
                    wait_time = retries * 3  # Increasing backoff
                    print(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logging.error(f"Failed to submit query after {max_retries} attempts")
                    print(f"Failed to submit query after {max_retries} attempts")
                    return None
    
    def check_job_status(self, job_id):
        """Check status of a job"""
        if not self.api:
            logging.error("Not connected to firewall")
            return None
            
        try:
            logging.info(f"Checking status for job {job_id}")
            self.api.op(cmd=f"<show><jobs><id>{job_id}</id></jobs></show>")
            response = self.api.xml_result()
            
            # Parse the response
            try:
                root = ET.fromstring(response)
                status_elem = root.find('.//status')
                
                if status_elem is not None:
                    status = status_elem.text
                    logging.info(f"Job {job_id} status: {status}")
                    return status
                else:
                    logging.warning("Status element not found in job status response")
                    return None
            except ET.ParseError:
                logging.error("Failed to parse job status XML")
                return None
                
        except Exception as e:
            logging.error(f"Error checking job status: {str(e)}")
            return None
    
    def wait_for_job_completion(self, job_id, timeout=MAX_JOB_WAIT_TIME):
        """Wait for job to complete with timeout"""
        start_time = time.time()
        elapsed = 0
        
        print(f"Waiting for job {job_id} to complete...")
        
        while elapsed < timeout:
            status = self.check_job_status(job_id)
            
            if status == "FIN":
                print(f"Job completed in {elapsed:.1f} seconds")
                return True
                
            elapsed = time.time() - start_time
            remaining = timeout - elapsed
            
            print(f"Job status: {status}, waiting... ({elapsed:.1f}s elapsed, timeout in {remaining:.1f}s)")
            
            # Sleep before next check
            time.sleep(min(JOB_POLL_INTERVAL, remaining))
        
        logging.error(f"Job {job_id} timed out after {timeout} seconds")
        print(f"Job timed out after {timeout} seconds")
        return False
    
    def get_job_results(self, job_id):
        """Retrieve results for a completed job"""
        if not self.api:
            logging.error("Not connected to firewall")
            return None
            
        try:
            logging.info(f"Retrieving results for job {job_id}")
            self.api.log(action="get", jobid=job_id)
            response = self.api.xml_result()
            
            # Save raw results for debugging
            with open('job_results.xml', 'w') as f:
                f.write(response)
                
            return response
        except Exception as e:
            logging.error(f"Error retrieving job results: {str(e)}")
            print(f"Error retrieving job results: {str(e)}")
            return None
    
    def parse_log_entries(self, xml_logs):
        """Parse log entries from XML response"""
        logs = []
        
        try:
            # Try to parse as XML first
            root = ET.fromstring(xml_logs)
            entries = root.findall('.//entry')
            
            for entry in entries:
                log_entry = {}
                for child in entry:
                    log_entry[child.tag] = child.text
                logs.append(log_entry)
                
            logging.info(f"Successfully parsed {len(logs)} log entries using XML parser")
            
        except ET.ParseError:
            # Fallback to regex parsing
            logging.warning("XML parsing failed, falling back to regex")
            
            entries = re.findall(r'<entry.*?</entry>', xml_logs, re.DOTALL)
            for entry in entries:
                log_entry = {}
                
                # Extract common fields
                for field in ['receive_time', 'time_generated', 'type', 'subtype', 'action']:
                    match = re.search(f'<{field}>(.*?)</{field}>', entry)
                    if match:
                        log_entry[field] = match.group(1)
                        
                logs.append(log_entry)
                
            logging.info(f"Successfully parsed {len(logs)} log entries using regex")
            
        return logs
    
    def get_logs(self, log_type="traffic", nlogs=1000, query=None, time_frame=None):
        """Get logs from PAN-OS device"""
        job_id = self.submit_log_query(log_type, nlogs, query, time_frame)
        if not job_id:
            return None
            
        if self.wait_for_job_completion(job_id):
            results = self.get_job_results(job_id)
            if results:
                return self.parse_log_entries(results)
            
        return None
    
    def save_logs_to_csv(self, logs, filename):
        """Save logs to CSV file"""
        if not logs:
            logging.warning("No logs to save")
            print("No logs to save.")
            return False
            
        try:
            # Get all unique field names across all logs
            fieldnames = set()
            for log in logs:
                fieldnames.update(log.keys())
                
            # Convert to sorted list
            fieldnames = sorted(fieldnames)
            
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for log in logs:
                    writer.writerow(log)
                    
            logging.info(f"Saved {len(logs)} logs to {filename}")
            print(f"Saved {len(logs)} logs to {filename}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving logs to CSV: {str(e)}")
            print(f"Error saving logs to CSV: {str(e)}")
            return False
    
    def load_logs_from_csv(self, filename):
        """Load logs from CSV file"""
        logs = []
        
        try:
            with open(filename, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                logs = list(reader)
                
            logging.info(f"Loaded {len(logs)} logs from {filename}")
            print(f"Loaded {len(logs)} logs from {filename}")
            return logs
            
        except Exception as e:
            logging.error(f"Error loading logs from CSV: {str(e)}")
            print(f"Error loading logs from CSV: {str(e)}")
            return None
    
    def parse_time(self, time_str):
        """Parse time string from logs"""
        # Try different formats
        formats = [
            "%Y/%m/%d %H:%M:%S",  # 2023/04/01 12:34:56
            "%Y-%m-%d %H:%M:%S",   # 2023-04-01 12:34:56
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
                
        logging.warning(f"Could not parse time string: {time_str}")
        return None
    
    def round_to_interval(self, dt, minutes=15):
        """Round datetime to specified interval"""
        return dt - timedelta(
            minutes=dt.minute % minutes,
            seconds=dt.second,
            microseconds=dt.microsecond
        )
    
    def analyze_logs_by_time(self, logs, interval_minutes=15, time_field='receive_time'):
        """Analyze logs by time intervals"""
        time_data = defaultdict(lambda: defaultdict(int))
        log_types = set()
        time_range = {'start': None, 'end': None}
        
        # Count logs by time interval and type
        for log in logs:
            # Skip logs without time field
            if time_field not in log:
                continue
                
            time_str = log[time_field]
            time_dt = self.parse_time(time_str)
            
            if not time_dt:
                continue
                
            # Track overall time range
            if time_range['start'] is None or time_dt < time_range['start']:
                time_range['start'] = time_dt
            if time_range['end'] is None or time_dt > time_range['end']:
                time_range['end'] = time_dt
                
            # Round to interval
            interval = self.round_to_interval(time_dt, interval_minutes)
            
            # Get log type
            log_type = log.get('type', 'unknown')
            log_types.add(log_type)
            
            # Count by interval and type
            time_data[interval]['total'] += 1
            time_data[interval][log_type] += 1
        
        # Add any missing intervals within the time range
        if time_range['start'] and time_range['end']:
            current = self.round_to_interval(time_range['start'], interval_minutes)
            while current <= time_range['end']:
                if current not in time_data:
                    time_data[current] = defaultdict(int)
                current += timedelta(minutes=interval_minutes)
        
        return time_data, log_types, time_range
    
    def calculate_rates(self, time_data, interval_minutes=15):
        """Calculate rates (logs per second) for each interval"""
        rates = defaultdict(lambda: defaultdict(float))
        interval_seconds = interval_minutes * 60
        
        for interval, counts in time_data.items():
            for log_type, count in counts.items():
                rates[interval][log_type] = count / interval_seconds
                
        return rates
    
    def print_rate_summary(self, rates):
        """Print summary of log rates"""
        print("\nLog rates (logs per second) by interval:")
        print("-" * 50)
        
        for interval, rate_data in sorted(rates.items()):
            total_rate = rate_data.get('total', 0)
            type_rates = ", ".join(
                f"{k}: {v:.2f}" for k, v in sorted(rate_data.items()) 
                if k != 'total' and v > 0
            )
            
            print(f"{interval}: Total: {total_rate:.2f} logs/sec  ({type_rates})")
    
    def plot_rates(self, rates, log_types, time_range, output_file, interval_minutes=15):
        """Plot log rates over time"""
        # Sort intervals
        intervals = sorted(rates.keys())
        if not intervals:
            logging.warning("No data to plot")
            return False
            
        # Create figure
        plt.figure(figsize=(12, 7))
        
        # Plot total rates
        total_rates = [rates[t]['total'] for t in intervals]
        plt.plot(intervals, total_rates, 'k-', label='Total', linewidth=2)
        
        # Plot rates by type
        for log_type in sorted(log_types):
            type_rates = [rates[t][log_type] for t in intervals]
            if any(rate > 0 for rate in type_rates):  # Only plot if has data
                plt.plot(intervals, type_rates, '-o', label=log_type, alpha=0.7)
        
        # Format x-axis
        plt.gcf().autofmt_xdate()
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        
        # Add labels and title
        time_period = "unknown"
        if time_range['start'] and time_range['end']:
            delta = time_range['end'] - time_range['start']
            hours = delta.total_seconds() / 3600
            if hours <= 24:
                time_period = f"{hours:.1f} hours"
            else:
                time_period = f"{hours/24:.1f} days"
                
        plt.xlabel('Time')
        plt.ylabel('Logs per Second')
        plt.title(f'PAN-OS Log Rates ({interval_minutes}-minute intervals, {time_period})')
        
        # Add legend
        plt.legend(loc='upper right')
        
        # Add grid
        plt.grid(True, alpha=0.3)
        
        # Tight layout
        plt.tight_layout()
        
        # Save figure
        try:
            plt.savefig(output_file, bbox_inches='tight', dpi=150)
            logging.info(f"Saved plot to {output_file}")
            print(f"Saved plot to {output_file}")
            return True
        except Exception as e:
            logging.error(f"Error saving plot: {str(e)}")
            print(f"Error saving plot: {str(e)}")
            return False


def get_user_input(prompt, default=None):
    """Get user input with optional default value"""
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='PAN-OS Log Analysis Script')
    
    parser.add_argument('--hostname', help='Firewall hostname or IP address')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--log-type', default=DEFAULT_LOG_TYPE, help=f'Log type (default: {DEFAULT_LOG_TYPE})')
    parser.add_argument('--log-count', type=int, default=DEFAULT_LOG_COUNT, help=f'Number of logs to retrieve (default: {DEFAULT_LOG_COUNT})')
    parser.add_argument('--interval', type=int, default=DEFAULT_INTERVAL_MINUTES, help=f'Time interval in minutes (default: {DEFAULT_INTERVAL_MINUTES})')
    parser.add_argument('--input-file', help='Load logs from CSV file instead of firewall')
    parser.add_argument('--output-file', default=DEFAULT_OUTPUT_FILE, help=f'Output CSV file (default: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('--graph-file', default=DEFAULT_GRAPH_FILE, help=f'Output graph file (default: {DEFAULT_GRAPH_FILE})')
    parser.add_argument('--skip-inventory', action='store_true', help='Skip using inventory.json (default is to use it)')
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()
    
    print("=== PAN-OS Log Analysis Tool ===\n")
    
    # Initialize analyzer and always try to load inventory first
    analyzer = PanosLogAnalyzer(use_inventory=True)
    
    # Determine log source (file or firewall)
    logs = None
    use_file = args.input_file is not None
    
    if not use_file and os.path.exists(DEFAULT_OUTPUT_FILE):
        use_existing = input(f"Existing log file '{DEFAULT_OUTPUT_FILE}' found. Use it? (y/n): ").lower() == 'y'
        if use_existing:
            use_file = True
            args.input_file = DEFAULT_OUTPUT_FILE
    
    if use_file:
        # Load logs from file
        print(f"Loading logs from {args.input_file}")
        logs = analyzer.load_logs_from_csv(args.input_file)
    else:
        # Always check inventory first regardless of args
        has_inventory = analyzer.inventory and len(analyzer.inventory) > 0
        
        if has_inventory:
            print("\nFound devices in inventory.json:")
            for i, (ip, device) in enumerate(analyzer.inventory.items(), 1):
                hostname = device.get('hostname', 'Unknown')
                print(f"{i}. {hostname} ({ip})")
            
            use_inventory = input("\nUse a device from inventory? (y/n): ").lower() == 'y'
            
            if use_inventory:
                # Let user select a device
                selection = input("Select device number (or enter IP directly): ").strip()
                try:
                    index = int(selection) - 1
                    keys = list(analyzer.inventory.keys())
                    ip = keys[index]
                except (ValueError, IndexError):
                    ip = selection
                
                if analyzer.connect_from_inventory(ip):
                    print(f"Successfully connected to {ip} using inventory credentials")
                else:
                    print(f"Failed to connect to {ip} using inventory credentials")
                    use_inventory = False
        else:
            print("No inventory.json file found or it's empty.")
            use_inventory = False
            
        # If not using inventory or connection failed, get manual credentials
        if not use_inventory:
            # Get connection details
            hostname = args.hostname or get_user_input("Enter Palo Alto firewall hostname or IP")
            username = args.username or get_user_input("Enter username")
            password = getpass("Enter password: ")
            
            print("\nAttempting to connect to firewall...")
            
            # Allow user to set a custom timeout
            custom_timeout = input("Would you like to set a custom timeout? (default is 60s) (y/n): ").lower() == 'y'
            timeout = DEFAULT_TIMEOUT
            if custom_timeout:
                try:
                    timeout = int(input("Enter timeout in seconds: "))
                except ValueError:
                    print(f"Invalid timeout, using default ({DEFAULT_TIMEOUT}s)")
            
            if not analyzer.connect(hostname, username, password, timeout=timeout):
                retry_connect = input("Connection failed. Would you like to try again with a longer timeout? (y/n): ").lower() == 'y'
                if retry_connect:
                    timeout = int(get_user_input("Enter new timeout in seconds", "120"))
                    if not analyzer.connect(hostname, username, password, timeout=timeout):
                        print("Failed to connect to firewall. Exiting.")
                        return
                else:
                    print("Failed to connect to firewall. Exiting.")
                    return
            
            # If connected successfully, add to inventory
            add_to_inventory = input("\nWould you like to add this device to inventory.json for future use? (y/n): ").lower() == 'y'
            if add_to_inventory:
                # Get system info to get hostname
                try:
                    analyzer.api.op(cmd="<show><s><info></info></s></show>")
                    response = analyzer.api.xml_result()
                    root = ET.fromstring(response)
                    hostname_elem = root.find('.//hostname')
                    if hostname_elem is not None:
                        hostname_value = hostname_elem.text
                    else:
                        hostname_value = hostname
                except:
                    hostname_value = hostname
                
                # Generate API key if we don't have one
                if not hasattr(analyzer, 'api_key') or not analyzer.api_key:
                    try:
                        analyzer.api.keygen()
                        api_key = analyzer.api.api_key
                    except:
                        print("Unable to generate API key. Device will be added without key.")
                        api_key = None
                else:
                    api_key = analyzer.api_key
                
                # Add to inventory
                if not os.path.exists(analyzer.inventory_file):
                    analyzer.inventory = {}
                
                analyzer.inventory[hostname] = {
                    "ip": hostname,
                    "hostname": hostname_value,
                    "api_key": api_key
                }
                
                # Save inventory
                try:
                    with open(analyzer.inventory_file, 'w') as f:
                        json.dump(analyzer.inventory, f, indent=4)
                    print(f"Added {hostname} to inventory.json")
                except Exception as e:
                    print(f"Error saving inventory: {str(e)}")
        
        # Get log parameters
        log_type = get_user_input("Enter log type (traffic, threat, etc.)", args.log_type)
        
        # Ask about log count with a reasonable default
        print("\nNote: Requesting too many logs can cause timeouts.")
        print("For better reliability, start with a smaller number (100-1000).")
        log_count = int(get_user_input("Enter number of logs to retrieve", str(args.log_count)))
        
        # Ask for time frame
        use_time_frame = input("Specify a time frame? (y/n): ").lower() == 'y'
        time_frame = None
        if use_time_frame:
            hours = get_user_input("Enter time range in hours (e.g., 1, 24)", "24")
            time_frame = f"last-{hours}-hour"
        
        # Query for logs
        print(f"\nRetrieving {log_count} {log_type} logs...")
        print("(This may take some time depending on log volume and network conditions)")
        logs = analyzer.get_logs(log_type, log_count, time_frame=time_frame)
        
        if logs:
            print(f"Successfully retrieved {len(logs)} logs")
            # Save logs to CSV
            analyzer.save_logs_to_csv(logs, args.output_file)
        else:
            print("\nNo logs retrieved. Would you like to:")
            print("1. Try again with fewer logs")
            print("2. Use a sample file for testing (if available)")
            print("3. Exit")
            
            choice = input("Enter choice (1-3): ").strip()
            if choice == "1":
                fewer_logs = int(get_user_input("Enter a smaller number of logs to retrieve", "100"))
                logs = analyzer.get_logs(log_type, fewer_logs, time_frame=time_frame)
                if logs:
                    analyzer.save_logs_to_csv(logs, args.output_file)
                else:
                    print("Still unable to retrieve logs. Exiting.")
                    return
            elif choice == "2":
                sample_file = "sample_panos_logs.csv"
                if os.path.exists(sample_file):
                    logs = analyzer.load_logs_from_csv(sample_file)
                    if not logs:
                        print("Unable to load sample file. Exiting.")
                        return
                else:
                    print("No sample file available. Exiting.")
                    return
            else:
                print("Exiting.")
                return
    
    if not logs:
        print("No logs to analyze. Exiting.")
        return
    
    # Get analysis parameters
    interval_minutes = int(get_user_input(
        "Enter time interval in minutes for analysis",
        str(args.interval)
    ))
    
    # Analyze logs
    print(f"\nAnalyzing {len(logs)} logs with {interval_minutes}-minute intervals...")
    
    time_data, log_types, time_range = analyzer.analyze_logs_by_time(
        logs, interval_minutes
    )
    
    if not time_data:
        print("No valid time data found in logs. Exiting.")
        return
    
    # Calculate rates
    rates = analyzer.calculate_rates(time_data, interval_minutes)
    
    # Print summary
    analyzer.print_rate_summary(rates)
    
    # Plot rates
    print(f"\nGenerating plot...")
    analyzer.plot_rates(rates, log_types, time_range, args.graph_file, interval_minutes)
    
    print("\n=== Analysis completed ===")


if __name__ == "__main__":
    main()