"""
SSL Certificate Checker - Checks SSL certificates for multiple domains
and provides information about expiration dates, certificate authorities,
and optional URL categorization via firewall integration.
"""

import ssl
import socket
import datetime
import warnings
import requests
import pathlib
import os
import random
import argparse
import xmltodict
import json
import logging
import re
import sys
import atexit
import time
import fcntl
from getpass import getpass
from typing import Tuple, List, Dict, Optional, Any
from dataclasses import dataclass
from colorama import Fore, Style, init
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning

# Initialize colorama
init(autoreset=True)

# Suppress warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Setup logging - file only, no console output by default
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ssl_checker.log")
    ]
)
logger = logging.getLogger("ssl_checker")

# Constants
APP_DIR = pathlib.Path(__file__).parent
DOMAIN_FILE = os.path.join(APP_DIR, 'domains.txt')
OPENDNS_FILE = os.path.join(APP_DIR, 'opendns.txt')
INVENTORY_FILE = os.path.join(APP_DIR, 'inventory.json')
LOCK_FILE = os.path.join(APP_DIR, 'ssl_checker.lock')
OPENDNS_URL = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
DEFAULT_TIMEOUT = 5  # seconds

# Global lock file handle
lock_file_handle = None

def acquire_lock():
    """Acquire a lock file to prevent multiple instances from running"""
    global lock_file_handle
    try:
        lock_file_handle = open(LOCK_FILE, 'w')
        fcntl.flock(lock_file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except IOError:
        return False

def release_lock():
    """Release the lock file"""
    global lock_file_handle
    if lock_file_handle and not lock_file_handle.closed:
        try:
            fcntl.flock(lock_file_handle, fcntl.LOCK_UN)
            lock_file_handle.close()
            try:
                os.remove(LOCK_FILE)
            except:
                pass
        except (IOError, ValueError) as e:
            # Silently handle errors during cleanup
            pass

@dataclass
class CertificateInfo:
    """Data class for certificate information"""
    domain: str
    expiration_date: Optional[datetime.datetime] = None
    issuer: Optional[str] = None
    days_remaining: Optional[int] = None
    category: Optional[str] = None
    risk: Optional[str] = None
    error: Optional[str] = None
    is_valid: bool = False
    cert_details: Optional[Dict[str, Any]] = None

class FirewallManager:
    """Manages firewall connections and API interactions"""
    
    def __init__(self, inventory_file: str):
        self.inventory_file = inventory_file
        self.current_firewall = None
        self.load_firewall_info()
    
    def load_firewall_info(self) -> bool:
        """Load firewall information from inventory and test API keys"""
        if not os.path.exists(self.inventory_file):
            logger.info("No inventory file found")
            return False
            
        try:
            with open(self.inventory_file, 'r') as f:
                inventory = json.load(f)
            
            if not inventory:
                logger.info("Inventory is empty")
                return False
            
            # Debug the inventory contents (masked API key for security)
            debug_inventory = {}
            for hostname, fw_data in inventory.items():
                debug_fw = fw_data.copy()
                if 'api_key' in debug_fw:
                    key = debug_fw['api_key']
                    debug_fw['api_key'] = f"{key[:5]}...{key[-5:]}" if len(key) > 10 else "***masked***"
                debug_inventory[hostname] = debug_fw
            
            logger.debug(f"Loaded inventory: {json.dumps(debug_inventory, indent=2)}")
            
            # Try most recently added firewall first (last in dict)
            latest_hostname = list(inventory.keys())[-1]
            latest_fw = inventory[latest_hostname]
            
            logger.debug(f"Testing connection to {latest_hostname} at {latest_fw['ip_address']}")
            if self._test_api_key(latest_fw['ip_address'], latest_fw['api_key']):
                self.current_firewall = latest_fw
                logger.debug(f"Connection to {latest_hostname} successful")
                return True
            
            # If latest fails, try others
            for hostname, fw_data in inventory.items():
                if hostname != latest_hostname:
                    logger.debug(f"Testing connection to {hostname} at {fw_data['ip_address']}")
                    if self._test_api_key(fw_data['ip_address'], fw_data['api_key']):
                        self.current_firewall = fw_data
                        logger.debug(f"Connection to {hostname} successful")
                        return True
            
            logger.warning("No firewalls with valid API keys found")
            return False
            
        except Exception as e:
            logger.error(f"Error loading firewall information: {e}")
            return False
    
    def setup_firewall(self) -> None:
        """Setup or update firewall information"""
        try:
            hostname = input("Enter firewall hostname: ").upper()
            ip_address = input("Enter firewall IP address: ")
            username = input("Enter username: ")
            password = getpass("Enter password: ")
            
            # Get API key
            api_url = f"https://{ip_address}/api/?type=keygen&user={username}&password={password}"
            try:
                response = requests.get(api_url, verify=False, timeout=DEFAULT_TIMEOUT)
                response.raise_for_status()
                xml_dict = xmltodict.parse(response.text)
                api_key = xml_dict['response']['result']['key']
            except Exception as e:
                logger.error(f"Failed to get API key: {e}")
                print(f"{Fore.RED}Failed to get API key: {e}{Style.RESET_ALL}")
                return
            
            # Test the API key
            if not self._test_api_key(ip_address, api_key):
                print(f"{Fore.RED}Failed to validate the API key. Firewall information not saved.{Style.RESET_ALL}")
                return
            
            # Prepare new firewall data
            new_firewall_data = {
                "hostname": hostname,
                "ip_address": ip_address,
                "api_key": api_key
            }
            
            # Load existing inventory or create new
            inventory = {}
            if os.path.exists(self.inventory_file):
                with open(self.inventory_file, 'r') as f:
                    inventory = json.load(f)
            
            # Update inventory
            inventory[hostname] = new_firewall_data
            
            with open(self.inventory_file, 'w') as f:
                json.dump(inventory, f, indent=2)
            
            self.current_firewall = new_firewall_data
            print(f"{Fore.GREEN}Successfully set up firewall connection to {hostname}{Style.RESET_ALL}")
            
        except Exception as e:
            logger.error(f"Error in setup_firewall: {e}")
            print(f"{Fore.RED}An error occurred during setup: {e}{Style.RESET_ALL}")
    
    def _test_api_key(self, ip_address: str, api_key: str) -> bool:
        """Test if the API key is valid by making a simple API call"""
        # Simplified API test using a more reliable endpoint
        test_url = f"https://{ip_address}/api/?type=op&cmd=<show><system><info></info></system></show>&key={api_key}"
        try:
            logger.debug(f"Testing API connection to {ip_address}")
            response = requests.get(test_url, verify=False, timeout=DEFAULT_TIMEOUT)
            
            # More detailed logging for debugging API issues
            logger.debug(f"API response status code: {response.status_code}")
            logger.debug(f"API response text: {response.text[:200]}...")  # Log the first 200 chars
            
            if response.status_code != 200:
                logger.debug(f"API test failed: non-200 status code")
                return False
                
            # Parse the response
            xml_dict = xmltodict.parse(response.text)
            is_valid = xml_dict.get('response', {}).get('@status') == 'success'
            logger.debug(f"API key test result: {'Success' if is_valid else 'Failed'}")
            return is_valid
        except Exception as e:
            logger.debug(f"API key test failed with exception: {e}")
            return False
    
    def get_url_category(self, url: str, very_verbose: bool = False) -> Tuple[Optional[str], Optional[str]]:
        """Query firewall for URL category and risk"""
        if not self.current_firewall:
            if very_verbose:
                print(f"{Fore.YELLOW}No firewall connection available{Style.RESET_ALL}")
            return None, None
        
        try:
            # Use the properly formatted test URL command
            api_url = (f"https://{self.current_firewall['ip_address']}/api/"
                      f"?type=op&cmd=<test><url>{url}</url></test>&key={self.current_firewall['api_key']}")
            
            # Create a sanitized version of the URL for logging (with masked API key)
            san_api_url = (f"https://{self.current_firewall['ip_address']}/api/"
                          f"?type=op&cmd=<test><url>{url}</url></test>&key={self.current_firewall['api_key'][:5]}...{self.current_firewall['api_key'][-5:]}")
            
            if very_verbose:
                print(f"API URL: {san_api_url}")
            
            response = requests.get(api_url, verify=False, timeout=DEFAULT_TIMEOUT)
            
            if response.status_code != 200:
                logger.warning(f"URL categorization failed with status code: {response.status_code}")
                if very_verbose:
                    print(f"{Fore.RED}URL categorization failed: HTTP {response.status_code}{Style.RESET_ALL}")
                return None, None
            
            # Log full response for debugging
            if very_verbose:
                print(f"{Fore.CYAN}Raw response:{Style.RESET_ALL}\n{response.text}")
            
            try:
                # Parse XML response properly
                xml_dict = xmltodict.parse(response.text)
                
                # Debug the parsed structure
                if very_verbose:
                    print(f"{Fore.CYAN}Parsed XML structure:{Style.RESET_ALL}")
                    print(json.dumps(xml_dict, indent=2)[:500] + "...")  # Limit output size
                
                # Extract the result text which contains category info
                result = xml_dict.get('response', {}).get('result', '')
                
                if not result:
                    if very_verbose:
                        print(f"{Fore.RED}No result found in the XML response{Style.RESET_ALL}")
                    return None, None
                
                # For text result parsing, different firewalls might format differently
                result_str = str(result)
                
                # Parse based on the specific firewall response format we now know:
                # "domain.com business-and-economy low-risk (Cloud db)"
                category = "unknown"
                risk = "unknown"
                
                # Find lines that mention the domain and categorization
                if very_verbose:
                    print(f"{Fore.CYAN}Looking for categorization pattern in:{Style.RESET_ALL}")
                    print(f"{result_str}")
                
                # Look for Cloud DB entry first as it's usually more reliable
                cloud_pattern = re.search(r'(\S+)\s+(\S+(?:-\S+)*)\s+(\S+(?:-\S+)*)\s+\(Cloud db\)', result_str)
                if cloud_pattern:
                    domain_found = cloud_pattern.group(1)
                    category = cloud_pattern.group(2)
                    risk = cloud_pattern.group(3)
                    if very_verbose:
                        print(f"{Fore.GREEN}Found Cloud DB match:{Style.RESET_ALL}")
                        print(f"  Domain: {domain_found}")
                        print(f"  Category: {category}")
                        print(f"  Risk: {risk}")
                else:
                    # Try base DB pattern if cloud pattern fails
                    base_pattern = re.search(r'(\S+)\s+(\S+(?:-\S+)*)\s+(\S+(?:-\S+)*)\s+\(Base db\)', result_str)
                    if base_pattern:
                        domain_found = base_pattern.group(1)
                        category = base_pattern.group(2)
                        risk = base_pattern.group(3)
                        if very_verbose:
                            print(f"{Fore.GREEN}Found Base DB match:{Style.RESET_ALL}")
                            print(f"  Domain: {domain_found}")
                            print(f"  Category: {category}")
                            print(f"  Risk: {risk}")
                    else:
                        # Generic pattern as a fallback
                        generic_pattern = re.search(r'(\S+)\s+(\S+(?:-\S+)*)\s+(\S+(?:-\S+)*)', result_str)
                        if generic_pattern:
                            domain_found = generic_pattern.group(1)
                            category = generic_pattern.group(2)
                            risk = generic_pattern.group(3)
                            if very_verbose:
                                print(f"{Fore.YELLOW}Found generic pattern match:{Style.RESET_ALL}")
                                print(f"  Domain: {domain_found}")
                                print(f"  Category: {category}")
                                print(f"  Risk: {risk}")
                
                # If all pattern matching fails, try line-by-line approach
                if category == "unknown" and risk == "unknown" and very_verbose:
                    print(f"{Fore.YELLOW}All patterns failed, trying line-by-line approach{Style.RESET_ALL}")
                    
                    # Split by lines and look for domain mentions
                    lines = result_str.split('\n')
                    for line in lines:
                        if url in line:
                            parts = line.split()
                            if len(parts) >= 4:  # domain, category, risk, and something after
                                category = parts[1]
                                risk = parts[2]
                                if very_verbose:
                                    print(f"{Fore.GREEN}Found match in line:{Style.RESET_ALL}")
                                    print(f"  Line: {line}")
                                    print(f"  Category: {category}")
                                    print(f"  Risk: {risk}")
                                break
                
                return category, risk
            
            except Exception as e:
                if very_verbose:
                    print(f"{Fore.RED}Error parsing XML: {e}{Style.RESET_ALL}")
                logger.error(f"Error parsing XML response: {e}")
                return None, None
                
        except Exception as e:
            logger.error(f"Error getting URL category: {e}")
            if very_verbose:
                print(f"{Fore.RED}Exception during URL categorization: {e}{Style.RESET_ALL}")
            return None, None

class DomainManager:
    """Manages domain lists and operations"""
    
    def __init__(self, domain_file: str, opendns_file: str):
        self.domain_file = domain_file
        self.opendns_file = opendns_file
    
    def load_domains(self) -> List[str]:
        """Load domains from file or return empty list"""
        if not os.path.isfile(self.domain_file) or os.path.getsize(self.domain_file) == 0:
            return []
        
        with open(self.domain_file, 'r') as f:
            # Only load non-empty lines
            return [line.strip() for line in f.readlines() if line.strip()]
    
    def generate_domains(self, count: int) -> List[str]:
        """Generate random domain list for demo purposes"""
        try:
            # Check if opendns file exists or needs to be downloaded
            if os.path.isfile(self.opendns_file):
                with open(self.opendns_file, 'r') as od:
                    domains_from_opendns = od.read()
            else:
                logger.info(f"Downloading domain list from OpenDNS")
                response = requests.get(OPENDNS_URL, verify=False, timeout=DEFAULT_TIMEOUT)
                response.raise_for_status()
                domains_from_opendns = response.text
                
                with open(self.opendns_file, 'w') as f:
                    f.write(domains_from_opendns)
            
            # Parse and sample domains
            all_domains = [d for d in domains_from_opendns.split() if d.strip()]
            count = min(count, len(all_domains))  # Ensure we don't exceed available domains
            domain_list = random.sample(all_domains, count)
            
            # Save to domains file
            with open(self.domain_file, 'w') as d:
                for domain in domain_list:
                    d.write(f"{domain}\n")
            
            return domain_list
            
        except Exception as e:
            logger.error(f"Error generating domains: {e}")
            return []
    
    def get_domains(self, demo: bool, count: int, single_domain: Optional[str] = None) -> List[str]:
        """Get domains based on provided options"""
        if single_domain:
            return [single_domain]
        
        if demo:
            return self.generate_domains(count)
        
        domains = self.load_domains()
        if not domains:
            logger.info("Domain list is empty, generating demo domains")
            return self.generate_domains(count)
        
        return domains

class SSLChecker:
    """Handles SSL certificate checks and information retrieval"""
    
    def __init__(self, firewall_manager: Optional[FirewallManager] = None):
        self.firewall_manager = firewall_manager
    
    def tcp_port_responding(self, domain: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> bool:
        """Check if the specified TCP port is responding"""
        try:
            with socket.create_connection((domain, port), timeout):
                return True
        except (socket.timeout, socket.error) as e:
            logger.debug(f"TCP port check failed for {domain}: {e}")
            return False
    
    def get_certificate_info(self, domain: str, verbose: bool = False) -> Tuple[Optional[datetime.datetime], Optional[str], Optional[Dict]]:
        """
        Get certificate information including expiration date and issuer.
        Returns a tuple of (expiration_date, issuer, cert_details).
        """
        logger.debug(f"get_certificate_info called for domain: {domain}, verbose: {verbose}")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(DEFAULT_TIMEOUT)
        
        try:
            conn.connect((domain, 443))
            der_cert = conn.getpeercert(True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            
            # Load certificate using cryptography for better parsing
            cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
            
            expiration_date = cert.not_valid_after
            issuer = cert.issuer.rfc4514_string()
            
            # Collect certificate details into a dict - only if verbose mode is requested
            cert_details = {}
            
            if verbose:
                # Add certificate details only in verbose mode
                subject = cert.subject.rfc4514_string()
                serial = cert.serial_number
                version = cert.version
                sigalg = cert.signature_algorithm_oid._name
                
                cert_details['subject'] = subject
                cert_details['serial'] = serial
                cert_details['version'] = version
                cert_details['sigalg'] = sigalg
                cert_details['valid_from'] = cert.not_valid_before
                cert_details['valid_until'] = expiration_date
                
                # Get Subject Alternative Names if present
                try:
                    san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    cert_details['san'] = san.value.get_values_for_type(x509.DNSName)
                except x509.extensions.ExtensionNotFound:
                    cert_details['san'] = []
                
                # Don't print details here - let the reporter handle it
            
            return expiration_date, issuer, cert_details if verbose else None
            
        except Exception as e:
            logger.debug(f"Certificate info retrieval failed for {domain}: {e}")
            return None, None, None
        finally:
            conn.close()
    
    def check_domain(self, domain: str, verbose: bool = False, very_verbose: bool = False) -> CertificateInfo:
        """Check SSL certificate for a single domain and return info"""
        domain = domain.strip()
        cert_info = CertificateInfo(domain=domain)
        
        if very_verbose:
            print(f"\n{Fore.CYAN}Checking domain: {domain}{Style.RESET_ALL}")
        
        if not self.tcp_port_responding(domain):
            cert_info.error = "The website is not responding on TCP/443."
            if very_verbose:
                print(f"{Fore.RED}TCP port 443 is not responding for {domain}{Style.RESET_ALL}")
            return cert_info
        
        try:
            if very_verbose:
                print(f"{Fore.CYAN}Getting certificate information...{Style.RESET_ALL}")
                
            # Pass the verbose flag directly to get_certificate_info
            expiration_date, issuer, cert_details = self.get_certificate_info(domain, verbose)
            
            if expiration_date and issuer:
                cert_info.expiration_date = expiration_date
                cert_info.issuer = issuer
                cert_info.days_remaining = (expiration_date - datetime.datetime.now()).days
                cert_info.is_valid = True
                
                # Only set cert_details if verbose mode is on
                if verbose:
                    cert_info.cert_details = cert_details
                
                if very_verbose:
                    print(f"{Fore.GREEN}Successfully retrieved certificate information:{Style.RESET_ALL}")
                    print(f"  Expiration: {expiration_date}")
                    print(f"  Issuer: {issuer}")
                    print(f"  Days remaining: {cert_info.days_remaining}")
                
                # Get URL category from firewall if available
                if self.firewall_manager and self.firewall_manager.current_firewall:
                    if very_verbose:
                        print(f"{Fore.CYAN}Getting URL category from firewall...{Style.RESET_ALL}")
                    
                    category, risk = self.firewall_manager.get_url_category(domain, very_verbose)
                    cert_info.category = category
                    cert_info.risk = risk
                    
                    if very_verbose:
                        print(f"{Fore.GREEN}URL categorization results:{Style.RESET_ALL}")
                        print(f"  Category: {cert_info.category or 'Unknown'}")
                        print(f"  Risk: {cert_info.risk or 'Unknown'}")
                elif very_verbose:
                    print(f"{Fore.YELLOW}No firewall connection available for URL categorization{Style.RESET_ALL}")
            else:
                cert_info.error = "Failed to retrieve certificate information."
                if very_verbose:
                    print(f"{Fore.RED}Failed to retrieve certificate information.{Style.RESET_ALL}")
                
        except Exception as e:
            cert_info.error = f"Error: {str(e)}"
            logger.error(f"Error checking domain {domain}: {e}")
            if very_verbose:
                print(f"{Fore.RED}Exception during certificate check: {e}{Style.RESET_ALL}")
        
        return cert_info

class CertificateReporter:
    """Formats and displays certificate information"""
    
    @staticmethod
    def print_report(cert_info: CertificateInfo, verbose: bool = False) -> None:
        """Print formatted certificate information"""
        print(f"Domain: {Fore.GREEN}{cert_info.domain}{Style.RESET_ALL}")
        
        if cert_info.is_valid:
            print(f"Expiration Date: {cert_info.expiration_date}")
            
            # Use color coding for days remaining
            if cert_info.days_remaining <= 7:
                days_color = Fore.RED
            elif cert_info.days_remaining <= 30:
                days_color = Fore.YELLOW
            else:
                days_color = Fore.GREEN
            print(f"Days Remaining: {days_color}{cert_info.days_remaining}{Style.RESET_ALL}")
            print(f"Certificate Authority: {Fore.CYAN}{cert_info.issuer}{Style.RESET_ALL}")
            
            # Print detailed certificate info only if verbose mode is on and cert_details exists
            if verbose and cert_info.cert_details:
                print(f"Cert Details: ")
                print(f"  Subject: {cert_info.cert_details['subject']}")
                print(f"  Serial Number: {cert_info.cert_details['serial']}")
                print(f"  Version: {cert_info.cert_details['version']}")
                print(f"  Signature Algorithm: {cert_info.cert_details['sigalg']}")
                print(f"  Valid From: {cert_info.cert_details['valid_from']}")
                print(f"  Valid Until: {cert_info.cert_details['valid_until']}")
                
                if cert_info.cert_details['san']:
                    print(f"  Subject Alternative Names: {cert_info.cert_details['san']}")
            
            # Only show category and risk if they have meaningful values
            if cert_info.category and cert_info.category.lower() != 'unknown':
                print(f"Category: {Fore.YELLOW}{cert_info.category}{Style.RESET_ALL}")
            
            if cert_info.risk and cert_info.risk.lower() != 'unknown':
                print(f"Risk: {Fore.YELLOW}{cert_info.risk}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{cert_info.error}{Style.RESET_ALL}")
        
        print()  # Empty line for readability
    
    @staticmethod
    def save_csv_report(cert_infos: List[CertificateInfo], filename: str = "ssl_report.csv") -> None:
        """Save certificate information to CSV file"""
        try:
            with open(filename, 'w') as f:
                # Write header
                f.write("Domain,ExpirationDate,DaysRemaining,CertificateAuthority,Category,Risk,Error,IsValid\n")
                
                # Write data
                for info in cert_infos:
                    f.write(f"{info.domain},{info.expiration_date or ''},{info.days_remaining or ''},"
                            f"\"{info.issuer or ''}\",\"{info.category or ''}\",\"{info.risk or ''}\"," 
                            f"\"{info.error or ''}\",{info.is_valid}\n")
            
            print(f"{Fore.GREEN}Report saved to {filename}{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Error saving CSV report: {e}")
            print(f"{Fore.RED}Failed to save report: {e}{Style.RESET_ALL}")

def clear_screen() -> None:
    """Clear the console screen"""
    os.system("cls" if os.name == "nt" else "clear")

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Domain SSL Certificate Checker - Shows CA, expiration, and optional URL categorization',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('-d', '--demo', action='store_true', 
                       help='Generate random domain names for demonstration')
    
    parser.add_argument('-c', '--count', type=int, default=5,
                       help='Number of demo domains to generate (max 10)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed certificate information')
                       
    parser.add_argument('-vv', '--very-verbose', action='store_true',
                       help='Show XML responses and detailed debugging information')
    
    parser.add_argument('-s', '--setup', action='store_true',
                       help='Setup or update firewall information')
    
    parser.add_argument('-n', '--name', type=str,
                       help='Specify a single domain name to check')
    
    parser.add_argument('-o', '--output', type=str,
                       help='Save results to CSV file')
    
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress console output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.count < 1:
        args.count = 1
    elif args.count > 10:
        args.count = 10
    
    return args

def main() -> None:
    """Main function to run the SSL checker"""
    # Only proceed if we can acquire the lock
    if not acquire_lock():
        print(f"{Fore.RED}Another instance of SSL Checker is already running. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Register cleanup handler
    atexit.register(release_lock)
    
    try:
        clear_screen()
        args = parse_arguments()
        
        # Update logging level based on verbosity
        if args.very_verbose:
            print(f"{Fore.CYAN}Running in VERY VERBOSE mode - showing detailed XML responses{Style.RESET_ALL}")
            # Enable console logging in very verbose mode
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            logger.setLevel(logging.DEBUG)
        
        # Create managers
        firewall_manager = FirewallManager(INVENTORY_FILE)
        domain_manager = DomainManager(DOMAIN_FILE, OPENDNS_FILE)
        ssl_checker = SSLChecker(firewall_manager)
        reporter = CertificateReporter()
        
        # Setup firewall if requested
        if args.setup:
            firewall_manager.setup_firewall()
            clear_screen()
            
        # Display firewall status in very verbose mode
        if args.very_verbose:
            if firewall_manager.current_firewall:
                print(f"{Fore.CYAN}Firewall connection status:{Style.RESET_ALL}")
                print(f"  Connected to: {Fore.GREEN}{firewall_manager.current_firewall['hostname']}{Style.RESET_ALL}")
                print(f"  IP Address: {firewall_manager.current_firewall['ip_address']}")
                key = firewall_manager.current_firewall['api_key']
                masked_key = f"{key[:5]}...{key[-5:]}" if len(key) > 10 else "***masked***"
                print(f"  API Key: {masked_key}")
                print()
            else:
                print(f"{Fore.YELLOW}No firewall connection available{Style.RESET_ALL}")
                print()
        
        # Get domains to check - force to a list to avoid any iterator issues
        domains = list(domain_manager.get_domains(args.demo, args.count, args.name))
        
        if not domains:
            print(f"{Fore.RED}Error: No domains to check{Style.RESET_ALL}")
            return
        
        # Ensure the list contains unique domains
        domains = list(dict.fromkeys(domains))  # Preserves order while removing duplicates
        
        # Debug the domain list in very verbose mode
        if args.very_verbose:
            print(f"{Fore.CYAN}Domains to check:{Style.RESET_ALL}")
            for i, domain in enumerate(domains):
                print(f"  {i+1}. {domain}")
            print()
        
        # Check each domain 
        results = []
        
        for i, domain in enumerate(domains):
            if args.very_verbose:
                print(f"{Fore.CYAN}Processing domain {i+1}/{len(domains)}: {domain}{Style.RESET_ALL}")
            
            # Pass the verbose flag to check_domain
            cert_info = ssl_checker.check_domain(domain, args.verbose, args.very_verbose)
            results.append(cert_info)
            
            if not args.quiet:
                # Pass the verbose flag to print_report
                reporter.print_report(cert_info, args.verbose)
        
        # Save report if requested
        if args.output:
            reporter.save_csv_report(results, args.output)
        
        if args.very_verbose:
            print(f"{Fore.GREEN}SSL Checker completed successfully{Style.RESET_ALL}")
        
    except Exception as e:
        logger.error(f"Unhandled exception in main: {e}")
        if args and args.very_verbose:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    finally:
        # Always release the lock
        release_lock()

if __name__ == '__main__':
    main()