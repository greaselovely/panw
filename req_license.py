import requests
import urllib3
import os
import xmltodict
import pathlib
from datetime import datetime
from colorama import Fore

# Disable SSL certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

inventory = "inventory.txt"
lpath = pathlib.Path(__file__).parent
fullpath = os.path.join(lpath, inventory)

def clear():
    # Clear the console
    os.system('cls' if os.name == 'nt' else 'clear')


def read_inventory():
    global devices
    # Read the inventory file
    with open(fullpath, 'r') as inventory_file:
        devices = inventory_file.readlines()

def days_until_date(date_string):
    date_format = "%B %d, %Y"
    target_date = datetime.strptime(date_string, date_format).date()
    today = datetime.now().date()
    days_difference = (target_date - today).days
    return days_difference


def request_licenses():
    # Iterate over the devices
    # inventory file is structured like this: hostname_ipaddress_apikey
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for device_info in devices:
        device_info = device_info.strip().split('_')
        firewall_name, ip_address, api_key = device_info

        # Create the API endpoint URL
        url = f"https://{ip_address}/api"

        # Set the request headers and payload
        payload = {
            "type": "op",
            "cmd": "<request><license><fetch></fetch></license></request>",
            "key": api_key
        }

        try:
            # Disable SSL certificate verification
            response = requests.post(url, headers=headers, data=payload, verify=False)

            # Check the response status code
            if response.status_code == 200:
                print(f"\n\t{Fore.YELLOW}Fetching license for {firewall_name}...{Fore.RESET}")
            else:
                print(f"Error fetching license for {firewall_name}: {response.text}")

            licenses = xmltodict.parse(response.text)
            for license in licenses.get('response').get('result').get('licenses').get('entry'):
                
                license_name = license.get('feature')
                expires = license.get('expires')
                
                if expires == "Never": 
                    days_to_expiry = 365
                else:
                    days_to_expiry = days_until_date(expires)
                
                if days_to_expiry <= 30: 
                    expires = f"{Fore.RED}{expires}{Fore.RESET}"
                elif days_to_expiry <= 90:
                    expires = f"{Fore.YELLOW}{expires}{Fore.RESET}"
                else:
                    expires = f"{Fore.GREEN}{expires}{Fore.RESET}"

                print(f"License: {license_name}\nExpires: {expires}\n")

        except requests.exceptions.RequestException as e:
            print(f"Error making API request for {firewall_name}: {str(e)}")


def main():
    clear()
    read_inventory()
    request_licenses()


if __name__ == '__main__':
    main()
