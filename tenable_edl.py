import os
import sys
import json
import pathlib
import argparse
import requests
from pathlib import Path
from http.client import IncompleteRead

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

url = "https://docs.tenable.com/ip-ranges/data.json"
file_name = "edl.txt"


"""
usage: tenable_edl.py [-h] [-4] [-6] [-a]

EDL creation from the JSON provided by Atlassian

options:
  -h, --help  show this help message and exit
  -4, --four  IPv4 addresses only
  -6, --six   IPv6 addresses only
"""

def load_config():
    """
    Used to reference an external json file for
    custom config items, in this first round
    the use of proxy servers so that it wasn't
    static in the original script
    """
    file_name = 'config.json'
    local_path = Path(__file__).resolve().parent
    config_path = Path.joinpath(local_path, file_name)

    try:
        with open(config_path, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        """
        We'll build an empty config.json file.
        Edit to use proxies
        ie: "http" : "http://127.0.0.1:8080", "https" : "http://127.0.0.1:8080"
        """
        config_init_starter = {"proxies" : {"http" : "", "https": ""}}
        with open(config_path, 'w') as file:
            json.dump(config_init_starter, file, indent=2)
         # recursion, load the config file since it wasn't found earlier
        return load_config()
    except json.JSONDecodeError:
        print(f"Error decoding JSON in '{config_path}'.")
        return None

def make_request(url, config, verify=False):
    """
    This was implemented so that we can make requests
    and check for the use of proxies or not.
    We moved the retry_count from the class to here
    and it works to avoid connection errors that 
    sometimes occur.
    """
    proxies = config.get('proxies')
    http_proxy = config.get('proxies').get('http')
    https_proxy = config.get('proxies').get('https')
    max_retries = 3
    for _ in range(max_retries):
        try:
            if http_proxy and https_proxy:
                response = requests.get(url, proxies=proxies, verify=verify)
                # breakpoint()
                response.raise_for_status()
                response = response.json()
                data = response.get('prefixes')
                return data
            else:
                response = requests.get(url, verify=verify, timeout=10)
                response.raise_for_status()
                response = response.json()
                data = response.get('prefixes')
                return data
        except IncompleteRead as e:
            print(f"IncompleteRead Error: {e}")
            continue
        except requests.RequestException as e:
            print(f"RequestException Error: {e}")
            break


def clear():
    os.system("cls" if os.name == "nt" else "clear")

def argue_with_me():
    parser = argparse.ArgumentParser(description='EDL creation from the JSON provided by Atlassian')
    parser.add_argument('-4', '--four', action='store_true', help='IPv4 addresses only', required=False)
    parser.add_argument('-6', '--six', action='store_true', help='IPv6 addresses only', required=False)
    args = parser.parse_args()
    four = args.four
    six = args.six
    return four, six

def ip_version_4(data: dict):
    cidr_list = []
    for cidr in data:
        if ':' in cidr.get('ip_prefix'):
            continue
        cidr_list.append(cidr.get('ip_prefix'))
    return cidr_list

def ip_version_6(data: dict):
    cidr_list = []
    for cidr in data:
        if ':' in cidr.get('ip_prefix'):
            cidr_list.append(cidr.get('ip_prefix'))
        else:
            continue
    return cidr_list

def ip_version_all(data: dict):
    cidr_list = []
    for cidr in data:
        cidr_list.append(cidr.get('ip_prefix'))
    return cidr_list


def write_file(cidr_list: list):
    local_path = pathlib.Path(__file__).parent
    full_path = pathlib.Path.joinpath(local_path, file_name)
    
    with open(full_path, 'w') as f:
        f.write('\n'.join(cidr_list))


def main():
    config = load_config()
    if len(sys.argv) >= 1:
        four, six = argue_with_me()
    else:
        four, six = False, False

    if four and six: four, six = False, False   # Because come on
    
    data = make_request(url, config)

    if four:
        cidr_list = ip_version_4(data)
    elif six:
        cidr_list = ip_version_6(data)
    else:
        cidr_list = ip_version_all(data)
    write_file(cidr_list)


if __name__ == "__main__":
    main()