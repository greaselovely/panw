import requests
import pathlib
import argparse
import sys, os
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

url = "https://ip-ranges.atlassian.com/"
file_name = "edl.txt"

"""
usage: atlassian_edl.py [-h] [-4] [-6] [-a]

EDL creation from the JSON provided by Atlassian

options:
  -h, --help  show this help message and exit
  -4, --four  IPv4 addresses only
  -6, --six   IPv6 addresses only
"""


proxies = {'http': 'http://10.29.60.86:3128', 'https': 'http://10.29.60.86:3128'}



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

def get_data_from_provider(url):
    response = requests.get(url, verify=False, proxies=proxies).json()
    data = response.get('items')
    return data

def ip_version_4(data: dict):
    cidr_list = []
    for cidr in data:
        if ':' in cidr.get('cidr'):
            continue
        cidr_list.append(cidr.get('cidr'))
    return cidr_list

def ip_version_6(data: dict):
    cidr_list = []
    for cidr in data:
        if ':' in cidr.get('cidr'):
            cidr_list.append(cidr.get('cidr'))
        else:
            continue
    return cidr_list

def ip_version_all(data: dict):
    cidr_list = []
    for cidr in data:
        cidr_list.append(cidr.get('cidr'))
    return cidr_list


def write_file(cidr_list: list):
    local_path = pathlib.Path(__file__).parent
    full_path = pathlib.Path.joinpath(local_path, file_name)
    
    with open(full_path, 'w') as f:
        f.write('\n'.join(cidr_list))


def main():
    if len(sys.argv) >= 1:
        four, six = argue_with_me()
    else:
        four, six = False, False

    if four and six: four, six = False, False   # Because come on
    
    data = get_data_from_provider(url)

    if four:
        cidr_list = ip_version_4(data)
    elif six:
        cidr_list = ip_version_6(data)
    else:
        cidr_list = ip_version_all(data)
    
    write_file(cidr_list)

    

if __name__ == "__main__":
    main()