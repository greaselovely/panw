import requests
import urllib3
import urllib
import socket
import getpass
import subprocess as sub
import os
import sys
import xmltodict
# import xml.etree.ElementTree as ET
from time import sleep


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

input_file = r"/path/to/stuff/and/things/ip.txt"
output_file = r"/path/to/stuff/and/things/inventory.txt"
description = ""


open(output_file, 'w').close # Blow away the existing file.

def clear():
    os.system("cls") if os.name == "nt" else os.system("clear")

def url_encode(url):
    return urllib.parse.quote_plus(url)

def log_it(*args):
    hostname, ip = args
    with open(output_file, 'a') as f:
        f.write(f"{hostname},{ip}\n")

def ping(ip):
    if os.name == "nt":
        nop = "-n"
    else:
        nop = "-c"
    command = f"ping {nop} 1 -w 2 {ip}".split()
    resp = sub.call(command, stdout=sub.DEVNULL) # suppress stdout
    return resp

def check_port(ip, port=443):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    resp = sock.connect_ex((ip, port))
    sock.close
    return resp

def get_api_key(ip, username, password, port="443"):
    password = url_encode(password) # urlencode the password since it may have special characters
    apiurl = f"https://{ip}:{port}/api/?type=keygen&user={username}&password={password}"
    key = requests.get(apiurl, verify=False)
    if key.status_code == 403:
        key = "Not Authorized"
        sys.exit()
    key_dict = xmltodict.parse(key.text)
    key = key_dict.get('response').get('result').get('key')
    return key

def get_config(ip, key, port="443"):
    apiurl = f"https://{ip}:{port}/api/?type=op&cmd=<show><config><running></running></config></show>&key={key}"
    config = requests.get(apiurl, verify=False)
    return config

def get_sys_info(ip, key, port="443"):
    apiurl = f'https://{ip}:{port}/api/?type=op&cmd=<show><system><info></info></system></show>&key={key}'
    sys_info = requests.get(apiurl, verify=False)
    sys_info = xmltodict.parse(sys_info.text)
    hostname = sys_info.get('response').get('result').get('system').get('hostname')
    log_it(hostname.upper(), ip)


def cudl(ip, key, port="443"):
    # request content upgrade download latest (cudl)
    apiaction="api/?&type=op&cmd="
    apixpath=""
    apielement="<request><content><upgrade><download><latest></latest></download></upgrade></content></request>"
    apikey=f"&key={key}"
    apiurl=f"https://{ip}:{port}/{apiaction}{apixpath}{apielement}{apikey}"
    r = requests.get(apiurl, verify=False)
    print("[i]\tCUDL", r.status_code)
    return

def cuivl(ip, key, port="443"):
    # request content upgrade install version latest (cuivl)
    apiaction="api/?&type=op&cmd="
    apixpath=""
    apielement="<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>"
    apikey=f"&key={key}"
    apiurl=f"https://{ip}:{port}/{apiaction}{apixpath}{apielement}{apikey}"
    r = requests.get(apiurl, verify=False)
    print("[i]\tCUIVL", r.status_code)
    return


def commit(ip, key, port="443"):
    apiurl = f"https://{ip}:{port}/api/?type=commit&cmd=<commit><description>{description}</description></commit>&key={key}"
    requests.post(apiurl, verify=False)
    print(f"[i]\tCommit sent to {ip}")
    return


def main():
    clear()
    username = input("[?]\tEnter your username: ")
    password = getpass.getpass("[?]\tEnter your password: ")
    with open(input_file) as f:
        text = f.read().splitlines()

    for ip in text:
        if ping(ip) == 0:
            if check_port(ip) == 0: # Can ping IP
                print(f"\n[i]\tChecking {ip}")
                pass # and port is open, so go do stuff
            else:
                continue # go to next IP
        else:
            continue # go to next IP

        key = get_api_key(ip, username, password)
        get_sys_info(ip, key)

        cudl(ip, key) # Download the latest TP signatures
        # cuivl(ip, key) # Install the latest TP signatures
        
        # There could be added some logic to check the last IP's job to see when it's done, but 
        # when I wrote this I was in a hurry so I just comment / uncomment as needed and run it twice.


if __name__ == "__main__":
    main()
