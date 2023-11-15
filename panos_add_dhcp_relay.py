import requests
import urllib3
import urllib
import socket
import getpass
import subprocess as sub
import os
import sys
import xmltodict
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

input_file = r"/path/to/stuff/and/things/ip.txt"
output_file = r"/path/to/stuff/and/things/inventory.txt"
description = "A Commit Description Here" # Used for commit description
servers = ["10.11.12.13", "10.11.12.14"] # DHCP Servers

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

def get_dhcp_config(ip, key, port="443"):
    apiurl = f'https://{ip}:{port}/api/?type=op&cmd=<show><config><running><xpath>devices/entry[@name="localhost.localdomain"]/network/dhcp</xpath></running></config></show>&key={key}'
    config = requests.get(apiurl, verify=False)
    return config.text

def get_interfaces(config):
    global interfaces
    interfaces = [] # clear the list for the next firewall.
    tree = ET.fromstring(config)
    for x in tree.iter('entry'):
        int = x.attrib.get('name')
        if "ethernet" in int:
            interfaces.append(int)
    return

def set_new_relay(ip, key, interfaces, port="443"):
    """
    iterate the interfaces and send the new relay IPs
    """
    for int in interfaces:
        for server in servers:
            print(f"[i]\t{server} added to {int}")
            apiurl = f"https://{ip}:{port}/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/dhcp/interface/entry[@name='{int}']/relay/ip/server&element=<member>{server}</member>&key={key}"
            send_it = requests.post(apiurl, verify=False)
            if send_it.status_code != 200:
                print(f"[!]\tPossible problem on {ip}")
    return

def commit(ip, key, port="443"):
    apiurl = f"https://{ip}:{port}/api/?type=commit&cmd=<commit><description>{description}</description></commit>&key={key}"
    commit_it = requests.post(apiurl, verify=False)
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
        config = get_dhcp_config(ip, key)
        get_interfaces(config)
        if len(interfaces) > 0:
            set_new_relay(ip, key, interfaces)
            commit(ip, key)



if __name__ == "__main__":
    main()
