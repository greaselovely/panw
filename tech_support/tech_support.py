import requests
import getpass
import os, sys
import urllib3
import urllib
import xmltodict
import cursor
import pathlib
import argparse
from datetime import datetime
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
usage: tech_support.py [-h] -i IP_ADDR [-u USER] [-p PASSWORD] [-a API_KEY]

Performs a request to generate a tech support file (TSF), monitors the job, and then downloads the TSF

options:
  -h, --help            show this help message and exit
  -i IP_ADDR, --ip_addr IP_ADDR
                        IP Address of the firewall
  -u USER, --user USER  Username on the firewall
  -p PASSWORD, --password PASSWORD
                        Password on the firewall
  -a API_KEY, --api_key API_KEY
                        API Key from the firewall
"""

status_dict = {'PEND': 'Pending', 'ACT': 'Running', 'FIN': 'Finished'}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def argue_with_me() -> tuple:
    global fw_ip, fw_username, fw_password, fw_api_key
    """
    This is called if there are arguments passed to the script via cli
    """
    parser = argparse.ArgumentParser(description='Performs a request to generate a tech support file (TSF), monitors the job, and then downloads the TSF')
    parser.add_argument('-i', '--ip_addr', type=str, help='IP Address of the firewall', required=True)
    parser.add_argument('-u', '--user', type=str, help='Username on the firewall', required=False)
    parser.add_argument('-p', '--password', type=str, help='Password on the firewall', required=False)
    parser.add_argument('-a', '--api_key', type=str, help='API Key from the firewall', required=False)
    args = parser.parse_args()
    fw_ip = args.ip_addr
    fw_api_key = args.api_key
    fw_username = args.user
    fw_password = args.password
    if fw_api_key is not None and len(fw_api_key) > 100:
        return
    elif fw_username and fw_password:
        return
    elif fw_username and not fw_password:
        fw_password = getpass.getpass("[?]\tEnter your password: ")
    elif fw_password and not fw_username:
        fw_username = input("[?]\tEnter your username: ")
    else:
        fw_username = input("[?]\tEnter your username: ")
        fw_password = getpass.getpass("[?]\tEnter your password: ")
    return



def create_session() -> None:
    """
    making variables global
    creating a session to the firewall
    adding API key to the header
    we use the header for the API key instead of passing in URL
    """
    global session, response, headers, fw_api_key
    session = requests.session()
    if fw_api_key is None:
        api_url = f"https://{fw_ip}/api/?type=keygen&user={fw_username}&password={fw_password}"
        response = session.post(api_url, verify=False)
        key_dict = xmltodict.parse(response.text)
        fw_api_key = key_dict.get('response').get('result').get('key')
        headers = {"X-PAN-KEY": fw_api_key}
    else:
        api_url = f"https://{fw_ip}/api/?type=op&cmd=<show><system><info></info></system></show>"
        headers = {"X-PAN-KEY": fw_api_key}
        response = session.get(api_url, headers=headers, verify=False)
    if response.status_code == 200:
        return
    else:
        broken = xmltodict.parse(response.text)
        broken = broken.get('response').get('result').get('msg', 'b0rk3n')
        print(f"\n\n[!]\tAuthentication failed with status code {response.status_code} - {broken}\n\n")
        sys.exit()


def get_hostname_and_filename() -> None:
    """
    Just using this to grab hostname which will 
    be used to name the TSF with the date.
    If we can't parse the hostname, we give it a 
    generic name using the var below
    """
    tmp_host_name = 'frwl'
    global full_path
    today = datetime.now().strftime('%m%d%Y')
    api_url = f"https://{fw_ip}/api/?type=op&cmd=<show><system><info></info></system></show>"
    response = session.get(api_url, headers=headers, verify=False)
    ssi_dict = xmltodict.parse(response.text)
    hostname = ssi_dict.get('response').get('result').get('system').get('hostname', tmp_host_name)
    file_name = f"{hostname}.{today}.tgz"
    local_path = pathlib.Path(__file__).parent
    full_path = pathlib.Path.joinpath(local_path, file_name) 

def start_tsf() -> str:
    """
    Simply starting the TSF processing
    """
    api_url = f"https://{fw_ip}/api/?type=export&category=tech-support"
    response = session.get(api_url, headers=headers)
    job_dict = xmltodict.parse(response.text)
    job_id = job_dict.get('response').get('result').get('job')
    return job_id

def sji(job_id: str) -> None:
    """
    sji = show job id
    We monitor the provided job id and 
    return once the status is FIN.  
    Print out friendly message using the dict above
    """
    api_url = f"https://{fw_ip}/api/?type=op&cmd=<show><jobs><id>{job_id}</id></jobs></show>"
    while True:
        response = session.post(api_url, headers=headers, verify=False)
        job_dict = xmltodict.parse(response.text)
        status = job_dict.get('response').get('result').get('job').get('status', "Something's Happening")
        if status == "FIN":
            clear()
            print(f"{status_dict.get(status)}")
            cursor.show()
            return
        progress = job_dict.get('response').get('result').get('job').get('progress', '0')
        cursor.hide()
        print(f"\t{status_dict.get(status)} - {progress}%\t\t", end='\r')
        sleep(10)
    

def download_tsf(job_id: str) -> None:
    """
    We download the file that was saved on the local disk
    of the firewall with the job id as reference in the URL
    """
    api_url = f"https://{fw_ip}/api/?type=export&category=tech-support&action=get&job-id={job_id}"
    response = session.get(api_url, headers=headers, stream=True)
    if response.status_code == 200:
        with open(full_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
        print(f"Tech support file saved to {full_path}")
    else:
        print("Error creating tech support file")
    return

def logoff_firewall() -> None:
    """
    Closing the session to the firewall
    """
    api_url = f"https://{fw_ip}/api/?type=keygen&user={fw_username}&password={fw_password}&logout=yes"
    session.post(api_url, headers=headers, verify=False)
    return

def main():
    global fw_ip, fw_username, fw_password, fw_api_key
    clear()
    if len(sys.argv) > 2:
        argue_with_me()
    elif len(sys.argv) > 1: # will simply send help to the user
        argue_with_me()
    else:
        fw_ip = input("[?]\tEnter FW IP Address: ")
        fw_username = input("[?]\tEnter your username: ")
        fw_password = getpass.getpass("[?]\tEnter your password: ")
        fw_password = urllib.parse.quote(fw_password)
        fw_api_key = None
        
        
    create_session()
    clear()
    get_hostname_and_filename()
    job_id = start_tsf()
    sji(job_id)
    download_tsf(job_id)
    logoff_firewall()



if __name__ == '__main__':
    main()
