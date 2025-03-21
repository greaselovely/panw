import requests
import time
import sys
from getpass import getpass

def get_connection_info():
    global FIREWALL_IP, API_KEY
    FIREWALL_IP = input("Enter the Palo Alto firewall IP address: ")
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")
    get_api_key(username, password)

def get_api_key(username, password):
    global API_KEY
    url = f"https://{FIREWALL_IP}/api/"
    params = {
        "type": "keygen",
        "user": username,
        "password": password
    }
    try:
        response = requests.get(url, params=params, verify=False)
        response.raise_for_status()
        API_KEY = response.json()["result"]["key"]
        print("API key obtained successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to obtain API key: {e}")
        sys.exit(1)

def api_request(endpoint, params=None, method="GET"):
    url = f"https://{FIREWALL_IP}/api/"
    params = params or {}
    params["key"] = API_KEY
    
    try:
        if method == "GET":
            response = requests.get(url + endpoint, params=params, verify=False)
        elif method == "POST":
            response = requests.post(url + endpoint, data=params, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        sys.exit(1)

def check_licenses():
    print("Checking licenses...")
    response = api_request("?type=op&cmd=<request><license><info></info></license></request>")
    # Process and print license information
    print(response)

def wait_for_job(job_id):
    while True:
        response = api_request(f"?type=op&cmd=<show><jobs><id>{job_id}</id></jobs></show>")
        status = response["result"]["job"]["status"]
        if status == "FIN":
            print(f"Job {job_id} completed.")
            break
        print(f"Job {job_id} status: {status}")
        time.sleep(10)

def update_dynamic_updates(update_type):
    print(f"Updating {update_type}...")
    response = api_request(f"?type=op&cmd=<request><{update_type}><upgrade><install><version>latest</version></install></upgrade></{update_type}></request>", method="POST")
    job_id = response["result"]["job"]
    wait_for_job(job_id)

def check_system_software():
    print("Checking system software...")
    response = api_request("?type=op&cmd=<request><system><software><check></check></software></system></request>")
    job_id = response["result"]["job"]
    wait_for_job(job_id)

def get_available_software():
    print("Getting available software versions...")
    response = api_request("?type=op&cmd=<request><system><software><info></info></software></system></request>")
    versions = response["result"]["sw-updates"]["versions"]["entry"]
    return {i: v["version"] for i, v in enumerate(versions, 1)}

def install_software(version):
    print(f"Installing software version {version}...")
    response = api_request(f"?type=op&cmd=<request><system><software><install><version>{version}</version></install></software></system></request>", method="POST")
    job_id = response["result"]["job"]
    wait_for_job(job_id)

def configure_network():
    print("Configuring network...")
    # Remove default configs
    api_request("?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-wire")
    api_request("?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface")
    api_request("?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone")

    # Configure new Tap zone and interface
    api_request("?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone&element=<entry name='Tap'><network><tap/></network></entry>")
    api_request("?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='ethernet1/1']&element=<tap/>")

def create_security_profiles():
    print("Creating security profiles...")
    profile_types = ["virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis"]
    
    for profile_type in profile_types:
        # Create "Alert" profile for each type
        api_request(f"?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/{profile_type}&element=<entry name='Alert'><alert><member>any</member></alert></entry>")

    # Create profile group
    api_request("?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profile-group&element=<entry name='Alert'><virus><member>Alert</member></virus><spyware><member>Alert</member></spyware><vulnerability><member>Alert</member></vulnerability><url-filtering><member>Alert</member></url-filtering><file-blocking><member>Alert</member></file-blocking><wildfire-analysis><member>Alert</member></wildfire-analysis></entry>")

def configure_security_policy():
    print("Configuring security policy...")
    # Delete existing policies
    api_request("?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules")

    # Add new Tap policy
    api_request("?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules&element=<entry name='Tap'><to><member>Tap</member></to><from><member>Tap</member></from><source><member>any</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action><profile-setting><group><member>Alert</member></group></profile-setting></entry>")

def main():
    get_connection_info()
    check_licenses()
    update_dynamic_updates("content")
    update_dynamic_updates("anti-virus")
    check_system_software()
    
    available_versions = get_available_software()
    print("Available software versions:")
    for key, value in available_versions.items():
        print(f"{key}: {value}")
    
    version_choice = int(input("Enter the number of the version you want to install: "))
    if version_choice in available_versions:
        install_software(available_versions[version_choice])
    else:
        print("Invalid choice. Skipping software installation.")
    
    configure_network()
    create_security_profiles()
    configure_security_policy()
    
    print("Configuration complete.")

if __name__ == "__main__":
    main()