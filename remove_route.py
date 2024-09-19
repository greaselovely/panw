import requests
import xmltodict
from getpass import getpass
import time

# Disable SSL warnings (not recommended for production use)
requests.packages.urllib3.disable_warnings()

def get_api_key(firewall_ip, username, password):
    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "keygen",
        "user": username,
        "password": password
    }
    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        response_dict = xmltodict.parse(response.text)
        return response_dict['response']['result']['key']
    return None

def get_router_type(firewall_ip, api_key):
    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "config",
        "action": "get",
        "xpath": "/config/devices/entry[@name='localhost.localdomain']/network",
        "key": api_key
    }
    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        response_dict = xmltodict.parse(response.text)
        if 'logical-router' in response_dict['response']['result']['network']:
            return "logical-router"
        elif 'virtual-router' in response_dict['response']['result']['network']:
            return "virtual-router"
    return "virtual-router"  # Default to virtual-router if unable to determine

def commit_changes(firewall_ip, api_key):
    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "commit",
        "cmd": "<commit></commit>",
        "key": api_key
    }
    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        response_dict = xmltodict.parse(response.text)
        if response_dict['response']['@status'] == 'success':
            if 'job' in response_dict['response'].get('result', {}):
                return response_dict['response']['result']['job']
    return None

def check_commit_status(firewall_ip, api_key, job_id):
    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "op",
        "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>",
        "key": api_key
    }
    while True:
        response = requests.get(url, params=params, verify=False)
        if response.status_code == 200:
            response_dict = xmltodict.parse(response.text)
            status = response_dict['response']['result']['job']['status']
            progress = response_dict['response']['result']['job']['progress']
            print(f"Commit progress: {progress}%", end='\r')
            if status == 'FIN':
                print("\nCommit completed successfully.")
                return True
            elif status in ['PEND', 'ACT']:
                time.sleep(5)
            else:
                print(f"\nCommit failed. Status: {status}")
                return False
        else:
            print("\nFailed to check commit status.")
            return False

def remove_static_route(firewall_ip, api_key, route_name, router_type):
    url = f"https://{firewall_ip}/api/"
    
    if router_type == "logical-router":
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/network/logical-router/entry[@name='default']/vrf/entry[@name='default']/routing-table/ip/static-route/entry[@name='{route_name}']"
    else:  # virtual-router
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='default']/routing-table/ip/static-route/entry[@name='{route_name}']"
    
    # Check if the route exists
    check_params = {
        "type": "config",
        "action": "get",
        "xpath": xpath,
        "key": api_key
    }
    
    check_response = requests.get(url, params=check_params, verify=False)
    check_dict = xmltodict.parse(check_response.text)
    
    if check_response.status_code == 200 and check_dict['response']['@status'] == 'success':
        if 'entry' in check_dict['response']['result']:
            # Route exists, proceed with deletion
            delete_params = {
                "type": "config",
                "action": "delete",
                "xpath": xpath,
                "key": api_key
            }
            
            delete_response = requests.get(url, params=delete_params, verify=False)
            delete_dict = xmltodict.parse(delete_response.text)
            
            if delete_response.status_code == 200 and delete_dict['response']['@status'] == 'success':
                return True
            else:
                print(f"Failed to remove static route. Error: {delete_response.text}")
        else:
            print(f"Static route '{route_name}' does not exist.")
    else:
        print(f"Failed to check for static route. Error: {check_response.text}")
    
    return False

def main():
    firewall_ip = input("Enter the firewall IP address: ")
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")
    route_name = input("Enter the name of the static route to remove: ")

    api_key = get_api_key(firewall_ip, username, password)
    if api_key:
        router_type = get_router_type(firewall_ip, api_key)
        print(f"Detected router type: {router_type}")
        
        if remove_static_route(firewall_ip, api_key, route_name, router_type):
            print(f"Static route '{route_name}' successfully removed.")
            print("Committing changes...")
            job_id = commit_changes(firewall_ip, api_key)
            if job_id:
                check_commit_status(firewall_ip, api_key, job_id)
            else:
                print("Failed to initiate commit. Please check the firewall for details.")
        else:
            print("No changes to commit.")
    else:
        print("Failed to retrieve API key. Cannot proceed with route removal.")

if __name__ == "__main__":
    main()
