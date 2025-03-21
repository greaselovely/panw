import argparse
import socket
import re
import pyperclip
import requests
import getpass
import time
import urllib.parse
import sys
import xml.etree.ElementTree as ET
from tabulate import tabulate
import csv

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def validate_fqdn(fqdn):
    pattern = re.compile(r"^(?!127\.0\.0\.1$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    if not pattern.match(fqdn):
        raise ValueError("Invalid FQDN or it matches 127.0.0.1.")
    return True

def get_a_records(fqdn):
    try:
        result = socket.gethostbyname_ex(fqdn)
        return result[2]
    except socket.gaierror:
        raise ValueError(f"Unable to resolve {fqdn}.")

def copy_to_clipboard(text):
    pyperclip.copy(text)

def get_api_key(firewall, username, password):
    url = f"https://{firewall}/api/"
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    api_key = re.search(r'<key>(.+?)</key>', response.text)
    if not api_key:
        raise ValueError("Failed to retrieve API key.")
    return api_key.group(1)

def wait_for_job_completion(firewall, api_key, job_id):
    url = f"https://{firewall}/api/"
    params_status = {
        'type': 'log',
        'action': 'get',
        'job-id': job_id,
        'key': api_key
    }

    print(f"[+] Monitoring job ID {job_id}...")
    for attempt in range(10):
        response = requests.get(url, params=params_status, verify=False)
        response.raise_for_status()
        if '<status>FIN</status>' in response.text:
            print("[+] Job completed. Fetching logs...")
            return fetch_logs(firewall, api_key, job_id)
        else:
            print("[+] Job still running... retrying in 3 seconds.")
            time.sleep(3)
    raise TimeoutError("Job did not complete in time.")

def fetch_logs(firewall, api_key, job_id):
    url = f"https://{firewall}/api/"
    params = {
        'type': 'log',
        'action': 'get',
        'job-id': job_id,
        'key': api_key
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    return extract_log_result(response.text)

def extract_log_result(response_text):
    """
    Return a tuple: (table_string, table_data)
    table_string: formatted table string using tabulate
    table_data: list of lists of raw log data suitable for CSV
    """
    try:
        root = ET.fromstring(response_text)
        entries = root.findall(".//entry")
        if not entries:
            return ("No log details found.", [])

        key_fields = [
            "receive_time", "type", "src", "dst", "sport", "dport",
            "app", "action", "rule", "bytes", "session_end_reason"
        ]

        table_data = []
        for entry in entries:
            row = [entry.find(field).text if entry.find(field) is not None else "N/A" for field in key_fields]
            table_data.append(row)

        table_string = tabulate(table_data, headers=key_fields, tablefmt="grid")
        return (table_string, table_data)
    except ET.ParseError as e:
        return (f"[!] Error parsing XML: {e}", [])

def query_last_25_logs(firewall, api_key):
    url = f"https://{firewall}/api/"
    params = {
        'type': 'log',
        'log-type': 'traffic',
        'nlogs': 25,
        'key': api_key
    }
    print("[+] Querying last 25 traffic logs...")
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()

    match = re.search(r'<job>(\d+)</job>', response.text)
    if match:
        job_id = match.group(1)
        return wait_for_job_completion(firewall, api_key, job_id)
    else:
        print("[!] Failed to enqueue job.")
        return None

def query_logs_with_filter(firewall, api_key, filter_string):
    url = f"https://{firewall}/api/"
    params = {
        'type': 'log',
        'log-type': 'traffic',
        'query': filter_string,
        'nlogs': 25,
        'key': api_key
    }
    print("[+] Querying logs with provided filter...")
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    match = re.search(r'<job>(\d+)</job>', response.text)
    if match:
        job_id = match.group(1)
        return wait_for_job_completion(firewall, api_key, job_id)
    else:
        print("[!] Failed to enqueue job with filter.")
        return None

def write_to_csv(filename, table_data):
    # table_data is list of lists. The first row of table_data corresponds to first entry.
    # We know the headers from the extract_log_result method.
    headers = ["receive_time", "type", "src", "dst", "sport", "dport", "app", "action", "rule", "bytes", "session_end_reason"]
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(table_data)
    print(f"[+] Logs written to {filename}")

def main():
    parser = argparse.ArgumentParser(description="PANW NGFW Traffic Filter Script")
    parser.add_argument('-d', '--domain', help="FQDN to resolve and filter by destination IP.")
    parser.add_argument('-f', '--firewall', help="PANW Firewall IP/Hostname.")
    parser.add_argument('-l', '--last25', action='store_true', help="Retrieve the last 25 traffic logs.")
    parser.add_argument('-r', '--rule', help="Filter logs by rule.")
    parser.add_argument('-a', '--action', help="Filter logs by action.")
    parser.add_argument('-c', '--copy', action='store_true', help="Copy the generated filter to the clipboard.")
    parser.add_argument('-eq', action='store_true', help="Set operator to 'eq' for subsequent rule/action.")
    parser.add_argument('-neq', action='store_true', help="Set operator to 'neq' for subsequent rule/action.")
    parser.add_argument('-o', '--output', nargs='?', const='filtered_logs.csv', help="Output logs to CSV file. If no filename is provided, 'filtered_logs.csv' is used.")

    args = parser.parse_args()

    # If no firewall is provided, automatically copy the filter
    if not args.firewall:
        args.copy = True

    # Determine operator mode based on the order of arguments in sys.argv
    operator_mode = 'eq'
    i = 1
    final_rule = None
    final_action = None
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '-eq':
            operator_mode = 'eq'
        elif arg == '-neq':
            operator_mode = 'neq'
        elif arg == '-r':
            if i+1 < len(sys.argv):
                final_rule = (operator_mode, sys.argv[i+1])
                i += 1
        elif arg == '-a':
            if i+1 < len(sys.argv):
                final_action = (operator_mode, sys.argv[i+1])
                i += 1
        i += 1

    if args.rule and final_rule is None:
        final_rule = ('eq', args.rule)
    if args.action and final_action is None:
        final_action = ('eq', args.action)

    api_key = None
    if args.firewall:
        username = input("Enter firewall username: ")
        password = getpass.getpass("Enter firewall password: ")
        print("[+] Retrieving API key...")
        try:
            api_key = get_api_key(args.firewall, username, password)
            print("[+] API key retrieved successfully.")
        except Exception as e:
            print(f"[!] Error retrieving API key: {e}")
            return

    # Retrieve last 25 logs if requested
    last25_data = None
    if args.last25:
        if args.firewall and api_key:
            try:
                logs = query_last_25_logs(args.firewall, api_key)
                if logs:
                    table_string, table_data = logs
                    print("[+] Last 25 Firewall Logs:")
                    print(table_string)

                    # If output is requested
                    if args.output and table_data:
                        output_file = args.output
                        write_to_csv(output_file, table_data)
            except Exception as e:
                print(f"[!] Error retrieving logs: {e}")
                return
        else:
            print("[!] The -l/--last25 option requires -f/--firewall.")
            return

    # Build filter conditions
    filter_conditions = []

    # Domain-based filter
    if args.domain:
        try:
            validate_fqdn(args.domain)
            ips = get_a_records(args.domain)
            print(f"[+] Found IPs: {', '.join(ips)}")

            if len(ips) == 1:
                ip_filter = f"(addr.dst eq {ips[0]})"
            else:
                ip_filter = " or ".join([f"(addr.dst eq {ip})" for ip in ips])

            filter_conditions.append(f"({ip_filter})")
            print(f"[+] Generated Filter (Domain): {ip_filter}")
        except Exception as e:
            print(f"[!] Error: {e}")
            return

    # Rule filter if specified
    if final_rule:
        op, rule_value = final_rule
        filter_conditions.append(f"(rule {op} {rule_value})")

    # Action filter if specified
    if final_action:
        op, action_value = final_action
        filter_conditions.append(f"(action {op} {action_value})")

    # Combine all filter conditions
    if len(filter_conditions) > 1:
        final_filter = " and ".join(filter_conditions)
    elif len(filter_conditions) == 1:
        final_filter = filter_conditions[0]
    else:
        final_filter = ""

    if args.copy and final_filter:
        copy_to_clipboard(final_filter)
        print("[+] Filter copied to clipboard.")
    elif args.copy and not final_filter:
        print("[!] No filter to copy.")

    # Query logs with filter if we have a firewall, api_key and a filter
    # and if last25 wasn't already done
    if final_filter and args.firewall and api_key and not args.last25:
        filtered_logs = query_logs_with_filter(args.firewall, api_key, final_filter)
        if filtered_logs:
            table_string, table_data = filtered_logs
            print("[+] Filtered Logs:")
            print(table_string)
            # If output is requested
            if args.output and table_data:
                output_file = args.output
                write_to_csv(output_file, table_data)

    if not args.domain and not args.last25 and not final_filter:
        print("[!] No domain, no last25, no filter conditions provided.")

if __name__ == "__main__":
    main()
