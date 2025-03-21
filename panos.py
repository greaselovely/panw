import requests
import getpass
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_api_key(firewall, username, password):
    """Retrieve API key from the firewall."""
    url = f"https://{firewall}/api/"
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    key_elem = root.find("./result/key")
    if key_elem is not None:
        return key_elem.text
    else:
        raise ValueError("Failed to retrieve API key.")

def get_software_info_xml(firewall, api_key):
    url = f"https://{firewall}/api/"
    # Use 'check' instead of 'info'
    cmd = "<request><system><software><check></check></software></system></request>"
    params = {
        'type': 'op',
        'cmd': cmd,
        'key': api_key
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    return response.text

def parse_software_info(xml_text):
    """Extract release notes links from the firewall system software info XML."""
    # Adjust this logic based on actual XML structure
    root = ET.fromstring(xml_text)
    links = []
    # Assuming release-notes is a child element under .//entry
    for entry in root.findall(".//entry"):
        rn = entry.find("release-notes")
        if rn is not None and rn.text:
            links.append(rn.text.strip())
    return list(set(links))

def fetch_page(url):
    """Fetch a page and return its HTML text."""
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def extract_links_from_page(html, base_url=None):
    """Extract all links from a page."""
    soup = BeautifulSoup(html, 'html.parser')
    all_links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # If links are relative and we have a base_url, join them
        # In this example, we assume absolute URLs for simplicity.
        # from urllib.parse import urljoin
        # full_url = urljoin(base_url, href)
        # For now, just assume href is absolute or handle as needed:
        if href.startswith('http'):
            all_links.add(href)
        # else:
        #     all_links.add(urljoin(base_url, href))
    return all_links

def is_known_issues_page(html):
    """Heuristic check if the page is a known issues page."""
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find("table")
    if not table:
        return False
    headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
    return ("issue id" in headers and "description" in headers)

def parse_issues_table(html):
    """Parse a known issues table."""
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find("table")
    if not table:
        return []
    rows = table.find_all("tr")
    if not rows:
        return []
    headers = [th.get_text(strip=True) for th in rows[0].find_all("th")]
    issues = []
    for row in rows[1:]:
        cells = row.find_all("td")
        if len(cells) == len(headers):
            issue_data = {}
            for h, c in zip(headers, cells):
                issue_data[h] = c.get_text(strip=True)
            issues.append(issue_data)
    return issues

def main():
    # Ask for firewall credentials
    firewall = input("Enter firewall IP address or hostname: ").strip()
    username = input("Enter firewall username: ").strip()
    password = getpass.getpass("Enter firewall password: ")

    # Get API key
    try:
        api_key = get_api_key(firewall, username, password)
        print("[+] API key retrieved successfully.")
    except Exception as e:
        print(f"[!] Error retrieving API key: {e}")
        return

    # Get system software info
    try:
        sw_info_xml = get_software_info_xml(firewall, api_key)
        print("[+] System software info retrieved.")
    except Exception as e:
        print(f"[!] Error retrieving system software info: {e}")
        return

    # Parse release notes links
    initial_links = parse_software_info(sw_info_xml)

    print("[+] Extracted links from software info:")
    for link in initial_links:
        print("   ", link)

    # Traverse links to find known issues
    to_visit = set(initial_links)
    visited = set()
    all_issues = []

    while to_visit:
        link = to_visit.pop()
        if link in visited:
            continue
        visited.add(link)

        try:
            html = fetch_page(link)
        except Exception as e:
            print(f"[!] Error fetching {link}: {e}")
            continue

        if is_known_issues_page(html):
            # Parse table and collect issues
            issues = parse_issues_table(html)
            if issues:
                print(f"[+] Found {len(issues)} issues on page: {link}")
                all_issues.extend(issues)
        else:
            # Extract further links and add to queue
            found_links = extract_links_from_page(html, base_url=link)
            for fl in found_links:
                if fl not in visited:
                    to_visit.add(fl)

    # Print all collected issues
    if all_issues:
        print("[+] Collected Issues:")
        for issue in all_issues:
            print(issue)
    else:
        print("[+] No known issues found.")

if __name__ == "__main__":
    main()
