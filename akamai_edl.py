import requests
import ipaddress
from datetime import datetime
import sys


core_cdn_asns = [
    16625,  # Akamai Technologies - North America
    20940,  # Akamai International B.V. - Europe/Global
    23454,  # Akamai Technologies - Additional North America capacity
    35994,  # Akamai Technologies - Additional Global capacity
    43639   # Akamai Technologies - Additional CDN capacity
]

def get_ip_prefixes_for_asn(asn):
    """
    Get all IP prefixes for a given ASN using multiple data sources.
    
    Args:
        asn (int): ASN number
        
    Returns:
        list: List of IP prefixes (CIDR notation)
    """
    prefixes = []
    
    # Try RIPE STAT API first
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        response = requests.get(url, timeout=30)
        data = response.json()
        
        if "data" in data and "prefixes" in data["data"]:
            ripe_prefixes = [prefix["prefix"] for prefix in data["data"]["prefixes"]]
            prefixes.extend(ripe_prefixes)
            print(f"  Found {len(ripe_prefixes)} prefixes from RIPE for ASN {asn}")
    except Exception as e:
        print(f"  Error getting prefixes from RIPE for ASN {asn}: {str(e)}")
    
    # Try BGPView API as a backup
    if not prefixes:
        try:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            response = requests.get(url, timeout=30)
            data = response.json()
            
            if data.get("status") == "ok":
                bgpview_ipv4 = [item["prefix"] for item in data.get("data", {}).get("ipv4_prefixes", [])]
                bgpview_ipv6 = [item["prefix"] for item in data.get("data", {}).get("ipv6_prefixes", [])]
                
                prefixes.extend(bgpview_ipv4)
                prefixes.extend(bgpview_ipv6)
                print(f"  Found {len(bgpview_ipv4)} IPv4 and {len(bgpview_ipv6)} IPv6 prefixes from BGPView for ASN {asn}")
        except Exception as e:
            print(f"  Error getting prefixes from BGPView for ASN {asn}: {str(e)}")
    
    # Remove duplicates
    unique_prefixes = list(set(prefixes))
    
    return unique_prefixes


def main():
    print("Akamai CDN IP Address Collector")
    print("-------------------------------")
    
    print(f"Using these Akamai CDN ASNs: {', '.join(map(str, core_cdn_asns))}")
    
    # Get all prefixes for each ASN
    all_prefixes = []
    asn_to_prefixes = {}  # Track which prefixes belong to which ASN
    
    for asn in core_cdn_asns:
        print(f"Fetching prefixes for ASN {asn}...")
        prefixes = get_ip_prefixes_for_asn(asn)
        print(f"Found {len(prefixes)} prefixes for ASN {asn}")
        all_prefixes.extend(prefixes)
        
        # Store mapping of ASN to its prefixes
        asn_to_prefixes[asn] = prefixes
    
    # Remove duplicates
    unique_prefixes = list(set(all_prefixes))
    print(f"Total unique prefixes: {len(unique_prefixes)}")
    
    # Separate IPv4 and IPv6 prefixes
    ipv4_prefixes = []
    ipv6_prefixes = []
    
    for prefix in unique_prefixes:
        try:
            network = ipaddress.ip_network(prefix)
            if network.version == 4:
                ipv4_prefixes.append(prefix)
            elif network.version == 6:
                ipv6_prefixes.append(prefix)
        except Exception as e:
            print(f"Error processing prefix {prefix}: {str(e)}")
    
    print(f"Found {len(ipv4_prefixes)} IPv4 prefixes and {len(ipv6_prefixes)} IPv6 prefixes")
    
    # Generate metadata header for files
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    # Write IPv4 prefixes to file
    ipv4_filename = f"akamai_cdn_v4.txt"
    with open(ipv4_filename, "w") as f:
        f.write(f"# Akamai CDN IPv4 Prefixes\n")
        f.write(f"# Generated on: {date_str}\n")
        f.write(f"# ASNs: {', '.join([str(asn) for asn in core_cdn_asns])}\n\n")
        
        for prefix in ipv4_prefixes:
            f.write(f"{prefix}\n")
    
    # Write IPv6 prefixes to file
    ipv6_filename = f"akamai_cdn_v6.txt"
    with open(ipv6_filename, "w") as f:
        f.write(f"# Akamai CDN IPv6 Prefixes\n")
        f.write(f"# Generated on: {date_str}\n")
        f.write(f"# ASNs: {', '.join([str(asn) for asn in core_cdn_asns])}\n\n")
        
        for prefix in ipv6_prefixes:
            f.write(f"{prefix}\n")
    
    print(f"IPv4 prefixes written to: {ipv4_filename}")
    print(f"IPv6 prefixes written to: {ipv6_filename}")


if __name__ == "__main__":
    main()