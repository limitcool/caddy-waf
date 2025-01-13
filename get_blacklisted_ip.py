import requests
import re
import ipaddress

# List of blocklist URLs and expected line formats
blocklist_sources = {
    "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "CI Army List": "http://cinsscore.com/list/ci-badguys.txt",
    "IPsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "BlockList.de": "https://www.blocklist.de/lists/all.txt",
}


def extract_ips(source_name, url):
    """Fetches data from the given URL and extracts IP addresses."""
    ips = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {source_name} from {url}: {e}")
        return ips

    if source_name == "Talos Intelligence":
        print(f"Skipping {source_name} due to webpage format, needs manual parsing.")
        return ips
    else:
        # Default parsing for normal text file blocklists
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Normalize ranges to single IPs
            if "/" in line:
                try:
                    for ip in ipaddress.ip_network(line, strict=False):
                        ips.add(str(ip))
                except ValueError:
                    continue
            elif "-" in line:
                try:
                    start, end = line.split('-')
                    start_ip = ipaddress.ip_address(start.strip())
                    end_ip = ipaddress.ip_address(end.strip())
                    if start_ip.version == end_ip.version:
                        for ip_int in range(int(start_ip), int(end_ip) + 1):
                            ips.add(str(ipaddress.ip_address(ip_int)))
                except ValueError:
                    continue
            else:
                try:
                    ipaddress.ip_address(line)
                    ips.add(line)
                except ValueError:
                    continue
        return ips


def is_valid_ip(ip_str):
    """Helper function to check if an IP address is valid."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def ip_to_int(ip_str):
    """Converts an IP address string to its integer representation."""
    try:
        return int(ipaddress.ip_address(ip_str))
    except ValueError:
        return None


def main():
    combined_ips = set()
    for source_name, url in blocklist_sources.items():
        print(f"Processing {source_name} from {url}")
        ips = extract_ips(source_name, url)
        print(f"  Found {len(ips)} IPs in {source_name}")
        combined_ips.update(ips)

    print(f"Total IPs before filtering: {len(combined_ips)}")
    # Filter out invalid IPs before sorting.
    valid_ips = [ip for ip in combined_ips if is_valid_ip(ip)]
    print(f"Total Valid IPs after filtering: {len(valid_ips)}")

    with open("ip_blacklist.txt", "w") as f:
        # Sort using the integer representation and write each IP to the file
        for ip in sorted(valid_ips, key=ip_to_int):
            f.write(f"{ip}\n")

    print("IP blacklist saved to ip_blacklist.txt")


if __name__ == "__main__":
    main()
