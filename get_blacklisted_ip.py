import requests  # For downloading IP lists from URLs
import os       # For file and directory operations
import re       # For regular expression pattern matching
import ipaddress  # For IP address validation and classification

# List of URLs containing known malicious IP addresses
ip_list_urls = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",      # Feodo Tracker botnet C&C servers
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",  # FireHOL Level 1 threats
    "https://cinsscore.com/list/ci-badguys.txt",                    # CINS Army list
    "https://iplists.firehol.org/files/firehol_level1.netset",      # Another FireHOL source
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",  # IPsum threat intelligence
    "https://www.projecthoneypot.org/list_of_ips.php",             # Project Honey Pot malicious IPs
    "https://www.abuseipdb.com/statistics"                         # AbuseIPDB reported addresses
]

# File where the final merged and deduplicated IP list will be saved
output_file = "ip_blacklist.txt"

# Create temporary directory to store downloaded IP lists
temp_dir = "temp_ip_lists"
os.makedirs(temp_dir, exist_ok=True)

# Set to store unique IP addresses
ip_set = set()

# Regular expression to match IPv4 addresses and CIDR notation
ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')

def is_valid_public_ip(ip):
    """
    Validates if an IP address or CIDR range is both valid and public.
    """
    try:
        ip_obj = ipaddress.ip_network(ip, strict=False)
        return not (ip_obj.is_private or
                   ip_obj.is_multicast or
                   ip_obj.is_reserved or
                   ip_obj.is_loopback)
    except ValueError:
        return False

def download_ip_list(url, temp_dir):
    """
    Downloads an IP list from given URL and saves it to temporary directory.
    """
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        filename = os.path.join(temp_dir, os.path.basename(url))
        with open(filename, "w") as f:
            f.write(response.text)
        return filename
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return None

# Process each IP list URL
for url in ip_list_urls:
    file_path = download_ip_list(url, temp_dir)
    if file_path:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if ip_regex.match(line) and is_valid_public_ip(line):
                    ip_set.add(line)

# Write deduplicated IPs to output file in sorted order
with open(output_file, "w") as f:
    for ip in sorted(ip_set):
        f.write(ip + "\n")

# Count individual IPs and IP ranges
individual_ips = []
ip_ranges = []
for ip in ip_set:
    if '/' in ip:
        ip_ranges.append(ip)
    else:
        individual_ips.append(ip)

# Calculate total unique IPs (including those in ranges)
total_unique_ips = len(individual_ips)
for ip_range in ip_ranges:
    network = ipaddress.ip_network(ip_range, strict=False)
    total_unique_ips += network.num_addresses

# Print counts
print(f"Total individual IPs: {len(individual_ips)}")
print(f"Total IP ranges: {len(ip_ranges)}")
print(f"Total unique IPs (including ranges): {total_unique_ips}")

# Save counts to a file
with open("ip_counts.txt", "w") as f:
    f.write(f"Total individual IPs: {len(individual_ips)}\n")
    f.write(f"Total IP ranges: {len(ip_ranges)}\n")
    f.write(f"Total unique IPs (including ranges): {total_unique_ips}\n")

# Cleanup: Remove temporary files and directory
for temp_file in os.listdir(temp_dir):
    os.remove(os.path.join(temp_dir, temp_file))
os.rmdir(temp_dir)
