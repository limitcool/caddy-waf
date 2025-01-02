import requests
import os
import re
import ipaddress

# URLs of the malicious IP lists
ip_list_urls = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://iplists.firehol.org/files/firehol_level1.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://www.projecthoneypot.org/list_of_ips.php",
    "https://www.abuseipdb.com/statistics"
]

output_file = "ip_blacklist.txt"

# Temporary directory to store downloaded files
temp_dir = "temp_ip_lists"
os.makedirs(temp_dir, exist_ok=True)

ip_set = set()

ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')

# Function to check if IP is public and valid
def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_network(ip, strict=False)
        return not (ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_loopback)
    except ValueError:
        return False

# Download and process each list
def download_ip_list(url, temp_dir):
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

for url in ip_list_urls:
    file_path = download_ip_list(url, temp_dir)
    if file_path:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if ip_regex.match(line) and is_valid_public_ip(line):
                    ip_set.add(line)

# Write deduplicated IPs to output file
with open(output_file, "w") as f:
    for ip in sorted(ip_set):
        f.write(ip + "\n")

print(f"Merged IP list saved to {output_file}")

# Cleanup temporary files
for temp_file in os.listdir(temp_dir):
    os.remove(os.path.join(temp_dir, temp_file))
os.rmdir(temp_dir)
