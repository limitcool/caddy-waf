import requests  # For downloading IP lists from URLs
import os       # For file and directory operations
import re       # For regular expression pattern matching
import ipaddress  # For IP address validation and classification
from tqdm import tqdm  # For progress bars
from concurrent.futures import ThreadPoolExecutor, as_completed  # For concurrent downloads
import logging  # For logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# List of URLs containing known malicious IP addresses
IP_LIST_URLS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",      # Feodo Tracker botnet C&C servers
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",  # FireHOL Level 1 threats
    "https://cinsscore.com/list/ci-badguys.txt",                    # CINS Army list
    "https://iplists.firehol.org/files/firehol_level1.netset",      # Another FireHOL source
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",  # IPsum threat intelligence
    "https://www.projecthoneypot.org/list_of_ips.php",             # Project Honey Pot malicious IPs
    "https://www.abuseipdb.com/statistics"                         # AbuseIPDB reported addresses
]

# File where the final merged and deduplicated IP list will be saved
OUTPUT_FILE = "ip_blacklist.txt"

# Temporary directory to store downloaded IP lists
TEMP_DIR = "temp_ip_lists"
os.makedirs(TEMP_DIR, exist_ok=True)

# Regular expression to match IPv4 addresses and CIDR notation
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')

# Set to store unique IP addresses
ip_set = set()

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
    Downloads an IP list from a given URL and saves it to a temporary directory.
    """
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        filename = os.path.join(temp_dir, os.path.basename(url))
        with open(filename, "w") as f:
            f.write(response.text)
        return filename
    except Exception as e:
        logging.error(f"Failed to download {url}: {e}")
        return None

def process_ip_list(file_path):
    """
    Processes a downloaded IP list file and extracts valid public IPs.
    """
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            for line in tqdm(lines, desc=f"Processing {os.path.basename(file_path)}", leave=False):
                line = line.strip()
                if IP_REGEX.match(line) and is_valid_public_ip(line):
                    ip_set.add(line)
    except Exception as e:
        logging.error(f"Failed to process {file_path}: {e}")

def download_and_process_all(urls, temp_dir):
    """
    Downloads and processes all IP lists concurrently.
    """
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(download_ip_list, url, temp_dir): url for url in urls}
        for future in tqdm(as_completed(futures), total=len(urls), desc="Downloading IP lists"):
            file_path = future.result()
            if file_path:
                process_ip_list(file_path)

def save_merged_ips(ip_set, output_file):
    """
    Saves the deduplicated and sorted IP list to the output file.
    """
    try:
        with open(output_file, "w") as f:
            for ip in sorted(ip_set):
                f.write(ip + "\n")
        logging.info(f"Merged IP list saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save merged IP list: {e}")

def calculate_ip_counts(ip_set):
    """
    Calculates and prints the counts of individual IPs, IP ranges, and total unique IPs.
    """
    individual_ips = [ip for ip in ip_set if '/' not in ip]
    ip_ranges = [ip for ip in ip_set if '/' in ip]

    total_unique_ips = len(individual_ips)
    for ip_range in tqdm(ip_ranges, desc="Calculating IPs in ranges"):
        network = ipaddress.ip_network(ip_range, strict=False)
        total_unique_ips += network.num_addresses

    print(f"Total individual IPs: {len(individual_ips)}")
    print(f"Total IP ranges: {len(ip_ranges)}")
    print(f"Total unique IPs (including ranges): {total_unique_ips}")

def cleanup_temp_dir(temp_dir):
    """
    Cleans up the temporary directory.
    """
    try:
        for temp_file in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, temp_file))
        os.rmdir(temp_dir)
        logging.info("Temporary files cleaned up.")
    except Exception as e:
        logging.error(f"Failed to clean up temporary directory: {e}")

def main():
    # Download and process all IP lists
    download_and_process_all(IP_LIST_URLS, TEMP_DIR)

    # Save the merged IP list to the output file
    save_merged_ips(ip_set, OUTPUT_FILE)

    # Calculate and print IP counts
    calculate_ip_counts(ip_set)

    # Clean up temporary files
    cleanup_temp_dir(TEMP_DIR)

if __name__ == "__main__":
    main()
