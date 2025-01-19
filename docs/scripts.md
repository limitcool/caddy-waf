# 🐍 Rule/Blacklists Population Scripts

To facilitate the management and population of rules and blacklists for the WAF, a set of Python scripts are provided. These scripts automate the process of fetching, converting, and downloading rules and blacklists from various external sources. These scripts help to simplify the process of keeping the WAF up to date with the latest threat intelligence.

Here's a detailed explanation of each script and its purpose:

## `get_owasp_rules.py`

*   **Purpose:** This script is designed to fetch and process the OWASP Core Rule Set (CRS), which provides a foundation for general web application security. It fetches the rules, parses them, and converts them to the JSON format required by the WAF (`rules.json`).
*   **Functionality:**
    *   The script downloads the latest version of the OWASP CRS.
    *   It extracts relevant rules and their metadata.
    *   It converts the rules to the WAF's JSON format.
    *   It saves the converted rules into the `rules.json` file.
*   **Usage:**

    ```bash
    python3 get_owasp_rules.py
    ```

*   **Considerations:**
    *   Ensure you have the necessary Python libraries installed (you can install them via `pip install requests`, or using `requirements.txt` if the repository has one)
    *   The OWASP CRS is a large ruleset, so the script may take some time to execute.
    *   The script will not override any custom rules you have on your configuration.
    *   The script is configured to obtain OWASP rules from a specific source, you may need to check the script if that source changes.
    *   You may want to customize or filter the rules that are loaded from OWASP in order to reduce the number of rules being processed by your WAF.

## `get_blacklisted_ip.py`

*   **Purpose:** This script downloads IP addresses from multiple external sources of known malicious IPs. The script combines them and converts them into a plain text format suitable for the WAF's `ip_blacklist.txt` file.
*   **Functionality:**
    *   The script retrieves IP lists from various open-source threat intelligence feeds.
    *   It processes and combines these lists into a single list, removing duplicates and invalid entries.
    *   It saves the blacklisted IPs in the `ip_blacklist.txt` file, one IP address or CIDR block per line.
*   **Usage:**

    ```bash
    python3 get_blacklisted_ip.py
    ```
*   **Considerations:**
    *   The script requires an active internet connection to download lists from external sources.
    *   The script combines multiple threat feeds, it is recommended to review the sources to make sure that you trust those lists.
    *   The script might be slow depending on the number of IPs that need to be processed and downloaded.
    *   You may want to review and filter the IP lists before loading them into your WAF, to avoid blocking legitimate traffic.
    *   The script is configured to obtain IP address lists from specific sources, you may need to check the script if any of the sources change.

## `get_blacklisted_dns.py`

*   **Purpose:** This script downloads blacklisted domain names from several open-source threat intelligence feeds, creating the `dns_blacklist.txt` file.
*   **Functionality:**
    *   The script fetches domain name lists from various threat intelligence feeds.
    *   It merges and removes duplicates from the fetched lists.
    *   It converts the domain names to lowercase and saves them into the `dns_blacklist.txt` file, one domain name per line.
*   **Usage:**

    ```bash
    python3 get_blacklisted_dns.py
    ```
*   **Considerations:**
    *   The script requires an active internet connection to retrieve lists from external sources.
    *  The script combines multiple threat feeds, it is recommended to review the sources to make sure that you trust those lists.
    *   You may want to review and filter the domain lists before loading them into your WAF, to avoid blocking legitimate traffic.
    *   The script is configured to obtain domain lists from specific sources, you may need to check the script if any of the sources change.

## `get_spiderlabs_rules.py`

*   **Purpose:** This script retrieves rules from the SpiderLabs repository, which provides a collection of security rules developed by Trustwave SpiderLabs.
*   **Functionality:**
    *   The script downloads the latest version of the SpiderLabs rules.
    *   It parses the rules and converts them into the WAF's JSON rule format.
    *   It saves the converted rules into the `rules.json` file.
*   **Usage:**

    ```bash
    python3 get_spiderlabs_rules.py
    ```

*   **Considerations:**
     *   Ensure you have the necessary Python libraries installed (you can install them via `pip install requests`, or using `requirements.txt` if the repository has one).
    *   The script requires an active internet connection to download rules.
    *   The rules may contain configurations not compatible with your setup.
    *   You may want to customize or filter the rules that are loaded from SpiderLabs to reduce the number of rules being processed.
    *   The script is configured to obtain SpiderLabs rules from a specific source, you may need to check the script if that source changes.

## `get_vulnerability_rules.py`

*   **Purpose:** This script downloads rules related to specific known vulnerabilities. These rules are usually designed to protect against the exploitation of well-known flaws in software and web applications.
*   **Functionality:**
    *   The script fetches rules from a source that is providing rules about known vulnerabilities (CVEs).
    *   It parses the rules and converts them to JSON.
    *   The rules are added to the `rules.json` file.
*   **Usage:**

    ```bash
    python3 get_vulnerability_rules.py
    ```

*   **Considerations:**
    *   Ensure you have the necessary Python libraries installed.
    *   The script requires an active internet connection.
    *   The effectiveness of the rules depends on the quality and timeliness of the vulnerability information.
    *  The script is configured to obtain vulnerability rules from a specific source, you may need to check the script if that source changes.
   *   You may want to customize or filter the rules that are loaded for known vulnerabilities to reduce the number of rules being processed or if you have patched that specific vulnerability.

## `get_caddy_feeds.py`

*   **Purpose:** This script downloads pre-generated blacklists and rules from a specific repository, offering a convenient way to keep rules and blacklists up to date with community-driven content, from this repository.
*   **Functionality:**
    *   The script fetches pre-generated JSON rules, blacklists and other feeds from a specific GitHub repository.
    *   It saves the downloaded files to the appropriate locations so that they can be used by the WAF.
*   **Usage:**

    ```bash
    python3 get_caddy_feeds.py
    ```
*   **Considerations:**
    *   The script requires an active internet connection to download files from the repository.
    *  The repository is external, so you should trust the source before including the rules and blacklists.
    *   You may want to review and filter the files before using them, to avoid including unwanted content.
    *  The script is configured to obtain rules and blacklists from a specific repository, you may need to check the script if that source changes.

## General Considerations for all scripts:

*   **Dependencies:** Ensure that you have all the required Python libraries installed (e.g., `requests`, `json`, and others). You can often install the required dependencies using `pip install -r requirements.txt` or `pip install <dependency>`.
*   **Internet Connection:** All scripts require an active internet connection to download resources from external locations.
*   **File Paths:** The script may have hardcoded paths for the output files, check them to be sure they match your setup.
*  **Trust Sources:** Always verify the trustworthiness of the sources used by the scripts before downloading data.
*   **Customization:** You can modify these scripts to better fit your specific needs, such as:
    *   Adding new sources of rules and blacklists.
    *   Customizing the downloaded data before converting it to a specific format.
    *   Filtering out specific entries that may not be relevant for your application.
*  **Scheduling:** It is recommend to automate the execution of these scripts to regularly fetch updated threat intelligence feeds. This will require using a scheduler like `cron` or other similar system.
* **Combining scripts:** These scripts can be combined into a single script or scheduled via `cron` to update rules and blacklists automatically.
*  **Rate Limiting:** Be aware that if you execute these scripts too often from the same IP address, you might be rate limited by the source that serves the lists.
*  **Testing:** Test the rules and blacklists after you obtain them to make sure they are working correctly and that there are no false positives.
* **Maintenance**: These scripts require periodic maintenance, if any of the sources they consume are moved, removed or changed.
*   **Review**: Review the data obtained by those scripts before loading it into production, to ensure it does not have unwanted effects.

These scripts provide a powerful set of tools to streamline the management of WAF rules and blacklists. By using them regularly, you can maintain a strong security posture and protect your applications from various threats. Remember to adapt the scripts to meet your specific needs and environment.
