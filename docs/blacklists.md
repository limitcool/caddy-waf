# 🚫 Blacklists

This document outlines the formats used for various blacklists. These lists are utilized to identify and block potentially malicious or unwanted entities. Each list type has its own specific syntax and interpretation rules to ensure proper functionality.

## General Considerations

*   **Case Sensitivity:** While DNS blacklist entries are explicitly lowercased, IP addresses are generally treated as case-insensitive. Any hostname or resource record included in an IP blacklist should be standardized in lowercase.
*   **Line Handling:** Each entry must be on its own line.
*   **Whitespace:** Leading and trailing whitespace should generally be ignored (trimmed) before processing each line, unless specifically defined otherwise.
*   **Comments:** Lines beginning with `#` are considered comments and should be ignored by the processing logic.
*   **Empty Lines:** Empty lines are permitted and should be skipped.
*   **UTF-8 Encoding:** All blacklist files should be encoded using UTF-8 to ensure proper handling of international characters (in the rare case they appear in domain names) and avoid compatibility issues.
*   **Error Handling:** Malformed entries should be logged or handled gracefully, with an option to skip them rather than halt the entire process.
*   **Updates:** These lists may be automatically updated on a schedule.
*   **Performance:** The chosen formats are designed to be easily parsed and matched against for efficient runtime operations.

## IP Blacklist (`ip_blacklist.txt`)

*   **Purpose:** To block network traffic originating from or destined for specified IP addresses or address ranges.
*   **Format:**
    *   **Single IPv4 Addresses:** Standard dotted-decimal notation (e.g., `192.168.1.1`).
    *   **Single IPv6 Addresses:** Standard colon-separated hexadecimal notation (e.g., `2001:0db8:85a3:0000:0000:8a2e:0370:7334`, but also allows the shortened forms e.g., `2001:db8::7334`)
    *   **IPv4 CIDR Ranges:** Uses CIDR notation (e.g., `192.168.0.0/24`). Represents a contiguous block of IP addresses.
    *   **IPv6 CIDR Ranges:** Uses CIDR notation (e.g., `2001:db8::/32`). Represents a contiguous block of IPv6 addresses.
    *   **Comments:** Lines beginning with `#` are ignored.
*   **Example:**

    ```text
    192.168.1.1
    10.0.0.0/8
    2001:db8::/32
    2001:0db8:85a3:0000:0000:8a2e:0370:7334
    # This is a comment about a range
    172.16.0.0/12 # Private IP range
    172.16.1.250
    2a02:2700::/32
    ```
*   **Matching Logic:** An IP address being checked will be matched against each entry. A match is successful if the address is:
    *   Identical to a single IP address listed.
    *   Within the range defined by a CIDR notation entry.
*   **Implementation Notes:** A parser should validate entries against standard formats and potentially log invalid entries. Efficient data structures such as prefix trees (Tries) can enhance lookup performance, particularly with large lists.

## DNS Blacklist (`dns_blacklist.txt`)

*   **Purpose:** To block access to or from websites and services associated with specified domain names.
*   **Format:**
    *   One fully qualified domain name (FQDN) per line.
    *   Comments are supported using `#`.
    *   All entries will be converted to lowercase before matching.
    *   Subdomains are not automatically included, unless explicit entries exist for them, and wildcard domains are not supported within these lists.
    *   Internationalized Domain Names (IDNs) must be stored as Punycode, following standard conventions (e.g., `xn--domain--432a.com`).
*  **Example:**
  ```text
   malicious.com
   evil.example.org
   # Example of a comment
   phishing-site.net
   another.malware.com
   xn--domain--432a.com
  ```
*   **Matching Logic:** A hostname will be matched (in a case-insensitive manner once lowercased) against each entry in the list. A match occurs if the hostname being checked is *exactly* equal to an entry, e.g. `evil.example.org` would not match `sub.evil.example.org`. The matching should happen against the FQDN (Fully Qualified Domain Name).

