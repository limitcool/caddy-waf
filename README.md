# 🛡️ Caddy WAF Middleware

A **simple Web Application Firewall (WAF)** middleware for the Caddy server, designed to provide **comprehensive protection** against web attacks. This middleware integrates seamlessly with Caddy and offers a wide range of security features to safeguard your applications.

[![Go](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml) [![Build and test Caddy with WAF](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql)

## 🌟 Key Features

-   **Rule-based request filtering** with regex patterns.
-   **IP and DNS blacklisting** to block malicious traffic.
-   **Country-based blocking** using MaxMind GeoIP2.
-   **Rate limiting** per IP address to prevent abuse.
-   **Anomaly scoring system** for detecting suspicious behavior.
-   **Request inspection** (URL, args, body, headers, cookies, user-agent).
-   **Protection against common attacks** (SQL injection, XSS, RCE, Log4j, etc.).
-   **Detailed logging and monitoring** for security analysis.
-   **Dynamic rule reloading** without server restart.

## 🚀 Quick start
```
curl -fsSL -H "Pragma: no-cache" https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

**Example output**

```
INFO	http.handlers.waf	Provisioning WAF middleware	{"log_level": "info", "log_json": false, "anomaly_threshold": 10}
INFO	http.handlers.waf	Rate limit configuration	{"requests": 1000, "window": 60, "cleanup_interval": 300}
INFO	http.handlers.waf	GeoIP database loaded successfully	{"path": "GeoLite2-Country.mmdb"}
INFO	http.handlers.waf	Rules loaded successfully	{"file": "rules.json", "total_rules": 416, "invalid_rules": 0}
INFO	http.handlers.waf	Total rules loaded	{"total_rules": 416}
INFO	http.handlers.waf	IP blacklist loaded successfully	{"file": "ip_blacklist.txt", "valid_entries": 19219, "total_lines": 19220}
INFO	http.handlers.waf	DNS blacklist loaded successfully	{"file": "dns_blacklist.txt", "valid_entries": 766270, "total_lines": 766271}
INFO	http.handlers.waf	WAF middleware provisioned successfully
```

## 📑 Table of Contents
1.  [🚀 Installation](#-installation)
    *   [Final Notes](#final-notes)
2.  [🛠️ Configuration](#️-configuration)
    *   [Basic Caddyfile Setup](#basic-caddyfile-setup)
3.  [⚙️ Configuration Options](#️-configuration-options)
4.  [📜 Rules Format (`rules.json`)](#-rules-format-rulesjson)
    *   [Rule Fields](#rule-fields)
5.  [🛡️ Protected Attack Types](#️-protected-attack-types)
6.  [🚫 Blacklist Formats](#-blacklist-formats)
    *   [IP Blacklist (`ip_blacklist.txt`)](#ip-blacklist-ip_blacklisttxt)
    *   [DNS Blacklist (`dns_blacklist.txt`)](#dns-blacklist-dns_blacklisttxt)
7.  [⏱️ Rate Limiting](#️-rate-limiting)
8.  [🌍 Country Blocking](#-country-blocking)
9. [🔄 Dynamic Updates](#-dynamic-updates)
10. [🧪 Testing](#-testing)
    *  [Basic Testing](#basic-testing)
    *  [Load Testing](#load-testing)
    *  [Security Testing Suite](#security-testing-suite)
11. [🐳 Docker Support](#-docker-support)
12. [🐍 Rule/Blacklist Population Scripts](#-ruleblacklist-population-scripts)
    * [get_owasp_rules.py](#get_owasp_rulespy)
    * [get_blacklisted_ip.py](#get_blacklisted_ippy)
    * [get_blacklisted_dns.py](#get_blacklisted_dnspy)
13. [📜 License](#-license)
14. [🙏 Contributing](#-contributing)


---

## 🚀 Installation

```bash
# Step 1: Clone the caddy-waf repository from GitHub
git clone https://github.com/fabriziosalmi/caddy-waf.git

# Step 2: Navigate into the caddy-waf directory
cd caddy-waf

# Step 3: Clean up and update the go.mod file
go mod tidy

# Step 4: Fetch and install the required Go modules
go get -v github.com/fabriziosalmi/caddy-waf github.com/caddyserver/caddy/v2 github.com/oschwald/maxminddb-golang

# Step 5: Download the GeoLite2 Country database
wget https://git.io/GeoLite2-Country.mmdb

# Step 6 (optional): Clean up previous build artifacts
# rm -rf buildenv_*

# Step 7: Build Caddy with the caddy-waf module
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./

# Step 8: Fix Caddyfile format
caddy fmt --overwrite

# Step 9: Run the compiled Caddy server
./caddy run
```

### Final Notes

-   If you encounter any issues, ensure that your Go environment is set up correctly and that you're using a compatible version of Go (as specified in the `caddy-waf` repository's `go.mod` file).
-   After building Caddy with `xcaddy`, the resulting binary will include the WAF middleware. You can verify this by running:
    ```bash
    ./caddy list-modules
    ```
    Look for the `http.handlers.waf` module in the output.

---

## 🛠️ Configuration

### Basic Caddyfile Setup

```caddyfile
{
    auto_https off
    admin off
}

:8080 {
    log {
        output stdout
        format console
        level DEBUG
    }

    route {
        waf {
            # Anomaly threshold will block request if the score is => the threshold
            anomaly_threshold 10

            # Rate limiting: 1000 requests per 1 minute
            rate_limit 1000 1m 5m

            # Rules and blacklists
            rule_file rules.json
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt

            # Country blocking (requires MaxMind GeoIP2 database)
            block_countries GeoLite2-Country.mmdb RU CN KP

            # Whitelist countries (requires MaxMind GeoIP2 database)
            # whitelist_countries GeoLite2-Country.mmdb US

            # Set Log Severity
            log_severity debug

            # Set Log JSON output
            log_json
        }
        respond "Hello, world!" 200
    }
}
```

---

## ⚙️ Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `anomaly_threshold` | Sets the anomaly score threshold. | `anomaly_threshold 20` |
| `rule_file` | JSON file containing WAF rules | `rule_file rules.json` |
| `ip_blacklist_file` | File with blocked IPs/CIDR ranges | `ip_blacklist_file blacklist.txt` |
| `dns_blacklist_file` | File with blocked domains | `dns_blacklist_file domains.txt` |
| `rate_limit` | Rate limiting config | `rate_limit 100 1m` |
| `block_countries` | Country blocking config | `block_countries GeoLite2-Country.mmdb RU CN KP` |
| `whitelist_countries` | Country whitelisting config  | `whitelist_countries GeoLite2-Country.mmdb US`|
| `log_severity` | Sets the minimum logging severity level for this module. | `log_severity debug`|
| `log_json` | Enables JSON log output | `log_json` |

---

## 📜 Rules Format (`rules.json`)

Rules are defined in a JSON file. Each rule specifies a pattern to match, targets to inspect, and actions to take.

```json
[
    {
        "id": "wordpress-brute-force",
        "phase": 2,
        "pattern": "(?i)(?:wp-login\\.php|xmlrpc\\.php).*?(?:username=|pwd=)",
        "targets": ["URI", "ARGS"],
        "severity": "HIGH",
        "action": "block",
        "score": 8,
        "description": "Block brute force attempts targeting WordPress login and XML-RPC endpoints."
    }
]
```

### Rule Fields

| Field          | Description                                                             | Example                               |
|----------------|-------------------------------------------------------------------------|---------------------------------------|
| `id`           | Unique identifier for the rule, used to track and manage security policies.| `sql_injection`                       |
| `phase`        | Processing phase, executed in order (1 - request headers, 2 - body, 3 - response headers, 4 - response body).| `1`                                   |
| `pattern`      | Regular expression pattern for detecting threats, allows precise filtering of malicious payloads. | `(?i)(?:insert)`                  |
| `targets`      | Specifies areas of the request to inspect for malicious content (URI, ARGS, BODY, HEADERS, COOKIES). | `["ARGS", "BODY"]`                    |
| `severity`     | Rule severity indicates the risk level of the threat (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). | `CRITICAL`                                |
| `action`       | Defines the action to take when the rule matches (`block` or `log`). If unspecified, the default action is `block`. | default: `block`               |
| `score`        | Score added to the anomaly detection system when a rule matches, contributing to overall request evaluation.| `10`                                  |
| `description`  | Provides a human-readable explanation of the rule's purpose and conditions it checks for. | `Block SQL injection attempts.`       |
| `mode`         | Optional field that allows switching between strict blocking and passive logging. | `block` or `log`                        |
| `enabled`      | Boolean flag to enable or disable specific rules dynamically.              | `true`                                 |
| `log_detail`   | Additional logging level for matched rules, providing extended information during forensic analysis. | `true` or `false`                      |

Rules can be fine-tuned by adjusting the `score` and `severity` values, allowing greater flexibility in blocking decisions. More complex patterns targeting multiple request areas can be designed using regexes, ensuring multi-layered defense strategies are effectively enforced.



---

## 🛡️ Protected Attack Types

1.  **SQL Injection**
    *   Basic `SELECT`/`UNION` injections
    *   Time-based injection attacks
    *   Boolean-based injections
2.  **Cross-Site Scripting (XSS)**
    *   Script tag injection
    *   Event handler injection
    *   SVG-based XSS
3.  **Path Traversal**
    *   Directory traversal attempts
    *   Encoded path traversal
    *   Double-encoded traversal
4.  **Remote Code Execution (RCE)**
    *   Command injection
    *   Shell command execution
    *   System command execution
5.  **Log4j Exploits**
    *   JNDI lookup attempts
    *   Nested expressions
6.  **Protocol Attacks**
    *   Git repository access
    *   Environment file access
    *   Configuration file access
7.  **Scanner Detection**
    *   Common vulnerability scanners
    *   Web application scanners
    *   Network scanning tools

---

## 🚫 Blacklist Formats

### IP Blacklist (`ip_blacklist.txt`)

```text
192.168.1.1
10.0.0.0/8
2001:db8::/32
```

### DNS Blacklist (`dns_blacklist.txt`)

```text
malicious.com
evil.example.org
```

---

## ⏱️ Rate Limiting

Configure rate limits using requests count and time window:

```caddyfile
# 100 requests per minute
rate_limit 100 1m 5m

# 10 requests per second
rate_limit 10 1s 5m

# 1000 requests per hour
rate_limit 1000 1h 5m

# note the last 5m is the cleanup routine cycle to remove stale address from memory
```

---

## 🌍 Country Blocking

Block traffic from specific countries using ISO country codes:

```caddyfile
# Block requests from Russia, China, and North Korea
block_countries /path/to/GeoLite2-Country.mmdb RU CN KP
```

---

## 🔄 Dynamic Updates

Rules and blacklists can be updated without server restart:

1.  Modify `rules.json` or blacklist files.
2.  Reload Caddy: `caddy reload`.

---

## 🧪 Testing

### Basic Testing
A `test.sh` script is included in this repository to perform a comprehensive security test suite. This script sends a series of forged `curl` requests, each designed to simulate a different type of attack.

```bash
caddy-waf % ./test.sh
WAF Security Test Suite
Target: http://localhost:8080
Date: Mar  7 Gen 2025 01:12:22 CET
----------------------------------------
[✗] SQL Injection - SQL Server Version                           [200]
[✗] SQL Injection - SQL Server Time Delay                        [200]
[✓] SQL Injection - Oracle Time Delay                            [403]
[✗] SQL Injection - Error Based 1                                [200]
[✗] SQL Injection - Error Based 2                                [200]
[✗] SQL Injection - Error Based 3                                [200]
[✗] SQL Injection - MySQL user                                   [200]
[✗] SQL Injection - PostgreSQL user                              [200]
[✗] SQL Injection - Case Variation                               [200]
[✗] SQL Injection - Whitespace Variation                         [200]
[✗] SQL Injection - Obfuscation Variation                        [200]
[✗] SQL Injection - Unicode Variation                            [200]
[✗] SQL Injection - Triple URL Encoded Variation                 [200]
[✗] SQL Injection - OOB DNS Lookup                               [200]
[✗] SQL Injection - Oracle OOB DNS Lookup                        [200]
[✓] SQL Injection - Header - Basic Select                        [403]
[✓] SQL Injection - Cookie - Basic Select                        [403]
[✗] SQL Injection - Header - Basic Select                        [200]
[✗] SQL Injection - JSON body                                    [200]
[✓] XSS - Basic Script Tag                                       [403]

[✓] XSS - IMG Onerror                                            [403]
[✓] XSS - JavaScript Protocol                                    [403]
[✓] XSS - SVG Onload                                             [403]
[✓] XSS - Anchor Tag JavaScript                                  [403]
[✓] XSS - URL Encoded Script                                     [403]
[✓] XSS - Double URL Encoded                                     [403]
[✓] XSS - URL Encoded IMG                                        [403]
[✓] XSS - Body Onload                                            [403]
[✓] XSS - Input Onfocus Autofocus                                [403]
[✓] XSS - Breaking Out of Attribute                              [403]
[✓] XSS - HTML Encoded                                           [403]
[✓] XSS - IFRAME srcdoc                                          [403]
[✓] XSS - Details Tag                                            [403]
[✓] XSS - HTML Comment Breakout                                  [403]
[✓] Path Traversal - Basic                                       [403]

[✓] Path Traversal - Double Dot                                  [403]
[✓] Path Traversal - Triple Dot                                  [403]
[✓] Path Traversal - URL Encoded                                 [403]
[✗] Path Traversal - Double URL Encoded                          [200]
[✓] Path Traversal - Mixed Slashes                               [403]
[✗] Path Traversal - UTF-8 Encoded                               [200]
[✓] Path Traversal - Encoded and Literal                         [403]
[✓] Path Traversal - Mixed Encoding                              [403]
[✗] Path Traversal - Multiple Slashes                            [200]
[✓] RCE - Basic Command                                          [403]

[✓] RCE - Base64 Command                                         [403]
[✗] RCE - Backticks                                              [200]
[✗] RCE - List Files                                             [200]
[✗] RCE - Uname                                                  [200]
[✗] RCE - ID                                                     [200]
[✓] RCE - whoami Command                                         [403]
[✓] RCE - Echo Test                                              [403]
[✗] RCE - Hex Encoded Command                                    [200]
[✓] RCE - Curl Request                                           [403]
[✓] RCE - Wget Request                                           [403]
[✗] RCE - Ping                                                   [200]
[✗] RCE - PowerShell Command                                     [200]
[✗] Log4j - JNDI LDAP                                            [200]

[✗] Log4j - Environment                                          [200]
[✗] Log4j - JNDI RMI                                             [200]
[✗] Log4j - System Property                                      [200]
[✗] Log4j - Lowercase                                            [200]
[✗] Log4j - Uppercase                                            [200]
[✗] Log4j - Date                                                 [200]
[✓] Log4j - Base64                                               [403]
[✗] Log4j - Partial Lookup                                       [200]
[✗] Log4j - URL Encoded                                          [200]
[✓] Header - SQL Injection                                       [403]

[✓] Header - XSS Cookie                                          [403]
[✓] Header - Path Traversal                                      [403]
[✓] Header - Custom X-Attack                                     [403]
[✗] Header -  X-Forwarded-Host                                   [200]
[✓] Header - User-Agent SQL                                      [403]
[✗] Header -  Host Spoof                                         [200]
[✓] Header -  Accept-Language                                    [403]
[✓] Protocol - Git Access                                        [403]

[✓] Protocol - Env File                                          [403]
[✓] Protocol - htaccess                                          [403]
[✗] Protocol - Web.config Access                                 [200]
[✓] Protocol - Java Web Descriptor                               [403]
[✓] Protocol - SVN Access                                        [403]
[✗] Protocol - Robots.txt                                        [200]
[✗] Protocol - VS Code Settings                                  [200]
[✗] Protocol - config.php Access                                 [200]
[✗] Protocol - Apache Server Status                              [200]
[✓] Valid - Homepage                                             [200]

[✓] Valid - API Endpoint                                         [200]
[✓] Scanner - SQLMap                                             [403]

[✓] Scanner - Acunetix                                           [403]
[✓] Scanner - Nikto                                              [403]
[✓] Scanner - Nmap                                               [403]
[✓] Scanner - Dirbuster                                          [403]
[✓] Valid - Health Check                                         [200]

[✓] Valid - Chrome Browser                                       [200]
[✗] Scanner -  Burp Suite                                        [200]

[✓] Scanner - OWASP ZAP                                          [403]
[✓] Scanner - Nessus                                             [403]
[✓] Scanner - Qualys                                             [403]
[✓] Scanner -  Wfuzz                                             [403]
[✓] Scanner -  OpenVAS                                           [403]
----------------------------------------
Results Summary
Total Tests: 100
Passed: 57
Failed: 43
Pass Percentage: 57%
Warning:  Test pass percentage is below 90%. Review the failures!

Detailed results saved to: waf_test_results.log
```

### Load Testing
```bash
ab -n 1000 -c 100 http://localhost:8080/
```

---

## 🐳 Docker Support

A `Dockerfile` is included to simplify building a Docker image with the Caddy server and WAF middleware. Here's how to use it:

```bash
# Build the Docker image
docker build -t caddy-waf .

# Run the Docker container
docker run -p 8080:8080 caddy-waf
```

---

## 🐍 Rule/Blacklist Population Scripts

Three Python scripts are provided in this repository to help automate the population of your rules and blacklists:

### `get_owasp_rules.py`

This script fetches the OWASP core rules and converts them into the JSON format required for the WAF rules.

```bash
python3 get_owasp_rules.py
```

### `get_blacklisted_ip.py`

This script downloads the blacklisted IPs from several external sources.

```bash
python3 get_blacklisted_ip.py
```

### `get_blacklisted_dns.py`

This script downloads blacklisted domains from various sources.

```bash
python3 get_blacklisted_dns.py
```

---

## 📜 License

This project is licensed under the **AGPLv3 License**.

---

## 🙏 Contributing

Contributions are welcome! Please open an issue or submit a pull request.
