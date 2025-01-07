# 🛡️ Caddy WAF Middleware

A **simple Web Application Firewall (WAF)** middleware for the Caddy server, designed to provide **comprehensive protection** against web attacks. This middleware integrates seamlessly with Caddy and offers a wide range of security features to safeguard your applications.

[![Go](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml)

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

# Step 8: Run the compiled Caddy server
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
            anomaly_threshold 5

            # Rate limiting: 1000 requests per 1 minute
            rate_limit 1000 1m

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
| `block_countries` | Country blocking config | `block_countries GeoLite2-Country.mmdb RU CN NK` |
| `whitelist_countries` | Country whitelisting config  | `whitelist_countries GeoLite2-Country.mmdb US GB CA`|
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

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Unique rule identifier | `sql_injection` |
| `phase` | Processing phase (1-2) | `1` |
| `pattern` | Regular expression pattern | `(?i)(?:select|insert)` |
| `targets` | Areas to inspect | `["ARGS", "BODY"]` |
| `severity` | Rule severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) | `CRITICAL` |
| `action` | Action to take (`block`, `log`) | `block` |
| `score` | Score for anomaly detection | `10` |
| `description` | Rule description | `Block SQL injection attempts.` |

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
rate_limit 100 1m

# 10 requests per second
rate_limit 10 1s

# 1000 requests per hour
rate_limit 1000 1h
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
```bash
# Test rate limiting
for i in {1..10}; do curl -i http://localhost:8080/; done

# Test country blocking
curl -H "X-Real-IP: 1.2.3.4" http://localhost:8080/

# Test SQL injection protection
curl "http://localhost:8080/?id=1+UNION+SELECT+*+FROM+users"

# Test XSS protection
curl "http://localhost:8080/?input=<script>alert(1)</script>"
```

### Load Testing
```bash
ab -n 1000 -c 100 http://localhost:8080/
```

### Security Testing Suite

A `test.sh` script is included in this repository to perform a comprehensive security test suite. This script sends a series of forged `curl` requests, each designed to simulate a different type of attack.

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
