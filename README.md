# 🛡️ Caddy WAF Middleware

A robust and flexible **Web Application Firewall (WAF)** middleware for the Caddy web server, designed to provide **comprehensive protection** against a wide array of web-based attacks. This middleware integrates seamlessly with Caddy and offers a rich set of security features to safeguard your applications.

[![Go](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql) [![Build and test Caddy with WAF](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml) 

---

## 🌟 Key Features

*   **Rule-Based Filtering:** Regex-based rules to inspect URLs, arguments, body, headers, and cookies.
*   **IP/DNS Blacklisting:** Block traffic using IP or domain blacklists, including CIDR ranges.
*   **TOR Blacklisting:** Block traffic from TOR exit nodes (optonal).
*   **Country Blocking/Whitelisting:** Restrict or allow access by client location using GeoIP2 databases.
*   **Rate Limiting:** Prevent abuse with request limits per IP or specific paths.
*   **Anomaly Scoring:** Detect threats by scoring rule matches and blocking when thresholds are exceeded.
*   **Multi-Phase Inspection:** Analyze traffic across request/response phases for deeper protection.
*   **Request Redaction:** Redact sensitive data (e.g., passwords, tokens) from logs.
*   **Metrics:** JSON endpoint to analyze rules performances and optimize your WAF.

## 🚀 Quick Start

```bash
curl -fsSL -H "Pragma: no-cache" https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

**Example output:**

```
INFO    Starting caddy-waf    {"version": "v0.0.0-20250109090908-5a8c1c74fab0"}
INFO    Rate limit configuration        {"requests": 1000, "window": 60, "cleanup_interval": 300}
INFO    Starting rate limiter cleanup goroutine
INFO    GeoIP database loaded successfully    {"path": "GeoLite2-Country.mmdb"}
INFO    Rules loaded    {"file": "rules.json", "total_rules": 14, "invalid_rules": 0}
INFO    IP blacklist loaded successfully    {"file": "ip_blacklist.txt", "valid_entries": 3, "total_lines": 3}
INFO    DNS blacklist loaded successfully    {"file": "dns_blacklist.txt", "valid_entries": 2, "total_lines": 2}
INFO    Rules and Blacklists loaded successfully    {"total_rules": 14}
INFO    WAF middleware provisioned successfully
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
8.  [🌍 Country Blocking and Whitelisting](#-country-blocking-and-whitelisting)
9.  [🔄 Dynamic Updates](#-dynamic-updates)
10. [🧪 Testing](#-testing)
    *  [Basic Testing](#basic-testing)
    *  [Load Testing](#load-testing)
    *  [Security Testing Suite](#security-testing-suite)
11. [🐳 Docker Support](#-docker-support)
12. [🐍 Rule/Blacklist Population Scripts](#-ruleblacklist-population-scripts)
    * [get_owasp_rules.py](#get_owasp_rulespy)
    * [get_blacklisted_ip.py](#get_blacklisted_ippy)
    * [get_blacklisted_dns.py](#get_blacklisted_dnspy)
    * [get_spiderlabs_rules](get_spiderlabs_rules)
    * [get_vulnerability_rules](get_vulnerability_rules)
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
go get github.com/caddyserver/caddy/v2
go get github.com/caddyserver/caddy/v2/caddyconfig/caddyfile
go get github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile
go get github.com/caddyserver/caddy/v2/modules/caddyhttp
go get github.com/oschwald/maxminddb-golang
go get github.com/fsnotify/fsnotify
go get -v github.com/fabriziosalmi/caddy-waf
go mod tidy

# Step 5: Download the GeoLite2 Country database (required for country blocking/whitelisting)
wget https://git.io/GeoLite2-Country.mmdb

# Step 6: Build Caddy with the caddy-waf module
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./

# Step 7: Fix Caddyfile format
caddy fmt --overwrite

# Step 8: Run the compiled Caddy server
./caddy run
```

### Final Notes

*   Ensure your Go environment is properly configured and that you are using a compatible version of Go as specified in the `go.mod` file.
*   After building with `xcaddy`, verify the `http.handlers.waf` module by running `./caddy list-modules`.

---

## 🛠️ Configuration

### Basic Caddyfile Setup

```caddyfile
{
    auto_https off
    admin localhost:2019
}

:8080 {
    log {
        output stdout
        format console
        level INFO
    }

    handle {
        header -Server
    }

    route {
        # WAF Plugin runs on all requests first
        waf {
            metrics_endpoint /waf_metrics
            anomaly_threshold 10
            block_countries GeoLite2-Country.mmdb RU CN KP
            # whitelist_countries GeoLite2-Country.mmdb US

            # Rate Limiting Configuration
            rate_limit {
                requests 100
                window 10s
                cleanup_interval 5m
                paths /api/v1/.* /admin/.*  # List of individual regex patterns
                match_all_paths false
            }

            rule_file rules.json
            # rule_file rules/wordpress.json
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            log_severity info
            log_json
            log_path debug.json
            # redact_sensitive_data
        }

        # Match the waf metrics endpoint specifically and stop processing
        @wafmetrics path /waf_metrics
        handle @wafmetrics {
            # Do not respond here so it goes to the WAF plugin
        }

        # All other requests, respond with "Hello World"
        handle {
            respond "Hello world!" 200
        }
    }
}
```

---

## ⚙️ Configuration Options

| Option                 | Description                                                                                                    | Example                                                       |
|------------------------|----------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| `anomaly_threshold`    | Sets the anomaly score threshold at which requests will be blocked.                                             | `anomaly_threshold 20`                                          |
| `rule_file`            | Path to a JSON file containing the WAF rules.                                                                    | `rule_file rules.json`                                          |
| `ip_blacklist_file`    | Path to a file containing blacklisted IP addresses and CIDR ranges.                                               | `ip_blacklist_file blacklist.txt`                               |
| `dns_blacklist_file`   | Path to a file containing blacklisted domain names.                                                             | `dns_blacklist_file domains.txt`                               |
| `rate_limit`           | Configures the rate limiting parameters. The syntax is requests, window, and optional cleanup interval          | `rate_limit 100 1m 5m`                                          |
| `block_countries`      | Enables country blocking, requires the GeoIP database path and ISO country codes.                               | `block_countries GeoLite2-Country.mmdb RU CN KP`                   |
| `whitelist_countries`  | Enables country whitelisting, requires the GeoIP database path and ISO country codes.                           | `whitelist_countries GeoLite2-Country.mmdb US`                   |
| `log_severity`         | Sets the minimum logging level (`debug`, `info`, `warn`, `error`).                                              | `log_severity debug`                                           |
| `log_json`             | Enables JSON formatted log output.                                                                             | `log_json`                                                   |
| `log_path`             | Sets the path for the log file. If not specified it will default to `/var/log/caddy/waf.json`                        | `log_path debug.json`                                           |
| `redact_sensitive_data` | When enabled, it will redact sensitive data from the query string on the logs.                          | `redact_sensitive_data`                                           |
| `custom_response`     | Defines custom response for the specified status code, following the sintax custom_response STATUS_CODE content_type body_string_or_file_path  | `custom_response 403 application/json error.json` or `custom_response 403 text/html "<h1>Access Denied</h1>"`|

---

## 📜 Rules Format (`rules.json`)

Rules are defined in a JSON file as an array of objects. Each rule specifies how to match a pattern, what parts of the request to inspect, and what action to take when a match is found.

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
    },
     {
        "id": "sql-injection-header",
        "phase": 1,
        "pattern": "(?i)(?:select|insert|update|delete|union|drop|--|;)",
        "targets": ["HEADERS:X-Attack"],
        "severity": "CRITICAL",
        "action": "block",
        "score": 10,
        "description": "Detect and block SQL injection attempts in custom header."
    },
     {
        "id": "log4j-jndi",
         "phase": 2,
        "pattern": "(?i)\\$\\{jndi:(ldap|rmi|dns):\\/\\/.*\\}",
        "targets": ["BODY","ARGS","URI","HEADERS"],
       "severity": "CRITICAL",
        "action": "block",
        "score": 10,
        "description":"Detect Log4j vulnerability attempts"
     }

]
```

### Rule Fields

| Field        | Description                                                                           | Example                                |
|--------------|---------------------------------------------------------------------------------------|----------------------------------------|
| `id`         | Unique identifier for the rule.                                                      | `sql_injection_1`                      |
| `phase`      | Processing phase (1: Request Headers, 2: Request Body, 3: Response Headers, 4: Response Body).| `2`                                    |
| `pattern`    | Regular expression to match malicious patterns.                                      | `(?i)(?:select|insert|update)`        |
| `targets`    | Array of request parts to inspect, which can be: `URI`, `ARGS`, `BODY`, `HEADERS`, `COOKIES`, `HEADERS:<header_name>`,  `RESPONSE_HEADERS`, `RESPONSE_BODY`, `RESPONSE_HEADERS:<header_name>`, or `COOKIES:<cookie_name>`.| `["ARGS", "BODY"]`                     |
| `severity`   | Severity of the rule (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).  Used only for logging.        | `CRITICAL`                             |
| `action`     | Action to take on match (`block` or `log`). If empty, defaults to `block`.            | `block`                                |
| `score`      | Anomaly score to add when this rule matches.                                        | `5`                                    |
| `description`| A descriptive text for the rule.                                                      | `Detect SQL injection`                 |

### Rules metrics
You can understand what's going under the hood and tune your ruleset by inspecting the rules metrics endpoints or process such stats with others tools.

```
caddy-waf % curl -fsSL http://localhost:8080/waf_metrics | jq .
{
  "block-bad-bots": 12,
  "common-credentials-in-body": 43,
  "exposed-admin-panels-no-referer": 65,
  "log4j-exploit": 26,
  "mass-assignment-indicators": 2,
  "path-traversal": 900,
  "rce-command-injection-args": 40,
  "rce-commands": 149,
  "rce-separators": 11,
  "reflected-xss-on-error-pages": 1,
  "scanner-detection": 12,
  "sensitive-files": 84,
  "sql-injection": 106,
  "sql-injection-comment-bypass-args": 12,
  "sql-injection-comment-bypass-body": 33,
  "sql-injection-common-keywords-body": 2,
  "suspicious-auth-headers": 492,
  "suspicious-file-uploads": 41,
  "unusual-paths": 1546,
  "xss": 354
}
```

---

## 🛡️ Protected Attack Types

1.  **SQL Injection (SQLi):** Detects attempts to inject malicious SQL code.
2.  **Cross-Site Scripting (XSS):** Protects against injection of malicious scripts.
3.  **Path Traversal:** Blocks access to restricted files/directories.
4.  **Remote Code Execution (RCE):** Detects attempts to execute arbitrary commands.
5.  **Log4j Exploits:** Identifies and blocks Log4j related attack patterns.
6.  **Protocol Attacks:** Protects against access to sensitive protocol or configuration files.
7.  **Scanner Detection:** Identifies known vulnerability scanners.

---

## 🚫 Blacklist Formats

### IP Blacklist (`ip_blacklist.txt`)

*   Supports single IP addresses, CIDR ranges, and comments (lines starting with `#`).

```text
192.168.1.1
10.0.0.0/8
2001:db8::/32
# This is a comment
```

### DNS Blacklist (`dns_blacklist.txt`)

*   Contains one domain per line (comments are allowed with `#`).
*   All entries are lowercased before matching.

```text
malicious.com
evil.example.org
# This is a comment
```

---

## ⏱️ Rate Limiting

Configure rate limits using requests count, time window, and optional cleanup interval. You can also specify paths to apply rate limiting selectively:

```caddyfile
rate_limit {
    requests 100
    window 10s
    cleanup_interval 5m
    paths /api/v1/.* /admin/.*  # List of individual regex patterns
    match_all_paths false
}
```

*   The rate limiter is based on the client IP address.
*   The cleanup interval controls how frequently the rate limiter clears expired entries from memory.
*   When the requests count is greater than the specified value for the defined period, the request will be blocked.
*   Use `paths` to specify regex patterns for selective rate limiting. If `match_all_paths` is `false`, only the specified paths will be rate-limited.

---

## 🌍 Country Blocking and Whitelisting

*   Uses the MaxMind GeoIP2 database for country lookups.
*   Download the `GeoLite2-Country.mmdb` file (see [Installation](#-installation)).
*   Use `block_countries` or `whitelist_countries` with ISO country codes:

```caddyfile
# Block requests from Russia, China, and North Korea
block_countries /path/to/GeoLite2-Country.mmdb RU CN KP

# Whitelist requests from the United States
whitelist_countries /path/to/GeoLite2-Country.mmdb US
```

*   **Note:** Only one of `block_countries` or `whitelist_countries` can be enabled at a time.
*   When GeoIP lookup fails, the fallback behavior is configurable using the `WithGeoIPLookupFallbackBehavior` option when instantiating the middleware. Default behavior is to log and treat the lookup as not in the list. Options are `none` to block if the lookup fails or a specific country code to fallback to. For example, setting it to `US` will allow requests from IPs if the GeoIP lookup fails and `US` was in the list of allowed countries.

---

## 🔄 Dynamic Updates

*   Most changes to the configuration (rules, blacklists, etc) can be applied without restarting Caddy.
*   File watchers monitor the changes on your rules and blacklist files and trigger the automatic reload.
*   Simply modify the related files and the changes will be applied automatically by the file watcher.
*   To reload configurations using the Caddy API execute `caddy reload`.

---

## 🧪 Testing

### Basic Testing

The included `test.sh` script sends a series of `curl` requests to test various attack scenarios:

```bash
./test.sh
```
### Load Testing

Use a tool like `ab` to perform load testing:
```bash
ab -n 1000 -c 100 http://localhost:8080/
```

### Security Testing Suite

The `test.sh` script will provide a comprehensive check if the rules configured are working. 
*   Each test will be passed or failed based on the configured WAF configuration.
*   The output log contains the result for each test along with a summary.
*   An overall percentage is given at the end, and if the percentage is less than 90% it is recommended to check the output log to analyse the cause of the failing tests.

---

## 🐳 Docker Support

Build and run a Docker container:

```bash
# Build the Docker image
docker build -t caddy-waf .

# Run the Docker container, mapping port 8080
docker run -p 8080:8080 caddy-waf
```

---

## 🐍 Rule/Blacklist Population Scripts

Scripts to generate/download rules and blacklists:

### `get_owasp_rules.py`

*   Fetches OWASP core rules and converts them to the required JSON format.

```bash
python3 get_owasp_rules.py
```

### `get_blacklisted_ip.py`

*   Downloads IPs from several external sources.

```bash
python3 get_blacklisted_ip.py
```

### `get_blacklisted_dns.py`

*   Downloads blacklisted domains from various sources.

```bash
python3 get_blacklisted_dns.py
```
### `get_spiderlabs_rules.py`

*   Downloads rules from SpiderLabs.

```bash
python3 get_spiderlabs_rules.py
```

### `get_vulnerability_rules.py`

*   Downloads rules related to known vulnerabilities.

```bash
python3 get_vulnerability_rules.py
```

---

## 📜 License

This project is licensed under the **AGPLv3 License**.

---

## 🙏 Contributing

Contributions are highly welcome! Feel free to open an issue or submit a pull request.
