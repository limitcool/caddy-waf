# 🛡️ Caddy WAF Middleware

A robust, highly customizable, and feature-rich **Web Application Firewall (WAF)** middleware for the Caddy web server. This middleware provides **advanced protection** against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

[![Go](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql) [![Build and test Caddy with WAF](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml)


## 🛡️ Core Protections

*   **Regex-Based Filtering:** Deep URL, data & header inspection using powerful regex rules.
*   **Blacklisting:** Blocks malicious IPs, domains & optionally TOR exit nodes.
*  **Geo-Blocking:** Restricts access by country using GeoIP.
*   **Rate Limiting:** Prevents abuse via customizable IP request limits.
*   **Anomaly Scoring:** Dynamically blocks requests based on cumulative rule matches.
*   **Multi-Phase Inspection:** Analyzes traffic throughout the request lifecycle.
*   **Sensitive Data Redaction:** Removes private info from logs.
*   **Custom Response Handling:** Tailored responses for blocked requests.
*   **Detailed Monitoring:** JSON endpoint for performance tracking & analysis.
*   **Dynamic Config Reloads:** Seamless updates without restarts.
*   **File Watchers:** Automatic reloads on rule/blacklist changes.
*   **Wide-Ranging Attack Detection:** [ *Implied, but consider a few common types if desired e.g., SQLi, XSS, etc.*]


## 🚀 Quick Start

```bash
curl -fsSL -H "Pragma: no-cache" https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

**Example Output:**

```
INFO    Provisioning WAF middleware     {"log_level": "info", "log_path": "debug.json", "log_json": true, "anomaly_threshold": 10}
INFO    http.handlers.waf       Updated Tor exit nodes in IP blacklist  {"count": 1077}
INFO    WAF middleware version  {"version": "v0.0.0-20250115164938-7f35253f2ffc"}
INFO    Rate limit configuration        {"requests": 100, "window": 10, "cleanup_interval": 300, "paths": ["/api/v1/.*", "/admin/.*"], "match_all_paths": false}
WARN    GeoIP database not found. Country blocking/whitelisting will be disabled        {"path": "GeoLite2-Country.mmdb"}
INFO    IP blacklist loaded successfully        {"file": "ip_blacklist.txt", "valid_entries": 3, "total_lines": 3}
INFO    DNS blacklist loaded successfully       {"file": "dns_blacklist.txt", "valid_entries": 2, "total_lines": 2}
INFO    Rules loaded    {"file": "rules.json", "total_rules": 70, "invalid_rules": 0}
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
    *   [Rules Metrics](#rules-metrics)
5.  [🛡️ Protected Attack Types](#️-protected-attack-types)
6.  [🚫 Blacklist Formats](#-blacklist-formats)
    *   [IP Blacklist (`ip_blacklist.txt`)](#ip-blacklist-ip_blacklisttxt)
    *   [DNS Blacklist (`dns_blacklist.txt`)](#dns-blacklist-dns_blacklisttxt)
7.  [⏱️ Rate Limiting](#️-rate-limiting)
8.  [🌍 Country Blocking and Whitelisting](#-country-blocking-and-whitelisting)
    *   [GeoIP Lookup Fallback](#geoip-lookup-fallback)
9.  [🔄 Dynamic Updates](#-dynamic-updates)
10. [🧪 Testing](#-testing)
    *   [Basic Testing](#basic-testing)
    *   [Load Testing](#load-testing)
    *   [Security Testing Suite](#security-testing-suite)
11. [🐳 Docker Support](#-docker-support)
12. [🐍 Rule/Blacklist Population Scripts](#-ruleblacklist-population-scripts)
    *   [get\_owasp\_rules.py](#get_owasp_rulespy)
    *   [get\_blacklisted\_ip.py](#get_blacklisted_ippy)
    *   [get\_blacklisted\_dns.py](#get_blacklisted_dnspy)
    *   [get\_spiderlabs\_rules.py](#get_spiderlabs_rulespy)
    *   [get\_vulnerability\_rules.py](#get_vulnerability_rulespy)
    *   [get\_caddy\_feeds.py](#get_caddy_feeds.py)
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
*   The `GeoLite2-Country.mmdb` needs to be in the same directory as `caddy` or a correct path should be passed to the `block_countries` or `whitelist_countries` configuration parameter.

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
                 paths /api/v1/.* /admin/.*   # List of regex patterns
                match_all_paths false   # When `true` it will apply only to the specified paths, `false` will rate limit all paths
            }

            rule_file rules.json
            # rule_file rules/wordpress.json
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            log_severity info
            log_json
            log_path debug.json
            # redact_sensitive_data
              # custom_response 403 application/json error.json # Loads a json file for custom response
              # custom_response 403 text/html "<h1>Access Denied</h1>" # Custom text/html response

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

| Option                 | Description                                                                                                                                                                                                | Example                                                                                                        |
|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `anomaly_threshold`    | Sets the anomaly score threshold at which requests will be blocked.                                                                                                                                      | `anomaly_threshold 20`                                                                                     |
| `rule_file`            | Path to a JSON file containing the WAF rules.                                                                                                                                                             | `rule_file rules.json`                                                                                     |
| `ip_blacklist_file`    | Path to a file containing blacklisted IP addresses and CIDR ranges.                                                                                                                                       | `ip_blacklist_file blacklist.txt`                                                                            |
| `dns_blacklist_file`   | Path to a file containing blacklisted domain names.                                                                                                                                                     | `dns_blacklist_file domains.txt`                                                                             |
| `rate_limit`           | Configures the rate limiting parameters. The syntax is `requests`, `window`, and optional `cleanup_interval`.  Use `paths` to set specific paths to rate limit, and `match_all_paths` to specify if only matching paths should be rate limited (`false`), or all paths except matching should be rate limited (`true`).   | `rate_limit { requests 100 window 1m cleanup_interval 5m paths /api/v1/.* /admin/.* match_all_paths false }`            |
| `block_countries`      | Enables country blocking, requires the GeoIP database path and ISO country codes.                                                                                                                          | `block_countries GeoLite2-Country.mmdb RU CN KP`                                                              |
| `whitelist_countries`  | Enables country whitelisting, requires the GeoIP database path and ISO country codes.                                                                                                                      | `whitelist_countries GeoLite2-Country.mmdb US`                                                              |
| `log_severity`         | Sets the minimum logging level (`debug`, `info`, `warn`, `error`).                                                                                                                                      | `log_severity debug`                                                                                        |
| `log_json`             | Enables JSON formatted log output.                                                                                                                                                                       | `log_json`                                                                                                   |
| `log_path`             | Sets the path for the log file. If not specified, it will default to `/var/log/caddy/waf.json`.                                                                                                             | `log_path debug.json`                                                                                       |
| `redact_sensitive_data` | When enabled, it will redact sensitive data from the query string on the logs.                                                                                                                             | `redact_sensitive_data`                                                                                       |
| `custom_response`      | Defines a custom response for the specified status code, following the syntax `custom_response STATUS_CODE content_type body_string_or_file_path`. Can load from a file or use a plain text string as response.  | `custom_response 403 application/json error.json` or `custom_response 403 text/html "<h1>Access Denied</h1>"`   |

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

| Field         | Description                                                                                                                                | Example                                         |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| `id`          | Unique identifier for the rule.                                                                                                            | `sql_injection_1`                               |
| `phase`       | Processing phase (1: Request Headers, 2: Request Body, 3: Response Headers, 4: Response Body).                                              | `2`                                             |
| `pattern`     | Regular expression to match malicious patterns. Use `(?i)` for case insensitive matching.                                                  | `(?i)(?:select|insert|update)`                 |
| `targets`     | Array of request parts to inspect, which can be: `URI`, `ARGS`, `BODY`, `HEADERS`, `COOKIES`, `HEADERS:<header_name>`,  `RESPONSE_HEADERS`, `RESPONSE_BODY`, `RESPONSE_HEADERS:<header_name>`, or `COOKIES:<cookie_name>`.| `["ARGS", "BODY"]`                               |
| `severity`    | Severity of the rule (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). Used only for logging and metric reporting.                                   | `CRITICAL`                                      |
| `action`      | Action to take on match (`block` or `log`). If empty or invalid, defaults to `block`.                                                     | `block`                                         |
| `score`       | Anomaly score to add when this rule matches.                                                                                                | `5`                                             |
| `description` | A descriptive text for the rule.                                                                                                            | `Detect SQL injection`                          |

### Rules Metrics

You can gain insights into your WAF's behavior, optimize your ruleset, and monitor your traffic by inspecting the metrics endpoint or processing such stats with other tools. This endpoint provides detailed information about requests, rule hits, and GeoIP statistics.

```
caddy-waf % curl -fsSL http://localhost:8080/waf_metrics | jq .
{
  "allowed_requests": 1209,
  "blocked_requests": 6275,
  "geoip_stats": {},
  "rule_hits": {
    "942440": 52,
    "allow-legit-browsers": 79,
    "block-scanners": 390,
    "crlf-injection-headers": 8,
    "header-attacks": 13,
    "header-attacks-consolidated": 279,
    "header-suspicious-x-forwarded-for": 39,
    "idor-attacks": 401,
    "insecure-deserialization-java": 13,
    "jwt-tampering": 117,
    "nosql-injection-attacks": 65,
    "open-redirect-attempt": 179,
    "path-traversal": 361,
    "rce-command-injection-args": 13,
    "rce-command-injection-body": 572,
    "rce-commands": 234,
    "rce-commands-expanded": 169,
    "sensitive-files": 59,
    "sensitive-files-expanded": 24,
    "sql-injection": 104,
    "sql-injection-comment-bypass-args": 416,
    "sql-injection-improved-basic": 715,
    "ssti-attacks": 65,
    "unusual-paths": 373,
    "xml-injection-attacks": 115,
    "xss": 156,
    "xss-attacks": 407,
    "xss-improved-encoding": 1638
  },
  "rule_hits_by_phase": {
    "1": 1297,
    "2": 5759
  },
  "total_requests": 7484
}
```

*   `allowed_requests`: Total number of requests that were allowed by the WAF.
*   `blocked_requests`: Total number of requests that were blocked by the WAF.
*  `geoip_stats`: Statistics about GeoIP lookups (if enabled).
*   `rule_hits`: An object showing how many times each rule has matched a request. The keys represent the rule IDs, and the values represent the number of matches.
*   `rule_hits_by_phase`: An object showing how many hits were recorded for each phase of request processing. The keys are the numeric phase identifiers, and values show the number of hits within each phase.
*   `total_requests`: The total number of requests processed by the WAF.

---

## 🛡️ Protected Attack Types

1.  **SQL Injection (SQLi):** Detects and blocks attempts to inject malicious SQL code.
2.  **Cross-Site Scripting (XSS):** Protects against the injection of malicious scripts into web pages.
3.  **Path Traversal:** Blocks access to restricted files and directories through directory traversal techniques.
4.  **Remote Code Execution (RCE):** Detects and prevents attempts to execute arbitrary commands on the server.
5.  **Log4j Exploits:** Identifies and blocks Log4j vulnerability related attack patterns.
6.  **Protocol Attacks:** Protects against attacks targeting sensitive protocol or configuration files.
7.  **Scanner Detection:** Detects and blocks requests originating from known vulnerability scanners.
8.  **Header & Cookie Injection:** Detects and blocks malicious content injected via headers and cookies.
9.  **Insecure Deserialization:** Blocks requests with potentially malicious serialized data.
10. **HTTP Request Smuggling:** Prevents attacks that bypass security devices using inconsistent header combinations.
11. **HTTP Response Splitting:** Blocks attempts to inject malicious code through header manipulation.
12. **Insecure Direct Object Reference (IDOR):** Detects attempts to access resources using predictable object IDs.
13. **Server-Side Request Forgery (SSRF):** Prevents attacks that make the server perform unauthorized requests.
14. **XML External Entity (XXE) Injection:** Blocks attacks leveraging XML external entity processing.
15. **Server-Side Template Injection (SSTI):** Prevents code injection through template engines.
16. **Mass Assignment:** Blocks unauthorized modification of object attributes through uncontrolled input.
17. **NoSQL Injection:** Prevents malicious NoSQL queries designed to bypass authentication or steal data.
18.  **XPath Injection:** Blocks attempts to manipulate XML documents with malicious XPath queries.
19. **LDAP Injection:** Detects and prevents the injection of malicious data into LDAP queries.
20. **XML Injection:** Detects various attacks exploiting XML manipulation.
21. **File Upload:** Blocks malicious file uploads to prevent execution of unwanted code.
22. **JWT Attacks:** Detects JWT tampering attempts and bypasses.
23. **GraphQL Injection:** Blocks attempts to perform unauthorized operations or extract data via GraphQL queries.
24. **Clickjacking:** Mitigates clickjacking attempts by preventing rendering the protected content inside a frame.
25.  **Cross-Site Request Forgery (CSRF):** Blocks CSRF attacks by preventing unauthorized requests from being performed.

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

Configure rate limits using requests count, time window, optional cleanup interval and specific paths. You can use exact paths or regex patterns for greater flexibility. You can specify to which path to apply rate limiting using the parameter `match_all_paths`, if true only matching paths will be rate limited, otherwise all paths except the matching will be rate limited:

```caddyfile
rate_limit {
    requests 100
    window 10s
    cleanup_interval 5m
    paths /api/v1/.* /admin/.*   # List of regex patterns
    match_all_paths false    # When `true` it will apply only to the specified paths, `false` will rate limit all paths
}
```

*   The rate limiter is based on the client IP address.
*   The cleanup interval controls how frequently the rate limiter clears expired entries from memory.
*   When the requests count is greater than the specified value for the defined period, the request will be blocked.
*   Use `paths` to specify regex patterns or paths for selective rate limiting. If `match_all_paths` is set to `false`, only the specified paths will be rate-limited. If `match_all_paths` is set to `true`, all paths *except* those specified will be rate-limited.

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

### GeoIP Lookup Fallback

When GeoIP lookup fails, the fallback behavior is configurable using the `WithGeoIPLookupFallbackBehavior` option when instantiating the middleware. Default behavior is to log and treat the lookup as not in the list. Options are `none` to block if the lookup fails or a specific country code to fallback to. For example, setting it to `US` will allow requests from IPs if the GeoIP lookup fails and `US` was in the list of allowed countries.

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

The `test.py` script provides a comprehensive check to verify the effectiveness of the configured WAF rules.

*   Each test case will result in either a pass or a fail, based on the rules configured in the WAF.
*   The output log contains detailed results for each test case, along with a summary of all tests performed.
*   An overall percentage is reported at the end, and if the percentage is below 90%, it's recommended to review the output log for further analysis of the failing tests.
*   The security testing suite will test SQL Injection, XSS, Path Traversal, RCE, and much more. You can find a list of tested attacks in the `test.py` script.
*   To run the security testing suite:

```bash
python3 test.py
```

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

### `get_caddy_feeds.py`

*   Downloads pre-generated blacklists and rules from [this repository](https://github.com/fabriziosalmi/caddy-feeds/) to be used by the WAF.

```bash
python3 get_caddy_feeds.py
```

---

## 📜 License

This project is licensed under the **AGPLv3 License**.

---

## 🙏 Contributing

Contributions are highly welcome! Feel free to open an issue or submit a pull request.
