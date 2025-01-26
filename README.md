# 🛡️ Caddy WAF Middleware

A robust, highly customizable, and feature-rich **Web Application Firewall (WAF)** middleware for the Caddy web server. This middleware provides **advanced protection** against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

[![Tests](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/tests.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql)  [![Build, Run and Validate](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build-run-validate.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build-run-validate.yml)

## 🛡️ Core Protections

*   **Regex-Based Filtering:** Deep URL, data & header inspection using powerful regex rules.
*   **Blacklisting:** Blocks malicious IPs, domains & optionally TOR exit nodes.
*   **Geo-Blocking:** Restricts access by country using GeoIP.
*   **Rate Limiting:** Prevents abuse via customizable IP request limits.
*   **Anomaly Scoring:** Dynamically blocks requests based on cumulative rule matches.
*   **Multi-Phase Inspection:** Analyzes traffic throughout the request lifecycle.
*   **Sensitive Data Redaction:** Removes private info from logs.
*   **Custom Response Handling:** Tailored responses for blocked requests.
*   **Detailed Monitoring:** JSON endpoint for performance tracking & analysis.
*   **Dynamic Config Reloads:** Seamless updates without restarts.
*   **File Watchers:** Automatic reloads on rule/blacklist changes.

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
2.  [🛠️ Basic Configuration](#️-basic-configuration)
3.  [📚 Full Documentation](#-full-documentation)
4.  [📜 License](#-license)
5.  [🙏 Contributing](#-contributing)

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

---

## 🛠️ Basic Configuration

Here's a minimal Caddyfile example to get started:

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
            rule_file rules.json
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
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

**For more detailed configuration options, rules format, and usage instructions, please refer to the [Full Documentation](#-full-documentation).**

---

## 📚 Full Documentation

For complete documentation, including configuration options, rule format details, protected attack types, testing strategies, and more, please refer to the `/docs` directory in this repository.

### 📑 Table of Contents

1.  [**Installation**](docs/installation.md) - *Instructions for installing the Caddy WAF middleware.*
2.  [**Configuration Options**](docs/configuration.md) - *Detailed explanation of all available configuration settings.*
3.  [**Rules Format (`rules.json`)**](docs/rules.md) - *A comprehensive guide to defining custom rules using the JSON format.*
4.  [**Blacklist Formats**](docs/blacklists.md) - *Documentation of the formats used for defining IP and DNS blacklists.*
5.   [**Rate Limiting**](docs/ratelimit.md) - *How to configure rate limiting, including parameters and usage.*
6.  [**Country Blocking and Whitelisting**](docs/geoblocking.md) - *Details on how to configure country-based blocking and whitelisting.*
7.  [**Protected Attack Types**](docs/attacks.md) - *An overview of the wide range of web-based threats that the Caddy WAF is designed to protect against.*
8.  [**Dynamic Updates**](docs/dynamicupdates.md) - *How to dynamically update the WAF rules and other settings without downtime.*
9.  [**Metrics**](docs/metrics.md) - *Details about the WAF's metrics endpoint and the different metrics collected.*
10. [**Prometheus Metrics**](docs/prometheus.md) - *Instructions on how to expose WAF metrics using the Prometheus format.*
11. [**Rule/Blacklist Population Scripts**](docs/scripts.md) - *Documentation on the provided scripts to automatically fetch, update and generate rules and blacklists.*
12. [**Testing**](docs/testing.md) - *Guidance on how to test the WAF's effectiveness using the provided testing tools.*
13.  [**Docker Support**](docs/docker.md) - *Instructions on how to build and run the WAF using Docker.*

---

## 📜 License

This project is licensed under the **AGPLv3 License**.

---

## 🙏 Contributing

Contributions are highly welcome! Feel free to open an issue or submit a pull request.
