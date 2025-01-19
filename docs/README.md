# 🛡️ Caddy WAF Middleware

A robust, highly customizable, and feature-rich **Web Application Firewall (WAF)** middleware for the Caddy web server. This middleware provides **advanced protection** against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

[![Go](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/go.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql) [![Build and test Caddy with WAF](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build.yml)

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
    *   [Configuration Options](docs/configuration.md)
    *   [Rules Format](docs/rules.md)
    *   [Metrics](docs/metrics.md)
    *   [Protected Attack Types](docs/attacks.md)
    *   [Blacklist Formats](docs/blacklists.md)
    *   [Rate Limiting](docs/ratelimit.md)
    *   [Country Blocking and Whitelisting](docs/geoblocking.md)
    *   [Dynamic Updates](docs/dynamicupdates.md)
    *   [Testing](docs/testing.md)
    *   [Docker Support](docs/docker.md)
    *   [Rule/Blacklist Population Scripts](docs/scripts.md)
    *   [Prometheus Metrics](docs/prometheus.md)
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

The detailed documentation for this project is organized into the following sections:

*   [Configuration Options](docs/configuration.md) - Detailed description of all the WAF settings.
*   [Rules Format](docs/rules.md) - Information on the rules syntax and structure.
*   [Metrics](docs/metrics.md) - How to use the metrics endpoint.
*   [Protected Attack Types](docs/attacks.md) - List of attacks the WAF protects against.
*   [Blacklist Formats](docs/blacklists.md) -  Explanation of the format for IP and DNS blacklist files.
*   [Rate Limiting](docs/ratelimit.md) - How to configure rate limits.
*   [Country Blocking and Whitelisting](docs/geoblocking.md) - How to use GeoIP for country filtering.
*   [Dynamic Updates](docs/dynamicupdates.md) - How to dynamically reload configurations.
*   [Testing](docs/testing.md) - Instructions for testing the WAF setup.
*   [Docker Support](docs/docker.md) -  How to run the WAF in Docker.
*   [Rule/Blacklist Population Scripts](docs/scripts.md) - Information on the helper scripts.
    *   [Prometheus Metrics](docs/prometheus.md) - How to use the prometheus endpoint.

---

## 📜 License

This project is licensed under the **AGPLv3 License**.

---

## 🙏 Contributing

