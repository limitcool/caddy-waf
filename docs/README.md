# 🛡️ Caddy WAF Middleware

A robust, highly customizable, and feature-rich **Web Application Firewall (WAF)** middleware for the Caddy web server. This middleware provides **advanced protection** against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

## 📑 Table of Contents

1.   *   [Configuration Options](configuration.md)
2.    *   [Rules Format](rules.md)
3.    *   [Metrics](metrics.md)
4.    *   [Protected Attack Types](attacks.md)
5.    *   [Blacklist Formats](blacklists.md)
6.    *   [Rate Limiting](ratelimit.md)
7.    *   [Country Blocking and Whitelisting](geoblocking.md)
8.    *   [Dynamic Updates](dynamicupdates.md)
9.    *   [Testing](testing.md)
10.    *   [Docker Support](docker.md)
11.    *   [Rule/Blacklist Population Scripts](scripts.md)
12.    *   [Prometheus Metrics](prometheus.md)


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

