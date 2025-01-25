A robust, highly customizable, and feature-rich **Web Application Firewall (WAF)** middleware for the Caddy web server. This middleware provides **advanced protection** against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

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

Go to the [installation](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/installation.md) documentation section.
