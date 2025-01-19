# 🔄 Dynamic Updates

The WAF is designed to be highly flexible and allows for dynamic updates to its configuration without requiring a full restart of the Caddy server. This functionality ensures that security policies can be modified and applied rapidly in response to new threats or changing business needs, while minimizing disruption to the application.

Here's a comprehensive breakdown of how dynamic updates work:

## Automatic Reloading via File Watchers

*   **File Monitoring:** The WAF incorporates file watchers that monitor changes on specific files, including:
    *   The rule file (`rules.json`)
    *   The IP blacklist file (`ip_blacklist.txt`)
    *   The DNS blacklist file (`dns_blacklist.txt`)
    *   The GeoIP database file (`GeoLite2-Country.mmdb`)
    *   The Caddyfile configuration file (if `Caddyfile` changes need to be applied)

*   **Change Detection:** When a change is detected in any of these monitored files (e.g., a file is modified, added, or deleted), the file watcher automatically triggers a reload of the WAF configuration, applying those changes.
*   **Automatic Reload:** This reload process parses the modified file, updates the WAF's internal state, and applies the new settings, without needing a full restart of the server.
*   **Minimal Disruption:** The automatic reload process is designed to be efficient, ensuring that changes are applied quickly with minimal disruption to ongoing requests. There will be a small period in which the rules are being reloaded.
*   **Real-Time Updates:** Changes made to the files can be applied almost in real time allowing for quick responses to new vulnerabilities and attack patterns.

## Configuration Reload via Caddy API

In addition to file watchers, the WAF can also be dynamically reloaded using the Caddy API. This can be useful for automation or in scenarios where changes might not be reflected directly on the file system.

*   **Caddy API Endpoint:** The Caddy server exposes a `reload` endpoint, which can be used to trigger a configuration reload.
*   **API Call:** To reload the configuration, an HTTP POST request is sent to the Caddy API endpoint, typically available at `localhost:2019/load` (this port can be changed in your `Caddyfile`).
*   **Command:** To use this API, an easy approach is to use the command `caddy reload` which performs this HTTP POST request.
*   **Manual Reload:** This process is useful when Caddy configuration changes must be applied programmatically or when file watchers may not be suitable.
*   **Automation:** You can integrate this API call into your configuration management systems, enabling automated deployments and updates of the WAF configuration.

## Practical Usage

*   **Rule Modifications:** To add a new WAF rule, modify the `rules.json` file. The file watcher will automatically detect the change, and the new rule will be loaded into the WAF.
*   **Blacklist Updates:** To block new IP addresses or domains, add the entries to the appropriate files (`ip_blacklist.txt` or `dns_blacklist.txt`). The changes will be applied automatically.
*   **GeoIP Database Updates:** If you need to update the GeoIP database, replace the `GeoLite2-Country.mmdb` file.
*   **Caddyfile Changes:** If you made changes to the `Caddyfile` configuration file you need to use the command `caddy reload` to apply them.

## Considerations and Best Practices

*   **File Format Validation:** The WAF includes validation mechanisms to ensure that the changes applied to the files are correctly formatted and don't cause errors when reloading.
*   **Error Handling:** In the event of an error during the file parsing, the WAF will gracefully handle the situation and report the error in logs, avoiding service disruption.
*   **Atomic Updates:** When making multiple changes across different files, ensure that changes are made atomically (e.g. by writing to a temporary file and then overwriting the original file), to prevent the WAF from reloading partial or incomplete configurations.
*   **Testing:** After applying configuration changes, you should always test the system to make sure that the rules are working correctly and there are no unexpected consequences.
*  **Permissions:** Verify the permissions for the file watcher are correct, to avoid that it does not have permissions to read the files you are trying to monitor.
* **Rate Limiting:**  Be aware that while the WAF rules and blacklists can be reloaded without a full restart, the rate limiting configuration is reloaded every time you modify the Caddyfile and run `caddy reload`.

## Summary

The dynamic updates feature of the WAF is a critical component for flexibility and ease of management. By utilizing file watchers and the Caddy API, security policies can be rapidly updated without disruption, ensuring that the WAF can adapt to the evolving threat landscape and provide continuous protection for web applications. Understanding how these dynamic update mechanisms work and their limitations is essential for effectively managing the WAF.
