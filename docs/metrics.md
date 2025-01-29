# Metrics

The WAF's metrics endpoint provides critical insights into its operational behavior, allowing you to analyze traffic patterns, fine-tune rule sets, and monitor performance. This data is essential for maintaining security posture and optimizing resource allocation. The metrics are available in JSON format, making them easily consumable by monitoring tools and analysis pipelines.

Here's a comprehensive breakdown of the metrics provided:

```json
{
  "allowed_requests": 1509,
  "blocked_requests": 25328,
  "dns_blacklist_hits": 0,
  "geoip_blocked": 0,
  "ip_blacklist_hits": 0,
  "rate_limiter_blocked_requests": 23640,
  "rate_limiter_requests": 27004,
  "rule_hits": {
    "allow-legit-browsers": 174,
    "auth-login-form-missing": 304,
    "block-scanners": 25,
    "crlf-injection-headers": 8,
    "header-attacks-consolidated": 22,
    "http-request-smuggling": 2,
    "idor-attacks": 30,
    "insecure-deserialization-java": 2,
    "nosql-injection-attacks": 5,
    "open-redirect-attempt": 6,
    "path-traversal": 30,
    "rce-commands-expanded": 28,
    "rfi-http-url": 29,
    "sensitive-files": 14,
    "sql-injection": 7,
    "sql-injection-improved-basic": 43,
    "ssrf-internal-ip": 5,
    "ssti-attacks": 4,
    "unusual-paths": 1186,
    "xss-attacks": 8,
    "xss-improved-encoding": 234
  },
  "rule_hits_by_phase": {
    "1": 1461,
    "2": 705
  },
  "total_requests": 27004,
  "version": "v0.0.1"
}
```

### Key Metrics:

*   **`allowed_requests` (Integer):**
    *   Represents the total count of HTTP requests that passed through all WAF checks without triggering any blocking rules.
    *   A high number of allowed requests generally indicates normal traffic flow. However, consistently high values could suggest that your WAF ruleset might need tuning to catch more sophisticated threats, or alternatively, that there is a low level of attack traffic at present.
    *   This metric can be crucial in determining how much normal traffic your system is handling.
*   **`blocked_requests` (Integer):**
    *   Indicates the total number of HTTP requests that were blocked by the WAF because they matched at least one blocking rule.
    *   A high number of blocked requests indicates the presence of malicious activity targeting the system.
    *   Monitoring this metric in conjunction with rule hit counts can help identify specific attack vectors and sources.
    *   Spikes in this number can be an indicator of an attack in progress and should be examined immediately.
*   **`dns_blacklist_hits` (Integer):**
    *   Counts the number of times a request was blocked or flagged due to matching a DNS blacklist.
    *   This metric indicates how often requests are originating from or interacting with domains known to be associated with malicious activity, as per configured DNS blacklists.
    *   A non-zero value suggests potential threats originating from or involving blacklisted domains.
*   **`geoip_blocked` (Integer):**
    *   Indicates the number of requests that were blocked specifically due to their geographic location, based on GeoIP data.
    *   This metric reflects the effectiveness of GeoIP-based blocking rules configured in the WAF.
    *   An increase in this metric might suggest a targeted attack originating from specific geographic regions that are being blocked.
*   **`geoip_stats` (Object):**
    *   Provides statistics about GeoIP lookups performed during request processing. This object will vary in its structure and content depending on the specific GeoIP implementation and the type of information the system collects.
    *   If no GeoIP lookups are enabled or no data is collected it would appear empty (`{}`).
    *   If enabled, this object might include the number of lookups, counts by country, specific countries that triggered blocking/whitelisting rules, or any other related insights. Example:

        ```json
        "geoip_stats": {
             "total_lookups": 10000,
             "blocked_by_country": {
               "RU": 200,
               "CN": 150
            },
             "allowed_by_country":{
                "US": 5000
              }
        }
        ```
    *   This metric is essential to understand geographical attack patterns and the effectiveness of country-based blocking/whitelisting.
    *   High numbers of lookups can indicate a lot of traffic originating from various regions.
*   **`ip_blacklist_hits` (Integer):**
    *   Represents the count of requests that were blocked or flagged because the source IP address was found on a configured IP blacklist.
    *   This metric indicates the frequency of requests originating from IPs known to be malicious or associated with undesirable activity.
    *   A higher value suggests that the WAF is effectively blocking traffic from known bad actors.
*   **`rate_limiter_blocked_requests` (Integer):**
    *   Indicates the number of requests that were blocked by the rate limiting mechanism.
    *   This metric shows how many requests exceeded the defined rate limits and were subsequently blocked to protect against brute-force attacks, DDoS attempts, or excessive traffic from a single source.
    *   A high number might indicate ongoing attacks or misconfigured rate limits.
*   **`rate_limiter_requests` (Integer):**
    *   Represents the total number of requests that were subjected to rate limiting checks.
    *   This metric provides context for `rate_limiter_blocked_requests`, showing the overall volume of traffic that was evaluated by the rate limiter.
    *   Comparing this with `rate_limiter_blocked_requests` can help understand the proportion of traffic being rate-limited and blocked.
*   **`rule_hits` (Object):**
    *   A core component of the metrics, this object provides a detailed breakdown of how many times each specific rule was triggered by incoming requests.
    *   The keys within this object represent unique rule identifiers (often the rule's ID or a user-defined name).
    *   The values associated with each key represent the number of times that particular rule was matched.
    *   This metric is invaluable for identifying which rules are being triggered most often, potentially indicating common attack vectors or incorrectly configured rules.
    *   High hit counts for specific rules indicate that they might be addressing a widespread issue or might be too sensitive and require refinement.
    *   Low hit counts on critical rules suggest those rules are either not performing correctly or that the particular attack is not present.
    *   Careful review of this information can help fine-tune the WAF ruleset, focusing on effective rules and removing unnecessary or incorrectly triggered rules.
    *   It is important to note that a low number of hits on a rule does not necessarily mean the rule is unnecessary; the rule may be designed to block rare, high-severity attacks that are not seen regularly.
* **`rule_hits_by_phase` (Object):**
    * Provides insights into how many rules were hit at each processing phase.
    * Keys are numeric phase identifiers. The specific meaning of each phase depends on the WAF architecture, but generally:
        * Phase 1: Typically, pre-processing or request parsing.
        * Phase 2: Usually, request analysis and rule evaluation.
    * The values indicate the number of rule hits recorded in the phase.
    *  Helps to understand which part of the pipeline is doing most of the work, which helps determine if there is a performance issue with the pre or post processing of requests.
*   **`total_requests` (Integer):**
    *   Represents the total number of requests that were received and processed by the WAF, regardless of whether they were allowed or blocked.
    *   This metric serves as a baseline for overall traffic volume.
    *   It can be used in conjunction with `allowed_requests` and `blocked_requests` to calculate percentages of allowed/blocked traffic and identify potential anomalies.
    *   Sudden changes in `total_requests` might indicate a change in traffic volume or an ongoing attack.
*   **`version` (String):**
    *   Indicates the version of the WAF software currently running.
    *   This is useful for tracking deployments, identifying if you are running the latest version, and for debugging or support purposes.
    *   Knowing the version helps in correlating metrics with specific software releases and their features or known issues.

### Analysis and Usage:

*   **Performance Monitoring:** Observe metrics over time to identify performance bottlenecks, high resource utilization, and potential areas for optimization.
*   **Security Analysis:** Identify common attack vectors by analyzing the `rule_hits` metric and the type of blocked requests. This can also show potential gaps in the security setup.
*   **Ruleset Optimization:** Refine and adjust rules based on real-world traffic patterns. Disable rules that trigger false positives or rules that are not used.
*   **Alerting:** Set up alerts based on metrics thresholds. For example, get alerts when `blocked_requests` are above a certain level or a specific rule has excessive hits.
*   **Capacity Planning:** Track trends to help with predicting future resource needs.
*   **Compliance Auditing:** Metrics can provide data needed to satisfy security and compliance audits.
*   **Dashboarding:** Visualizing metrics in a dashboard helps with daily monitoring and quick problem identification.

### Prometheus and Grafana
Instructions on how to expose WAF metrics using the Prometheus format, for integration with your monitoring system are available [here](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/prometheus.md).

### Important Considerations:

*  **Context is important:** These metrics should always be interpreted in context to fully understand them.
*   **Custom Metrics:** Depending on implementation, it may be possible to add custom metrics to enhance the default ones.

By carefully analyzing the data provided by the metrics endpoint, you gain critical insights into the effectiveness of your WAF and can make data-driven decisions to protect your applications. This information is essential for ensuring robust security and optimal performance.
