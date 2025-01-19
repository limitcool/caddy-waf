# Metrics

The WAF's metrics endpoint provides critical insights into its operational behavior, allowing you to analyze traffic patterns, fine-tune rule sets, and monitor performance. This data is essential for maintaining security posture and optimizing resource allocation. The metrics are available in JSON format, making them easily consumable by monitoring tools and analysis pipelines.

Here's a comprehensive breakdown of the metrics provided:

```json
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

### Analysis and Usage:

*   **Performance Monitoring:** Observe metrics over time to identify performance bottlenecks, high resource utilization, and potential areas for optimization.
*   **Security Analysis:** Identify common attack vectors by analyzing the `rule_hits` metric and the type of blocked requests. This can also show potential gaps in the security setup.
*   **Ruleset Optimization:** Refine and adjust rules based on real-world traffic patterns. Disable rules that trigger false positives or rules that are not used.
*   **Alerting:** Set up alerts based on metrics thresholds. For example, get alerts when `blocked_requests` are above a certain level or a specific rule has excessive hits.
*   **Capacity Planning:** Track trends to help with predicting future resource needs.
*   **Compliance Auditing:** Metrics can provide data needed to satisfy security and compliance audits.
*   **Dashboarding:** Visualizing metrics in a dashboard helps with daily monitoring and quick problem identification.

### Important Considerations:

*  **Context is important:** These metrics should always be interpreted in context to fully understand them.
*   **Custom Metrics:** Depending on implementation, it may be possible to add custom metrics to enhance the default ones.

By carefully analyzing the data provided by the metrics endpoint, you gain critical insights into the effectiveness of your WAF and can make data-driven decisions to protect your applications. This information is essential for ensuring robust security and optimal performance.
