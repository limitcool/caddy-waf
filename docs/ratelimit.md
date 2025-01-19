# ⏱️ Rate Limiting

Rate limiting is a crucial mechanism for protecting web applications from abuse, denial-of-service attacks, and brute-force login attempts. It works by restricting the number of requests a client can make within a given time period. This configuration allows for granular control over traffic flow based on client IP addresses and specific paths.

The rate limiting functionality is configured within a `rate_limit` block, allowing fine-grained control of its behavior, as shown in the following Caddyfile example:

```caddyfile
rate_limit {
    requests 100
    window 10s
    cleanup_interval 5m
    paths /api/v1/.* /admin/.*   # List of regex patterns
    match_all_paths false    # When `true` it will apply only to the specified paths, `false` will rate limit all paths
}
```

Here's a comprehensive breakdown of the configuration options:

### Configuration Options:

*   **`requests` (Integer):**
    *   Specifies the maximum number of requests allowed from a single client IP address within the defined `window`.
    *   A lower value makes the rate limiting stricter, reducing the number of requests allowed within the time window, while a higher value allows more requests.
    *   Choosing an appropriate value requires balancing protection from abusive behavior against legitimate traffic patterns.
    *   This value must be a positive integer.
    *   Example: `requests 50`, `requests 100`, `requests 500`

*   **`window` (Time Duration):**
    *   Defines the time window in which the `requests` limit is enforced.
    *   It uses standard time units (e.g., seconds, minutes, hours).
    *   When the number of `requests` from a given client IP exceeds the configured value within the `window`, further requests are blocked.
    *   Common examples include `1s`, `10s`, `1m`, `5m`, or `1h`.
    *   Shorter windows are suitable for stricter protection of critical resources, whereas longer windows allow for legitimate usage, but might be less effective at blocking attacks.
    *   Example: `window 10s`, `window 1m`, `window 30m`

*   **`cleanup_interval` (Time Duration):**
    *   Specifies the interval at which the rate limiter clears expired entries from its internal memory.
    *   Expired entries refer to client IP addresses whose request count within their time `window` has fallen below the specified `requests` limit.
    *   A shorter `cleanup_interval` reduces memory usage by removing expired entries more frequently, but may increase CPU load. A longer `cleanup_interval` may increase memory footprint but will lower CPU usage.
    *   The rate limiter should automatically cleanup expired entries as they become expired, this `cleanup_interval` configuration provides a periodic, global sweep to make sure entries are removed.
    *   Example: `cleanup_interval 1m`, `cleanup_interval 5m`, `cleanup_interval 15m`

*   **`paths` (Array of Strings):**
    *   An array of strings representing regular expressions (or exact paths) that determine which URLs should be targeted by this rate limiter.
    *   Each string is treated as a regular expression pattern, allowing for flexible matching of URLs.
    *   When this array is not empty, rate limiting will be applied based on the `match_all_paths` configuration.
    *   For exact paths, specify the exact URL path, such as `"/login"` or `"/api/users"`.
    *   For more flexible matching, use regex patterns, like `"/api/v1/.*"` (all paths under `/api/v1/`), or `"/product/\d+"` (all paths like `/product/123`).
     *  Example: `paths /api/v1/.* /admin/.*`, `paths /users /login`, `paths /static/.*`

*   **`match_all_paths` (Boolean):**
     *   Determines how rate limiting is applied to the specified paths.
     *   When `false` (or omitted), the rate limiting rules apply *only* to the paths matching the patterns specified in `paths`, all other paths bypass this rate limit configuration.
     *    When `true`, the rate limiting rules apply to *all* paths, *except* for the paths matching the patterns specified in the `paths` field.
     *   This option is useful when you need to rate limit most of your traffic and make exceptions for specific paths or endpoints.
    *   Example: `match_all_paths false`, `match_all_paths true`

### Rate Limiting Behavior:

*   **IP-Based:** Rate limiting is enforced based on the client IP address. The rate limiter will track the number of requests per IP, not by user or any other attribute.
*   **Blocking:** When the request count from a given IP address exceeds the `requests` limit within the specified `window`, subsequent requests from that IP are blocked and will return a configurable error code (by default this is a `429 - Too Many Requests`).
*   **Path Matching:** The `paths` setting and the `match_all_paths` setting together determines which requests will be rate limited by the current `rate_limit` configuration block. If `match_all_paths` is false, only paths that match the patterns provided in the `paths` block will be rate limited, if it is set to true, then every request will be rate limited unless it matches a path provided in the `paths` block.
*   **Non-Blocking:** If the request count from an IP does not exceed the limit, the request is allowed to proceed normally.
*  **Multiple rules** It is possible to configure multiple `rate_limit` blocks, each with a different configurations. The order in which the rate limiters appear is not important.

### Considerations and Best Practices:

*   **Choosing Limits:** Choose `requests` and `window` values carefully based on your application's normal traffic patterns and requirements. A value that is too low could cause denial of service for legitimate users, whereas a value that is too high might not provide adequate protection.
*   **Monitoring:** Continuously monitor the rate limiter's effectiveness and adjust the values as needed. Use logging and metrics to gain insights into how the rate limiter performs.
*   **Dynamic Rate Limiting:** For more advanced scenarios, consider implementing dynamic rate limiting, where the limits are adjusted based on real-time traffic conditions and historical patterns.
*   **Multiple Rate Limiters:** It's recommended to apply different rate limit rules for various endpoints or resources based on their criticality and anticipated usage patterns.
*   **Global vs. Local:** Use rate limiting along with other security methods for better protection. Also consider using rate limiting at other levels, including load balancers, and reverse proxies to provide multi-layered protection.
*   **IP Spoofing:** Rate limiting based on IP addresses might be bypassed by sophisticated attackers who spoof IP addresses; take this into consideration when configuring your WAF.
* **Log information** Each time a request is rate limited, logs should provide relevant information for debugging (client IP, blocked path and other relevant information).
*   **Testing:** Test rate limiting thoroughly to ensure that it does not affect legitimate users and that it is working as intended, particularly when complex path matching is involved.

### Advanced scenarios

*   **Varying window based on request path:** It might be useful to configure different time windows and request limits based on the path that is being accessed, e.g. stricter limits on authentication endpoints and looser limits on static files.
*   **Combining with other security features:** Rate limiting can be combined with other WAF features such as IP blocking, country blocking, and rule-based blocking to provide a holistic approach to security.

