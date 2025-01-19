# ⏱️ Rate Limiting

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

