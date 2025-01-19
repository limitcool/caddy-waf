  # Rules Metrics

  You can gain insights into your WAF's behavior, optimize your ruleset, and monitor your traffic by inspecting the metrics endpoint or processing such stats with other tools. This endpoint provides detailed information about requests, rule hits, and GeoIP statistics.

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

  *   `allowed_requests`: Total number of requests that were allowed by the WAF.
  *   `blocked_requests`: Total number of requests that were blocked by the WAF.
  *  `geoip_stats`: Statistics about GeoIP lookups (if enabled).
  *   `rule_hits`: An object showing how many times each rule has matched a request. The keys represent the rule IDs, and the values represent the number of matches.
  *   `rule_hits_by_phase`: An object showing how many hits were recorded for each phase of request processing. The keys are the numeric phase identifiers, and values show the number of hits within each phase.
  *   `total_requests`: The total number of requests processed by the WAF.
