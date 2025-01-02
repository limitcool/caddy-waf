# Caddy WAF Middleware

This repository contains a custom Web Application Firewall (WAF) middleware for the Caddy web server. It allows you to define rules to inspect incoming HTTP requests, block or log potentially malicious activity, and enhance your application's security.

## Features

- **Rule-Based Filtering:** Use regular expressions to identify and mitigate common threats like SQL injection, XSS, and path traversal.
- **Targeted Inspection:** Inspect specific parts of requests (URL, query parameters, body, headers).
- **IP & DNS Blacklisting:** Block requests from specific IPs or domains with ease.
- **Anomaly Scoring:** Apply a scoring system to block requests based on cumulative rule matches.
- **Customizable Actions:** Choose to block or log suspicious requests based on matched rules.
- **Flexible Configuration:** Configure the middleware directly via the Caddyfile.
- **Comprehensive Logging:** Track matched rules and blocked requests with detailed logs.

## Getting Started

### Prerequisites

- Go 1.20 or higher
- Caddy v2

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/fabriziosalmi/caddy-waf.git
   cd caddy-waf
   ```

2. Build the Caddy plugin:
   ```bash
   xcaddy build --with github.com/fabriziosalmi/caddy-waf
   ```
   This command creates a custom Caddy binary with the WAF middleware integrated.

3. Replace the existing Caddy binary:
   Replace your current `caddy` executable with the newly created binary.

### Configuration

Add the `waf` directive to your `Caddyfile` inside `route` blocks:

```caddyfile
{
    http_port 80
}

localhost {
    route {
        waf {
            rule_file rules.json
            log_all
            log_file "waf.log"
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            anomaly_threshold 7
        }
        respond "Hello, world!"
    }
}
```

#### Configuration Options

- **`rule_file <path>`:** Path to a JSON file with WAF rules. Supports multiple files.
- **`log_all`**: Logs all matched rules to the console.
- **`log_file <path>`:** Specifies a custom log file for rule-triggered events.
- **`ip_blacklist_file <path>`:** File with blocked IPs or CIDR subnets.
- **`dns_blacklist_file <path>`:** File with blocked domains.
- **`anomaly_threshold <number>`:** Total score threshold to block requests. Default: 5.

### Rule File Format (`rules.json`)

Define rules in JSON format:
```json
[
    {
        "id": "rule_1",
        "phase": 2,
        "pattern": "(?i)select.*from",
        "targets": ["ARGS", "BODY", "URL"],
        "severity": "HIGH",
        "action": "block",
        "score": 3
    },
    {
        "id": "rule_2",
        "phase": 2,
        "pattern": "(?i)<script>",
        "targets": ["BODY", "HEADERS"],
        "severity": "CRITICAL",
        "action": "log",
        "score": 5
    }
]
```

### Blacklist File Formats

- **`ip_blacklist.txt`:** Contains one IP or CIDR block per line.
- **`dns_blacklist.txt`:** Contains one domain per line.

### Example Files

Sample rule and blacklist files are included in the repository for reference.

## Testing

Run the test suite:
```bash
./test.sh
```
Test results are saved in `waf_test_results.log`.

## Future Enhancements

- Advanced anomaly scoring based on severity levels.
- Integration with external alerting systems.
- Streaming support for large request bodies.
- Optimized regex matching for performance.
- Granular targeting for specific request headers.

## Contributing

Contributions are welcome! Submit pull requests to add features, fix bugs, or enhance documentation.

## License

This project is licensed under the [AGPLv3 License](LICENSE).

Repository: [Caddy WAF](https://github.com/fabriziosalmi/caddy-waf/tree/main)
