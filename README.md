# Caddy WAF Middleware

This repository contains a custom Web Application Firewall (WAF) middleware for the Caddy web server. It allows you to define rules to inspect incoming HTTP requests and block or log potentially malicious activity.

## Features

*   **Rule-Based Filtering:** Define rules using regular expressions to detect various attack patterns (SQL injection, XSS, path traversal, etc.).
*   **Targeted Inspection:** Rules can target specific parts of the request (URL, query parameters, body, headers).
*   **IP & DNS Blacklisting:** Block requests from specific IPs or domains.
*   **Anomaly Scoring:** Implement a simple anomaly scoring system to block requests based on cumulative rule matches.
*   **Customizable Actions:** Rules can `block` requests or `log` the event.
*   **Flexible Configuration:** Configure via Caddyfile.
*   **Logging:** Detailed logging for matched rules and blocked requests.

## Getting Started

### Prerequisites

*   Go (1.20 or higher)
*   Caddy (v2)

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/caddy-waf.git
    cd caddy-waf
    ```

2.  **Build the Caddy plugin:**

    ```bash
    xcaddy build --with github.com/your-username/caddy-waf
    ```
    *Replace `your-username` with your actual GitHub username.*
    This will generate a custom caddy binary with your middleware embedded.

3. **Replace the Caddy executable:**
    Replace the current caddy binary with the new one created by `xcaddy`.

### Configuration

Configure the middleware by adding the `waf` directive inside your `route` blocks in your Caddyfile:

```caddyfile
{
    http_port 80
}

localhost {
    route {
        waf {
            rule_file rules.json
            rule_file custom_rules.json # You can specify multiple rule files
            log_all  # Enable logging of all matched rules
            log_file "waf.log"  # Optional custom log file for triggered log rules.
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            anomaly_threshold 7 # Optionally change the anomaly threshold, the default is 5
        }
        respond "Hello, world!"
    }
}
```

*   **`rule_file <path>`**: Specifies the path to a JSON file containing WAF rules. Multiple `rule_file` directives can be used.
*   **`log_all`**: Enables logging of all matched rules to the standard output.
*   **`log_file <path>`**: Specifies an optional file path to write the log events triggered by rules with action `log`.
*   **`ip_blacklist_file <path>`**: Path to a text file containing IP addresses or CIDR subnets to block (one per line).
*   **`dns_blacklist_file <path>`**: Path to a text file containing domains to block (one per line).
*   **`anomaly_threshold <number>`**: Sets the anomaly score threshold. If the total score of matched rules is equal or greater than the threshold, the request will be blocked. Default is 5.

### Rule File Format (`rules.json`)

The rule file uses the following JSON format:

```json
[
    {
        "id": "rule_id",
        "phase": 2,
        "pattern": "(?i)regex_pattern",
        "targets": ["ARGS", "BODY", "URL", "HEADERS", "USER_AGENT", "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP"],
        "severity": "LOW/MEDIUM/HIGH/CRITICAL",
        "action": "block/log/alert",
        "score": 1
    },
   {
    "id": "rule_id_2",
        "phase": 2,
        "pattern": "(?i)regex_pattern_2",
        "targets": ["ARGS", "BODY"],
        "severity": "LOW",
        "action": "log",
        "score": 1
    }
    // ... more rules
]
```

*   **`id`**: A unique identifier for the rule.
*   **`phase`**:  (Not currently used) Intended for future phases like request/response. Always use `2` for now.
*   **`pattern`**: The regular expression pattern to match. Use `(?i)` for case-insensitive matching.
*   **`targets`**: An array of where to look in the request. Possible values are: `ARGS`, `BODY`, `URL`, `HEADERS`, `USER_AGENT`, `CONTENT_TYPE`, `X-FORWARDED-FOR`, `X-REAL-IP`
*   **`severity`**: The severity of the rule (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
*   **`action`**: The action to take when the rule matches:
    *   `block`: Block the request.
    *   `log`: Log the event to `stdout` and optionally to the `log_file` if configured.
    *   `alert`: (Not implemented) intended to be used with an external alerting system.
*   **`score`**: The score added to the anomaly score when the rule matches.

### Blacklist File Format (`ip_blacklist.txt` & `dns_blacklist.txt`)

*   Each line in the `ip_blacklist.txt` file represents an IP address or a CIDR subnet to block.
*   Each line in the `dns_blacklist.txt` file represents a domain to block.
* Empty lines are skipped.

### Example Files

Sample files can be found in the repository. Feel free to add or edit them as needed.

## Testing

To run the tests, use the provided test script:

```bash
./test.sh
```

This script will send a series of requests to the local Caddy server and check the responses against expected results. Detailed results are stored in the `waf_test_results.log` file.

## Potential Improvements (TODO)

*   **More Sophisticated Scoring:** Implement more advanced anomaly scoring mechanism based on rule severities and other parameters.
*   **External Alerting:** Support integration with external alerting systems.
*   **Request Body Streaming:** Process large request bodies without reading into memory all at once.
*   **Performance:** Optimize regex matching.
*   **Target Specificity:** Refactor `HEADERS` target to target specific headers instead.

## Contributing

Pull requests are welcome. Feel free to contribute by adding new features, fixing bugs, or improving documentation.

## License

This project is licensed under the [AGPL3 License](LICENSE).
