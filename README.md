# Caddy WAF Middleware

This is a Web Application Firewall (WAF) middleware for the Caddy web server. It allows you to define rules to block or alert on suspicious requests.

## Features

-   Rule-based request filtering.
-   Support for different targets like ARGS, BODY, HEADERS and URL.
-   Customizable severity levels and actions (block, alert).
-   Log all functionality.
-   IP and DNS Blacklist functionality (under development)

## Installation

1.  Clone this repository to your local machine.
2.  Build the `caddywaf` plugin:

    ```bash
    go build -buildmode=plugin -o caddywaf.so ./caddywaf.go
    ```
3.  Include the plugin in the Caddy build using the `xcaddy` tool:

    ```bash
    xcaddy build --with github.com/<your-username>/caddy-waf-middleware=/caddywaf.so
    ```

## Configuration

In your Caddyfile, add the following directive:

```caddyfile
{
    http_port 80
}

localhost {
    waf {
        rule_file rules.json
        log_all true
    }
    respond "Hello, world!"
}
```

## Rules File (`rules.json`)

The rule file must be a JSON array of rule objects. Here's an example rule:

```json
[
    {
        "id": "942100",
        "phase": 2,
        "pattern": "(?i)(select|union|update|delete|insert|table|from|where|drop|alter|exec)",
        "targets": ["ARGS", "BODY"],
        "severity": "CRITICAL",
        "action": "block",
        "score": 5
    }
]
```

## Contributing

Contributions are welcome! Please submit any issues or pull requests.

## License
See the `LICENSE` file for details.
