# Caddy WAF Middleware

This is a Web Application Firewall (WAF) middleware for the Caddy web server. It allows you to define rules to block or alert on suspicious requests.

## Features

-   Rule-based request filtering.
-   Support for different targets like ARGS, BODY, HEADERS and URL.
-   Customizable severity levels and actions (block, alert).
-   Log all functionality.
-   IP and DNS Blacklist functionality (under development)

## Example

- curl to caddy blocked
  
```
2025/01/02 12:18:06.310 INFO    http.log.access.log0    handled request {"request": {"remote_ip": "::1", "remote_port": "49949", "client_ip": "::1", "proto": "HTTP/1.1", "method": "GET", "host": "localhost", "uri": "/", "headers": {"User-Agent": ["curl/8.7.1"], "Accept": ["*/*"]}}, "bytes_read": 0, "user_id": "", "duration": 0.000916833, "size": 0, "status": 403, "resp_headers": {"Server": ["Caddy"]}}
```

- browser to caddy allowed
  
```
2025/01/02 12:18:16.497 INFO    http.log.access.log0    handled request {"request": {"remote_ip": "127.0.0.1", "remote_port": "49950", "client_ip": "127.0.0.1", "proto": "HTTP/1.1", "method": "GET", "host": "localhost", "uri": "/", "headers": {"Connection": ["keep-alive"], "Dnt": ["1"], "Sec-Fetch-User": ["?1"], "Accept-Language": ["en-US,en;q=0.5"], "Sec-Gpc": ["1"], "User-Agent": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"], "Accept": ["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"], "Sec-Fetch-Dest": ["document"], "Sec-Fetch-Mode": ["navigate"], "Accept-Encoding": ["gzip, deflate, br, zstd"], "Upgrade-Insecure-Requests": ["1"], "Sec-Fetch-Site": ["none"], "Priority": ["u=0, i"]}}, "bytes_read": 0, "user_id": "", "duration": 0.001484292, "size": 13, "status": 200, "resp_headers": {"Server": ["Caddy"], "Content-Type": ["text/plain; charset=utf-8"]}}
```

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
