# Caddy WAF Middleware

An advanced Web Application Firewall (WAF) middleware for Caddy server providing comprehensive protection against web attacks.

## Features
- Rule-based request filtering with regex patterns
- IP and DNS blacklisting
- Country-based blocking using MaxMind GeoIP2
- Rate limiting per IP address
- Anomaly scoring system
- Request inspection (URL, args, body, headers, cookies, user-agent)
- Protection against common attacks
- Detailed logging and monitoring
- Dynamic rule reloading

## Installation

1. Install MaxMind GeoIP library:
```bash
go get github.com/oschwald/maxminddb-golang
```

2. Build Caddy with WAF:
```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
```

## Configuration

Basic Caddyfile setup with all features:

```caddyfile
{
    auto_https off
    admin off
    debug
}

:8080 {
    log {
        output stdout
        format console
        level DEBUG
    }
    
    route {
        waf {
            # Rate limiting: 100 requests per 5 seconds
            rate_limit 100 5s
            
            # Rules and blacklists
            rule_file rules.json
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            
            # Country blocking (requires MaxMind GeoIP2 database)
            block_countries /path/to/GeoLite2-Country.mmdb RU CN NK
            
            # Enable detailed logging
            log_all
        }
        respond "Hello, world!" 200
    }
}
```

### Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `rule_file` | JSON file containing WAF rules | `rule_file rules.json` |
| `ip_blacklist_file` | File with blocked IPs/CIDR ranges | `ip_blacklist_file blacklist.txt` |
| `dns_blacklist_file` | File with blocked domains | `dns_blacklist_file domains.txt` |
| `rate_limit` | Rate limiting config | `rate_limit 100 1m` |
| `block_countries` | Country blocking config | `block_countries /path/to/GeoIP.mmdb RU CN` |
| `log_all` | Enable detailed logging | `log_all` |
| `anomaly_threshold` | Score threshold for blocking | `anomaly_threshold 5` |

### Rules Format (rules.json)

```json
[
    {
        "id": "sql_injection",
        "phase": 1,
        "pattern": "(?i)(?:select|insert|update|delete|drop|alter)(?:[\\s\\v\\/\\*]+)(?:from|into|where|table)\\b",
        "targets": ["ARGS", "BODY", "HEADERS", "COOKIES"],
        "severity": "HIGH",
        "action": "block",
        "score": 5,
        "mode": "block"
    }
]
```

Rule fields:
- `id`: Unique rule identifier
- `phase`: Processing phase (1-5)
- `pattern`: Regular expression pattern
- `targets`: Areas to inspect ["ARGS", "BODY", "HEADERS", "COOKIES", "URL", "PATH", "USER_AGENT"]
- `severity`: Rule severity (LOW, MEDIUM, HIGH)
- `action`: Action to take (block, log)
- `score`: Score for anomaly detection
- `mode`: Processing mode (block, log, pass)

### Protected Attack Types

1. **SQL Injection**
   - Basic SELECT/UNION injections
   - Time-based injection attacks
   - Boolean-based injections

2. **Cross-Site Scripting (XSS)**
   - Script tag injection
   - Event handler injection
   - SVG-based XSS

3. **Path Traversal**
   - Directory traversal attempts
   - Encoded path traversal
   - Double-encoded traversal

4. **Remote Code Execution**
   - Command injection
   - Shell command execution
   - System command execution

5. **Log4j Attacks**
   - JNDI lookup attempts
   - Nested expressions

6. **Protocol Attacks**
   - Git repository access
   - Environment file access
   - Configuration file access

7. **Scanner Detection**
   - Common vulnerability scanners
   - Web application scanners
   - Network scanning tools

### Blacklist Formats

IP Blacklist (ip_blacklist.txt):
```text
192.168.1.1
10.0.0.0/8
2001:db8::/32
```

DNS Blacklist (dns_blacklist.txt):
```text
malicious.com
evil.example.org
```

## Rate Limiting

Configure rate limits using requests count and time window:

```caddyfile
# 100 requests per minute
rate_limit 100 1m

# 10 requests per second
rate_limit 10 1s

# 1000 requests per hour
rate_limit 1000 1h
```

## Country Blocking

Block traffic from specific countries using ISO country codes:

```caddyfile
# Block requests from Russia, China, and North Korea
block_countries /path/to/GeoLite2-Country.mmdb RU CN KP
```

## Dynamic Updates

Rules and blacklists can be updated without server restart:
1. Modify rules.json or blacklist files
2. Reload Caddy: `caddy reload`

## Testing

Basic testing:
```bash
# Test rate limiting
for i in {1..10}; do curl -i http://localhost:8080/; done

# Test country blocking
curl -H "X-Real-IP: 1.2.3.4" http://localhost:8080/

# Test SQL injection protection
curl "http://localhost:8080/?id=1+UNION+SELECT+*+FROM+users"

# Test XSS protection
curl "http://localhost:8080/?input=<script>alert(1)</script>"
```

Load testing:
```bash
ab -n 1000 -c 100 http://localhost:8080/
```

## License

This project is licensed under the AGPLv3 License.
