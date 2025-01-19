# 🚫 Blacklist Formats

## IP Blacklist (`ip_blacklist.txt`)

*   Supports single IP addresses, CIDR ranges, and comments (lines starting with `#`).

```text
192.168.1.1
10.0.0.0/8
2001:db8::/32
# This is a comment
```

## DNS Blacklist (`dns_blacklist.txt`)

*   Contains one domain per line (comments are allowed with `#`).
*   All entries are lowercased before matching.

```text
malicious.com
evil.example.org
# This is a comment
```

