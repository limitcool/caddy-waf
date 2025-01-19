# 🐍 Rule/Blacklist Population Scripts

Scripts to generate/download rules and blacklists:

## `get_owasp_rules.py`

*   Fetches OWASP core rules and converts them to the required JSON format.

```bash
python3 get_owasp_rules.py
```

## `get_blacklisted_ip.py`

*   Downloads IPs from several external sources.

```bash
python3 get_blacklisted_ip.py
```

## `get_blacklisted_dns.py`

*   Downloads blacklisted domains from various sources.

```bash
python3 get_blacklisted_dns.py
```

## `get_spiderlabs_rules.py`

*   Downloads rules from SpiderLabs.

```bash
python3 get_spiderlabs_rules.py
```

## `get_vulnerability_rules.py`

*   Downloads rules related to known vulnerabilities.

```bash
python3 get_vulnerability_rules.py
```

## `get_caddy_feeds.py`

*   Downloads pre-generated blacklists and rules from [this repository](https://github.com/fabriziosalmi/caddy-feeds/) to be used by the WAF.

```bash
python3 get_caddy_feeds.py
```

