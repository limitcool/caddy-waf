# 🌍 Country Blocking and Whitelisting

*   Uses the MaxMind GeoIP2 database for country lookups.
*   Download the `GeoLite2-Country.mmdb` file (see [Installation](#-installation)).
*   Use `block_countries` or `whitelist_countries` with ISO country codes:

```caddyfile
# Block requests from Russia, China, and North Korea
block_countries /path/to/GeoLite2-Country.mmdb RU CN KP

# Whitelist requests from the United States
whitelist_countries /path/to/GeoLite2-Country.mmdb US
```
