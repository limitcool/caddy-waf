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

*   **Note:** Only one of `block_countries` or `whitelist_countries` can be enabled at a time.

## GeoIP Lookup Fallback

When GeoIP lookup fails, the fallback behavior is configurable using the `WithGeoIPLookupFallbackBehavior` option when instantiating the middleware. Default behavior is to log and treat the lookup as not in the list. Options are `none` to block if the lookup fails or a specific country code to fallback to. For example, setting it to `US` will allow requests from IPs if the GeoIP lookup fails and `US` was in the list of allowed countries.

