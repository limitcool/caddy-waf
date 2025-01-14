package caddywaf

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// GeoIPHandler struct
type GeoIPHandler struct {
	logger                      *zap.Logger
	geoIPCache                  map[string]GeoIPRecord
	geoIPCacheMutex             sync.RWMutex
	geoIPCacheTTL               time.Duration // Configurable TTL for cache
	geoIPLookupFallbackBehavior string        // "default", "none", or a specific country code
}

// NewGeoIPHandler creates a new GeoIPHandler with a given logger
func NewGeoIPHandler(logger *zap.Logger) *GeoIPHandler {
	return &GeoIPHandler{logger: logger}
}

// WithGeoIPCache enables GeoIP lookup caching.
func (gh *GeoIPHandler) WithGeoIPCache(ttl time.Duration) {
	gh.geoIPCache = make(map[string]GeoIPRecord)
	gh.geoIPCacheTTL = ttl
}

// WithGeoIPLookupFallbackBehavior configures the fallback behavior for GeoIP lookups.
func (gh *GeoIPHandler) WithGeoIPLookupFallbackBehavior(behavior string) {
	gh.geoIPLookupFallbackBehavior = behavior
}

// LoadGeoIPDatabase opens the geoip database
func (gh *GeoIPHandler) LoadGeoIPDatabase(path string) (*maxminddb.Reader, error) {
	if gh.logger == nil {
		gh.logger = zap.NewNop()
	}
	if path == "" {
		return nil, fmt.Errorf("no GeoIP database path specified")
	}
	gh.logger.Debug("Attempting to load GeoIP database",
		zap.String("path", path),
	)
	reader, err := maxminddb.Open(path)
	if err != nil {
		gh.logger.Error("Failed to load GeoIP database",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to load GeoIP database: %w", err)
	}
	gh.logger.Info("GeoIP database loaded successfully",
		zap.String("path", path),
	)
	return reader, nil
}

// IsCountryInList checks if an IP belongs to a list of countries
func (gh *GeoIPHandler) IsCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if gh.logger == nil {
		gh.logger = zap.NewNop()
	}
	if geoIP == nil {
		return false, fmt.Errorf("geoip database not loaded")
	}
	ip, err := gh.extractIPFromRemoteAddr(remoteAddr)
	if err != nil {
		return false, err
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		gh.logger.Error("invalid IP address", zap.String("ip", ip))
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Easy: Add caching of GeoIP lookups for performance.
	if gh.geoIPCache != nil {
		gh.geoIPCacheMutex.RLock()
		if record, ok := gh.geoIPCache[ip]; ok {
			gh.geoIPCacheMutex.RUnlock()
			for _, country := range countryList {
				if strings.EqualFold(record.Country.ISOCode, country) {
					return true, nil
				}
			}
			return false, nil
		}
		gh.geoIPCacheMutex.RUnlock()
	}

	var record GeoIPRecord
	err = geoIP.Lookup(parsedIP, &record)
	if err != nil {
		gh.logger.Error("geoip lookup failed", zap.String("ip", ip), zap.Error(err))

		// Critical: Handle cases where the GeoIP database lookup fails more gracefully.
		switch gh.geoIPLookupFallbackBehavior {
		case "default":
			// Log and treat as not in the list
			return false, nil
		case "none":
			return false, fmt.Errorf("geoip lookup failed: %w", err)
		case "": // No fallback configured, maintain existing behavior
			return false, fmt.Errorf("geoip lookup failed: %w", err)
		default:
			// Configurable fallback country code
			for _, country := range countryList {
				if strings.EqualFold(gh.geoIPLookupFallbackBehavior, country) {
					return true, nil
				}
			}
			return false, nil
		}

	}

	// Easy: Add caching of GeoIP lookups for performance.
	if gh.geoIPCache != nil {
		gh.geoIPCacheMutex.Lock()
		gh.geoIPCache[ip] = record
		gh.geoIPCacheMutex.Unlock()

		// Invalidate cache entry after TTL (basic implementation)
		if gh.geoIPCacheTTL > 0 {
			time.AfterFunc(gh.geoIPCacheTTL, func() {
				gh.geoIPCacheMutex.Lock()
				delete(gh.geoIPCache, ip)
				gh.geoIPCacheMutex.Unlock()
			})
		}
	}

	for _, country := range countryList {
		if strings.EqualFold(record.Country.ISOCode, country) {
			return true, nil
		}
	}

	return false, nil
}

// getCountryCode extracts the country code for logging purposes
func (gh *GeoIPHandler) GetCountryCode(remoteAddr string, geoIP *maxminddb.Reader) string {
	if gh.logger == nil {
		gh.logger = zap.NewNop()
	}
	if geoIP == nil {
		return "N/A"
	}
	ip, err := gh.extractIPFromRemoteAddr(remoteAddr)
	if err != nil {
		return "N/A"
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "N/A"
	}
	var record GeoIPRecord
	err = geoIP.Lookup(parsedIP, &record)
	if err != nil {
		return "N/A"
	}
	return record.Country.ISOCode
}

// extractIPFromRemoteAddr extracts the ip from remote address
func (gh *GeoIPHandler) extractIPFromRemoteAddr(remoteAddr string) (string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, nil // If it's not in host:port format, assume it's just the IP
	}
	return host, nil
}
