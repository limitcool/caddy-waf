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
	if logger == nil {
		logger = zap.NewNop()
	}
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
	if path == "" {
		gh.logger.Error("No GeoIP database path specified")
		return nil, fmt.Errorf("no GeoIP database path specified")
	}

	gh.logger.Debug("Loading GeoIP database", zap.String("path", path))

	reader, err := maxminddb.Open(path)
	if err != nil {
		gh.logger.Error("Failed to load GeoIP database", zap.String("path", path), zap.Error(err))
		return nil, fmt.Errorf("failed to load GeoIP database: %w", err)
	}
	gh.logger.Info("GeoIP database loaded", zap.String("path", path))
	return reader, nil
}

// IsCountryInList checks if an IP belongs to a list of countries
func (gh *GeoIPHandler) IsCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if geoIP == nil {
		return false, fmt.Errorf("geoip database not loaded")
	}

	ip, err := gh.extractIPFromRemoteAddr(remoteAddr)
	if err != nil {
		gh.logger.Debug("Failed to extract IP from remote address", zap.String("remote_addr", remoteAddr), zap.Error(err))
		return false, err
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		gh.logger.Debug("Invalid IP address", zap.String("ip", ip))
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	return gh.isCountryInListWithCache(ip, parsedIP, countryList, geoIP)
}

// getCountryCode extracts the country code for logging purposes
func (gh *GeoIPHandler) GetCountryCode(remoteAddr string, geoIP *maxminddb.Reader) string {
	if geoIP == nil {
		gh.logger.Error("GeoIP database not loaded for GetCountryCode")
		return "N/A"
	}

	ip, err := gh.extractIPFromRemoteAddr(remoteAddr)
	if err != nil {
		gh.logger.Debug("Failed to extract IP from remote address for GetCountryCode", zap.String("remote_addr", remoteAddr), zap.Error(err))
		return "N/A"
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		gh.logger.Debug("Invalid IP address for GetCountryCode", zap.String("ip", ip))
		return "N/A"
	}

	return gh.getCountryCodeWithCache(ip, parsedIP, geoIP)
}

func (gh *GeoIPHandler) isCountryInListWithCache(ip string, parsedIP net.IP, countryList []string, geoIP *maxminddb.Reader) (bool, error) {

	// Check cache first
	if gh.geoIPCache != nil {
		gh.geoIPCacheMutex.RLock()
		if record, ok := gh.geoIPCache[ip]; ok {
			gh.geoIPCacheMutex.RUnlock()
			return gh.isCountryInRecord(record, countryList), nil
		}
		gh.geoIPCacheMutex.RUnlock()
	}

	var record GeoIPRecord
	err := geoIP.Lookup(parsedIP, &record)
	if err != nil {
		gh.logger.Error("GeoIP lookup failed", zap.String("ip", ip), zap.Error(err))
		return gh.handleGeoIPLookupError(err, countryList) // Helper function for error handling
	}

	// Cache the record
	if gh.geoIPCache != nil {
		gh.cacheGeoIPRecord(ip, record) // Helper function for caching
	}
	return gh.isCountryInRecord(record, countryList), nil // Helper function for country check
}

func (gh *GeoIPHandler) getCountryCodeWithCache(ip string, parsedIP net.IP, geoIP *maxminddb.Reader) string {

	// Check cache first for GetCountryCode as well for consistency and potential perf gain
	if gh.geoIPCache != nil {
		gh.geoIPCacheMutex.RLock()
		if record, ok := gh.geoIPCache[ip]; ok {
			gh.geoIPCacheMutex.RUnlock()
			return record.Country.ISOCode
		}
		gh.geoIPCacheMutex.RUnlock()
	}

	var record GeoIPRecord
	err := geoIP.Lookup(parsedIP, &record)
	if err != nil {
		gh.logger.Debug("GeoIP lookup failed for getCountryCode", zap.String("ip", ip), zap.Error(err))
		return "N/A"
	}

	// Cache the record for GetCountryCode as well
	if gh.geoIPCache != nil {
		gh.cacheGeoIPRecord(ip, record)
	}

	return record.Country.ISOCode
}

// extractIPFromRemoteAddr extracts the ip from remote address
func (gh *GeoIPHandler) extractIPFromRemoteAddr(remoteAddr string) (string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If it's not in host:port format, assume it's just the IP
		ip := net.ParseIP(remoteAddr)
		if ip == nil {
			return "", fmt.Errorf("invalid IP format: %s", remoteAddr)
		}
		return remoteAddr, nil
	}
	return host, nil
}

// Helper function to check if the country in the record is in the country list
func (gh *GeoIPHandler) isCountryInRecord(record GeoIPRecord, countryList []string) bool {
	for _, country := range countryList {
		if strings.EqualFold(record.Country.ISOCode, country) {
			return true
		}
	}
	return false
}

// Helper function to handle GeoIP lookup errors based on fallback behavior
func (gh *GeoIPHandler) handleGeoIPLookupError(err error, countryList []string) (bool, error) {
	switch gh.geoIPLookupFallbackBehavior {
	case "default":
		// Log at debug level as it's a fallback scenario, not necessarily an error for the overall operation
		gh.logger.Debug("GeoIP lookup failed, using default fallback (not in list)", zap.Error(err))
		return false, nil // Treat as not in the list
	case "none":
		gh.logger.Debug("GeoIP lookup failed, using none fallback", zap.Error(err))
		return false, fmt.Errorf("geoip lookup failed: %w", err) // Propagate the error
	case "": // No fallback configured, maintain existing behavior
		gh.logger.Debug("GeoIP lookup failed, no fallback defined", zap.Error(err))
		return false, fmt.Errorf("geoip lookup failed: %w", err) // Propagate the error
	default: // Configurable fallback country code
		gh.logger.Debug("GeoIP lookup failed, using configured fallback", zap.String("fallbackCountry", gh.geoIPLookupFallbackBehavior), zap.Error(err))
		for _, country := range countryList {
			if strings.EqualFold(gh.geoIPLookupFallbackBehavior, country) {
				return true, nil // Treat as in the list for the fallback country
			}
		}
		return false, nil // Treat as not in the list if fallback country is not in the list
	}
}

// Helper function to cache GeoIP record
func (gh *GeoIPHandler) cacheGeoIPRecord(ip string, record GeoIPRecord) {
	gh.geoIPCacheMutex.Lock()
	gh.geoIPCache[ip] = record
	gh.geoIPCacheMutex.Unlock()

	// Invalidate cache entry after TTL
	if gh.geoIPCacheTTL > 0 {
		time.AfterFunc(gh.geoIPCacheTTL, func() {
			gh.geoIPCacheMutex.Lock()
			delete(gh.geoIPCache, ip)
			gh.geoIPCacheMutex.Unlock()
		})
	}
}
