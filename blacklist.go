package caddywaf

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// BlacklistLoader struct
type BlacklistLoader struct {
	logger *zap.Logger
}

// NewBlacklistLoader creates a new BlacklistLoader with a given logger
func NewBlacklistLoader(logger *zap.Logger) *BlacklistLoader {
	return &BlacklistLoader{logger: logger}
}

// LoadIPBlacklistFromFile loads IP addresses from a file
func (bl *BlacklistLoader) LoadIPBlacklistFromFile(path string, ipBlacklist map[string]bool) error {
	if bl.logger == nil {
		bl.logger = zap.NewNop()
	}
	// Initialize the IP blacklist
	// Log the attempt to load the IP blacklist file
	bl.logger.Debug("Loading IP blacklist from file",
		zap.String("file", path),
	)

	// Attempt to read the file
	content, err := os.ReadFile(path)
	if err != nil {
		bl.logger.Warn("Failed to read IP blacklist file",
			zap.String("file", path),
			zap.Error(err),
		)
		return nil // Continue with an empty blacklist
	}

	// Split the file content into lines
	lines := strings.Split(string(content), "\n")
	validEntries := 0

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Check if the line is a valid IP or CIDR range
		if _, _, err := net.ParseCIDR(line); err == nil {
			// It's a valid CIDR range
			ipBlacklist[line] = true
			validEntries++
			bl.logger.Debug("Added CIDR range to blacklist",
				zap.String("cidr", line),
			)
			continue
		}

		if ip := net.ParseIP(line); ip != nil {
			// It's a valid IP address
			ipBlacklist[line] = true
			validEntries++
			bl.logger.Debug("Added IP to blacklist",
				zap.String("ip", line),
			)
			continue
		}

		// Log invalid entries for debugging
		bl.logger.Warn("Invalid IP or CIDR range in blacklist file, skipping",
			zap.String("file", path),
			zap.Int("line", i+1),
			zap.String("entry", line),
		)
	}

	bl.logger.Info("IP blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", validEntries),
		zap.Int("total_lines", len(lines)),
	)
	return nil
}

// LoadDNSBlacklistFromFile loads DNS entries from a file
func (bl *BlacklistLoader) LoadDNSBlacklistFromFile(path string, dnsBlacklist map[string]bool) error {
	if bl.logger == nil {
		bl.logger = zap.NewNop()
	}
	// Log the attempt to load the DNS blacklist file
	bl.logger.Debug("Loading DNS blacklist from file",
		zap.String("file", path),
	)

	// Attempt to read the file
	content, err := os.ReadFile(path)
	if err != nil {
		bl.logger.Warn("Failed to read DNS blacklist file",
			zap.String("file", path),
			zap.Error(err),
		)
		return nil // Continue with an empty blacklist
	}

	// Convert all entries to lowercase and trim whitespace and add to the map
	lines := strings.Split(string(content), "\n")
	validEntriesCount := 0

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		dnsBlacklist[line] = true
		validEntriesCount++
	}

	// Log the successful loading of the DNS blacklist
	bl.logger.Info("DNS blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", validEntriesCount),
		zap.Int("total_lines", len(lines)),
	)

	return nil
}

// isIPBlacklisted checks if the given IP address is in the blacklist.
func (m *Middleware) isIPBlacklisted(remoteAddr string) bool {
	ipStr := extractIP(remoteAddr)
	if ipStr == "" {
		return false
	}

	// Check if the IP is directly blacklisted
	if m.ipBlacklist[ipStr] {
		return true
	}

	// Check if the IP falls within any CIDR range in the blacklist
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for blacklistEntry := range m.ipBlacklist {
		if strings.Contains(blacklistEntry, "/") {
			_, ipNet, err := net.ParseCIDR(blacklistEntry)
			if err != nil {
				continue
			}
			if ipNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if m.geoIPHandler == nil {
		return false, fmt.Errorf("geoip handler not initialized")
	}
	return m.geoIPHandler.IsCountryInList(remoteAddr, countryList, geoIP)
}

func (m *Middleware) isDNSBlacklisted(host string) bool {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		m.logger.Warn("Empty host provided for DNS blacklist check")
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.dnsBlacklist[normalizedHost]; exists {
		m.logger.Info("Host is blacklisted",
			zap.String("host", host),
			zap.String("blacklisted_domain", normalizedHost),
		)
		return true
	}

	m.logger.Debug("Host is not blacklisted",
		zap.String("host", host),
	)
	return false
}
