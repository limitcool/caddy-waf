package caddywaf

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// BlacklistLoader handles loading IP and DNS blacklists from files.
type BlacklistLoader struct {
	logger *zap.Logger
}

// NewBlacklistLoader creates a new BlacklistLoader with the provided logger.
func NewBlacklistLoader(logger *zap.Logger) *BlacklistLoader {
	return &BlacklistLoader{logger: logger}
}

// LoadDNSBlacklistFromFile loads DNS entries from a file into the provided map.
func (bl *BlacklistLoader) LoadDNSBlacklistFromFile(path string, dnsBlacklist map[string]struct{}) error {
	if bl.logger == nil {
		bl.logger = zap.NewNop()
	}
	bl.logger.Debug("Loading DNS blacklist from file", zap.String("file", path))

	content, err := os.ReadFile(path)
	if err != nil {
		bl.logger.Warn("Failed to read DNS blacklist file", zap.String("file", path), zap.Error(err))
		return fmt.Errorf("failed to read DNS blacklist file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	validEntries := 0

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		dnsBlacklist[line] = struct{}{}
		validEntries++
	}

	bl.logger.Info("DNS blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", validEntries),
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

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if the IP is directly blacklisted
	if _, exists := m.ipBlacklist[ipStr]; exists {
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

// isCountryInList checks if the IP's country is in the provided list using the GeoIP database.
func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if m.geoIPHandler == nil {
		return false, fmt.Errorf("geoip handler not initialized")
	}
	return m.geoIPHandler.IsCountryInList(remoteAddr, countryList, geoIP)
}

// isDNSBlacklisted checks if the given host is in the DNS blacklist.
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

	m.logger.Debug("Host is not blacklisted", zap.String("host", host))
	return false
}

// extractIP extracts the IP address from a remote address string.
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // Assume the input is already an IP address
	}
	return host
}

// LoadIPBlacklistFromFile loads IP addresses from a file into the provided map.
func (bl *BlacklistLoader) LoadIPBlacklistFromFile(path string, ipBlacklist map[string]struct{}) error {
	if bl.logger == nil {
		bl.logger = zap.NewNop()
	}
	bl.logger.Debug("Loading IP blacklist from file", zap.String("file", path))

	content, err := os.ReadFile(path)
	if err != nil {
		bl.logger.Warn("Failed to read IP blacklist file", zap.String("file", path), zap.Error(err))
		return fmt.Errorf("failed to read IP blacklist file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	validEntries := 0

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		if _, _, err := net.ParseCIDR(line); err == nil {
			// Valid CIDR range
			ipBlacklist[line] = struct{}{}
			validEntries++
			bl.logger.Debug("Added CIDR range to blacklist", zap.String("cidr", line))
			continue
		}

		if ip := net.ParseIP(line); ip != nil {
			// Valid IP address
			ipBlacklist[line] = struct{}{}
			validEntries++
			bl.logger.Debug("Added IP to blacklist", zap.String("ip", line))
			continue
		}

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
