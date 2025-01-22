package caddywaf

import (
	"bufio" // Optimized reading
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
	bl.logger.Debug("Loading DNS blacklist", zap.String("path", path)) // Improved log message

	file, err := os.Open(path)
	if err != nil {
		bl.logger.Warn("Failed to open DNS blacklist file", zap.String("path", path), zap.Error(err)) // Path instead of file for consistency
		return fmt.Errorf("failed to open DNS blacklist file: %w", err)                               // More accurate error message
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	validEntries := 0
	totalLines := 0 // Initialize totalLines

	for scanner.Scan() {
		totalLines++
		line := scanner.Text()
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		dnsBlacklist[line] = struct{}{}
		validEntries++
	}

	if err := scanner.Err(); err != nil {
		bl.logger.Error("Error reading DNS blacklist file", zap.String("path", path), zap.Error(err)) // More specific error log
		return fmt.Errorf("error reading DNS blacklist file: %w", err)
	}

	bl.logger.Info("DNS blacklist loaded", // Improved log message
		zap.String("path", path),
		zap.Int("valid_entries", validEntries),
		zap.Int("total_lines", totalLines), // Use totalLines which is correctly counted
	)
	return nil
}

func (m *Middleware) isIPBlacklisted(ip string) bool {
	return m.ipBlacklist.Contains(ip)
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
		m.logger.Debug("DNS blacklist hit", // More concise log message, debug level
			zap.String("host", host),
			zap.String("blacklisted_domain", normalizedHost),
		)
		return true
	}

	m.logger.Debug("DNS blacklist miss", zap.String("host", host)) // More concise log message, debug level
	return false
}

// extractIP extracts the IP address from a remote address string.
func extractIP(remoteAddr string, logger *zap.Logger) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		logger.Debug("Using full remote address as IP", // More descriptive debug log
			zap.String("remoteAddr", remoteAddr),
			zap.Error(err), // Keep error for debugging
		)
		return remoteAddr // Assume the input is already an IP address
	}
	return host
}

// LoadIPBlacklistFromFile loads IP addresses from a file into the provided map.
func (bl *BlacklistLoader) LoadIPBlacklistFromFile(path string, ipBlacklist map[string]struct{}) error {
	if bl.logger == nil {
		bl.logger = zap.NewNop()
	}
	bl.logger.Debug("Loading IP blacklist", zap.String("path", path)) // Improved log message

	file, err := os.Open(path)
	if err != nil {
		bl.logger.Warn("Failed to open IP blacklist file", zap.String("path", path), zap.Error(err)) // Path instead of file for consistency
		return fmt.Errorf("failed to open IP blacklist file: %w", err)                               // More accurate error message
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	validEntries := 0
	totalLines := 0 // Initialize totalLines

	for scanner.Scan() {
		totalLines++
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		if _, _, err := net.ParseCIDR(line); err == nil {
			// Valid CIDR range
			ipBlacklist[line] = struct{}{}
			validEntries++
			bl.logger.Debug("Added CIDR to IP blacklist", zap.String("cidr", line)) // More specific debug log
			continue
		}

		if ip := net.ParseIP(line); ip != nil {
			// Valid IP address
			ipBlacklist[line] = struct{}{}
			validEntries++
			bl.logger.Debug("Added IP to IP blacklist", zap.String("ip", line)) // More specific debug log
			continue
		}

		bl.logger.Warn("Invalid IP/CIDR entry in blacklist file", // More concise warning message
			zap.String("path", path),
			zap.Int("line", totalLines), // Use totalLines which is correctly counted
			zap.String("entry", line),
		)
	}

	if scanner.Err() != nil {
		bl.logger.Error("Error reading IP blacklist file", zap.String("path", path), zap.Error(scanner.Err())) // More specific error log
		return fmt.Errorf("error reading IP blacklist file: %w", scanner.Err())
	}

	bl.logger.Info("IP blacklist loaded", // Improved log message
		zap.String("path", path),
		zap.Int("valid_entries", validEntries),
		zap.Int("total_lines", totalLines), // Use totalLines which is correctly counted
	)
	return nil
}
