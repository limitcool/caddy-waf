package caddywaf

import (
	"net"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
)

type BlacklistManager struct {
	mu               sync.RWMutex
	ipBlacklist      map[string]bool
	dnsBlacklist     map[string]bool
	ipBlacklistPath  string
	dnsBlacklistPath string
	logger           *zap.Logger
}

func NewBlacklistManager(ipBlacklistPath, dnsBlacklistPath string, logger *zap.Logger) *BlacklistManager {
	return &BlacklistManager{
		ipBlacklist:      make(map[string]bool),
		dnsBlacklist:     make(map[string]bool),
		ipBlacklistPath:  ipBlacklistPath,
		dnsBlacklistPath: dnsBlacklistPath,
		logger:           logger,
	}
}

func (bm *BlacklistManager) LoadBlacklists() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.ipBlacklistPath != "" {
		if err := bm.loadIPBlacklistFromFile(bm.ipBlacklistPath); err != nil {
			return err
		}
	}

	if bm.dnsBlacklistPath != "" {
		if err := bm.loadDNSBlacklistFromFile(bm.dnsBlacklistPath); err != nil {
			return err
		}
	}
	return nil
}

func (bm *BlacklistManager) loadIPBlacklistFromFile(path string) error {
	bm.logger.Debug("Loading IP blacklist from file",
		zap.String("file", path),
	)

	newIPBlacklist := make(map[string]bool)
	if err := bm.loadIPBlacklistIntoMap(path, newIPBlacklist); err != nil {
		return err
	}
	bm.ipBlacklist = newIPBlacklist

	bm.logger.Info("IP blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", len(bm.ipBlacklist)),
	)

	return nil
}

func (bm *BlacklistManager) loadDNSBlacklistFromFile(path string) error {
	bm.logger.Debug("Loading DNS blacklist from file",
		zap.String("file", path),
	)

	newDNSBlacklist := make(map[string]bool)
	if err := bm.loadDNSBlacklistIntoMap(path, newDNSBlacklist); err != nil {
		return err
	}
	bm.dnsBlacklist = newDNSBlacklist

	bm.logger.Info("DNS blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", len(bm.dnsBlacklist)),
	)

	return nil
}

func (bm *BlacklistManager) loadIPBlacklistIntoMap(path string, blacklistMap map[string]bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if _, _, err := net.ParseCIDR(line); err == nil {
			// It's a valid CIDR range
			blacklistMap[line] = true
			bm.logger.Debug("Added CIDR range to blacklist",
				zap.String("cidr", line),
			)
			continue
		}

		if ip := net.ParseIP(line); ip != nil {
			// It's a valid IP address
			blacklistMap[line] = true
			bm.logger.Debug("Added IP to blacklist",
				zap.String("ip", line),
			)
			continue
		}

		// Log invalid entries for debugging
		bm.logger.Warn("Invalid IP or CIDR range in blacklist file, skipping",
			zap.String("file", path),
			zap.Int("line", i+1),
			zap.String("entry", line),
		)
	}
	return nil
}

func (bm *BlacklistManager) loadDNSBlacklistIntoMap(path string, blacklistMap map[string]bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blacklistMap[line] = true
	}
	return nil
}

func (bm *BlacklistManager) IsIPBlacklisted(remoteAddr string) bool {
	ipStr := extractIP(remoteAddr)
	if ipStr == "" {
		return false
	}
	// Check if the IP is directly blacklisted
	if bm.ipBlacklist[ipStr] {
		return true
	}
	// Check if the IP falls within any CIDR range in the blacklist
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for blacklistEntry := range bm.ipBlacklist {
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

func (bm *BlacklistManager) IsDNSBlacklisted(host string) bool {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		bm.logger.Warn("Empty host provided for DNS blacklist check")
		return false
	}

	bm.mu.RLock()
	defer bm.mu.RUnlock()

	if _, exists := bm.dnsBlacklist[normalizedHost]; exists {
		bm.logger.Info("Host is blacklisted",
			zap.String("host", host),
			zap.String("blacklisted_domain", normalizedHost),
		)
		return true
	}

	bm.logger.Debug("Host is not blacklisted",
		zap.String("host", host),
	)

	return false
}

func (bm *BlacklistManager) ReloadBlacklists() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	newIPBlacklist := make(map[string]bool)
	if bm.ipBlacklistPath != "" {
		if err := bm.loadIPBlacklistIntoMap(bm.ipBlacklistPath, newIPBlacklist); err != nil {
			bm.logger.Error("Failed to reload IP blacklist",
				zap.String("file", bm.ipBlacklistPath),
				zap.Error(err),
			)
			return err
		}
	} else {
		bm.logger.Debug("No IP blacklist file specified, skipping reload")
	}

	newDNSBlacklist := make(map[string]bool)
	if bm.dnsBlacklistPath != "" {
		if err := bm.loadDNSBlacklistIntoMap(bm.dnsBlacklistPath, newDNSBlacklist); err != nil {
			bm.logger.Error("Failed to reload DNS blacklist",
				zap.String("file", bm.dnsBlacklistPath),
				zap.Error(err),
			)
			return err
		}
	} else {
		bm.logger.Debug("No DNS blacklist file specified, skipping reload")
	}
	bm.ipBlacklist = newIPBlacklist
	bm.dnsBlacklist = newDNSBlacklist

	bm.logger.Info("Blacklists reloaded successfully.")
	return nil
}
