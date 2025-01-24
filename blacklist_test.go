package caddywaf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
)

// TestLoadDNSBlacklistFromFile_EmptyFile tests loading from an empty file
func TestLoadDNSBlacklistFromFile_EmptyFile(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	tmpFile, err := os.CreateTemp("", "dns_blacklist_empty-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	dnsBlacklist := make(map[string]struct{})
	err = bl.LoadDNSBlacklistFromFile(tmpFile.Name(), dnsBlacklist)
	assert.NoError(t, err)
	assert.Empty(t, dnsBlacklist)
}

// TestLoadIPBlacklistFromFile_EmptyFile tests loading from an empty file
func TestLoadIPBlacklistFromFile_EmptyFile(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	tmpFile, err := os.CreateTemp("", "ip_blacklist_empty-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	ipBlacklist := make(map[string]struct{})
	err = bl.LoadIPBlacklistFromFile(tmpFile.Name(), ipBlacklist)
	assert.NoError(t, err)
	assert.Empty(t, ipBlacklist)
}

// TestLoadIPBlacklistFromFile_InvalidCIDR tests loading with an invalid CIDR range
func TestLoadIPBlacklistFromFile_InvalidCIDR(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	tmpFile, err := os.CreateTemp("", "ip_blacklist_invalid-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("192.168.1.0/abc\n")
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}

	tmpFile.Close()
	ipBlacklist := make(map[string]struct{})
	err = bl.LoadIPBlacklistFromFile(tmpFile.Name(), ipBlacklist)
	assert.NoError(t, err) // Loading should not fail completely, but log the error
	assert.Empty(t, ipBlacklist)
}

// TestNewBlacklistLoader tests the creation of a new BlacklistLoader.
func TestNewBlacklistLoader(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	assert.NotNil(t, bl)
	assert.Equal(t, logger, bl.logger)
}

// TestLoadDNSBlacklistFromFile tests loading DNS entries from a file.
func TestLoadDNSBlacklistFromFile(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	// Create a temporary file with DNS entries
	tmpFile, err := os.CreateTemp("", "dns_blacklist-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test DNS entries to the file
	testEntries := []string{
		"example.com",
		"malicious.domain",
		"# This is a comment",
		"", // Empty line
	}
	for _, entry := range testEntries {
		_, err := tmpFile.WriteString(entry + "\n")
		if err != nil {
			t.Fatalf("Failed to write to temporary file: %v", err)
		}
	}
	tmpFile.Close()

	// Load the DNS blacklist
	dnsBlacklist := make(map[string]struct{})
	err = bl.LoadDNSBlacklistFromFile(tmpFile.Name(), dnsBlacklist)
	assert.NoError(t, err)

	// Validate the loaded entries
	assert.Contains(t, dnsBlacklist, "example.com")
	assert.Contains(t, dnsBlacklist, "malicious.domain")
	assert.NotContains(t, dnsBlacklist, "# This is a comment")
	assert.NotContains(t, dnsBlacklist, "")
}

// TestLoadDNSBlacklistFromFile_InvalidFile tests loading from a non-existent file.
func TestLoadDNSBlacklistFromFile_InvalidFile(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	dnsBlacklist := make(map[string]struct{})
	err := bl.LoadDNSBlacklistFromFile("nonexistent.txt", dnsBlacklist)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open DNS blacklist file") // Updated error message
}

// TestLoadIPBlacklistFromFile tests loading IP addresses and CIDR ranges from a file.
func TestLoadIPBlacklistFromFile(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	// Create a temporary file with IP entries
	tmpFile, err := os.CreateTemp("", "ip_blacklist-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test IP entries to the file
	testEntries := []string{
		"192.168.1.1",
		"10.0.0.0/24",
		"# This is a comment",
		"", // Empty line
		"invalid.ip.address",
	}
	for _, entry := range testEntries {
		_, err := tmpFile.WriteString(entry + "\n")
		if err != nil {
			t.Fatalf("Failed to write to temporary file: %v", err)
		}
	}
	tmpFile.Close()

	// Load the IP blacklist
	ipBlacklist := make(map[string]struct{})
	err = bl.LoadIPBlacklistFromFile(tmpFile.Name(), ipBlacklist)
	assert.NoError(t, err)

	// Validate the loaded entries
	assert.Contains(t, ipBlacklist, "192.168.1.1")
	assert.Contains(t, ipBlacklist, "10.0.0.0/24")
	assert.NotContains(t, ipBlacklist, "# This is a comment")
	assert.NotContains(t, ipBlacklist, "")
	assert.NotContains(t, ipBlacklist, "invalid.ip.address")
}

// TestLoadIPBlacklistFromFile_InvalidFile tests loading from a non-existent file.
func TestLoadIPBlacklistFromFile_InvalidFile(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)

	ipBlacklist := make(map[string]struct{})
	err := bl.LoadIPBlacklistFromFile("nonexistent.txt", ipBlacklist)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open IP blacklist file") // Updated error message
}

// TestIsDNSBlacklisted tests checking if a host is blacklisted.
func TestIsDNSBlacklisted(t *testing.T) {
	m := &Middleware{
		dnsBlacklist: make(map[string]struct{}),
		logger:       zap.NewNop(),
	}

	// Add hosts to the blacklist
	m.dnsBlacklist["example.com"] = struct{}{}
	m.dnsBlacklist["malicious.domain"] = struct{}{}

	// Test blacklisted hosts
	assert.True(t, m.isDNSBlacklisted("example.com"))
	assert.True(t, m.isDNSBlacklisted("MALICIOUS.DOMAIN")) // Case-insensitive check

	// Test non-blacklisted hosts
	assert.False(t, m.isDNSBlacklisted("google.com"))
	assert.False(t, m.isDNSBlacklisted("")) // Empty host
}

// TestExtractIP tests extracting the IP address from a remote address string.
func TestExtractIP(t *testing.T) {
	logger := zap.NewNop()

	// Test valid remote address with port
	remoteAddr := "192.168.1.1:8080"
	ip := extractIP(remoteAddr, logger)
	assert.Equal(t, "192.168.1.1", ip)

	// Test invalid remote address (no port)
	remoteAddr = "192.168.1.1"
	ip = extractIP(remoteAddr, logger)
	assert.Equal(t, "192.168.1.1", ip)

	// Test invalid remote address (malformed)
	remoteAddr = "invalid.address"
	ip = extractIP(remoteAddr, logger)
	assert.Equal(t, "invalid.address", ip)
}
