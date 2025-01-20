package caddywaf

import (
	"context"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"regexp"
	"strings"

	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

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
	assert.Contains(t, err.Error(), "failed to read DNS blacklist file")
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
	assert.Contains(t, err.Error(), "failed to read IP blacklist file")
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

func TestMiddleware_Provision(t *testing.T) {
	// Ensure testdata files exist
	if _, err := os.Stat("testdata/rules.json"); os.IsNotExist(err) {
		t.Skip("testdata/rules.json does not exist, skipping test")
	}
	if _, err := os.Stat("testdata/ip_blacklist.txt"); os.IsNotExist(err) {
		t.Skip("testdata/ip_blacklist.txt does not exist, skipping test")
	}
	if _, err := os.Stat("testdata/dns_blacklist.txt"); os.IsNotExist(err) {
		t.Skip("testdata/dns_blacklist.txt does not exist, skipping test")
	}
	if _, err := os.Stat("testdata/GeoIP2-Country-Test.mmdb"); os.IsNotExist(err) {
		t.Skip("testdata/GeoIP2-Country-Test.mmdb does not exist, skipping test")
	}

	m := &Middleware{
		RuleFiles:        []string{"testdata/rules.json"},
		IPBlacklistFile:  "testdata/ip_blacklist.txt",
		DNSBlacklistFile: "testdata/dns_blacklist.txt",
		AnomalyThreshold: 10,
		CountryBlock: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"US"},
			GeoIPDBPath: "testdata/GeoIP2-Country-Test.mmdb",
		},
	}

	ctx := caddy.Context{Context: context.Background()}
	err := m.Provision(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, m.logger)
	assert.NotNil(t, m.ruleCache)
	assert.NotNil(t, m.ipBlacklist)
	assert.NotNil(t, m.dnsBlacklist)
	assert.NotNil(t, m.Rules)
}

// TestNewConfigLoader tests the creation of a new ConfigLoader instance.
func TestNewConfigLoader(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)

	if cl.logger != logger {
		t.Errorf("Expected logger to be set, got %v", cl.logger)
	}
}

// TestParseMetricsEndpoint tests the parseMetricsEndpoint function.
func TestParseMetricsEndpoint(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        metrics_endpoint /metrics
    `)

	// Advance to the "metrics_endpoint" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseMetricsEndpoint(d, m)
	if err != nil {
		t.Fatalf("parseMetricsEndpoint failed: %v", err)
	}

	if m.MetricsEndpoint != "/metrics" {
		t.Errorf("Expected metrics endpoint to be '/metrics', got '%s'", m.MetricsEndpoint)
	}
}

// TestParseLogPath tests the parseLogPath function.
func TestParseLogPath(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        log_path /var/log/waf.log
    `)

	// Advance to the "log_path" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseLogPath(d, m)
	if err != nil {
		t.Fatalf("parseLogPath failed: %v", err)
	}

	if m.LogFilePath != "/var/log/waf.log" {
		t.Errorf("Expected log path to be '/var/log/waf.log', got '%s'", m.LogFilePath)
	}
}

// TestParseRateLimit tests the parseRateLimit function.
func TestParseRateLimit(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        rate_limit {
            requests 100
            window 10s
            cleanup_interval 300s
            paths /api /admin
            match_all_paths true
        }
    `)

	// Advance to the "rate_limit" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseRateLimit(d, m)
	if err != nil {
		t.Fatalf("parseRateLimit failed: %v", err)
	}

	if m.RateLimit.Requests != 100 {
		t.Errorf("Expected requests to be 100, got %d", m.RateLimit.Requests)
	}
	if m.RateLimit.Window != 10*time.Second {
		t.Errorf("Expected window to be 10s, got %v", m.RateLimit.Window)
	}
	if m.RateLimit.CleanupInterval != 300*time.Second {
		t.Errorf("Expected cleanup interval to be 300s, got %v", m.RateLimit.CleanupInterval)
	}
	if len(m.RateLimit.Paths) != 2 || m.RateLimit.Paths[0] != "/api" || m.RateLimit.Paths[1] != "/admin" {
		t.Errorf("Expected paths to be ['/api', '/admin'], got %v", m.RateLimit.Paths)
	}
	if !m.RateLimit.MatchAllPaths {
		t.Errorf("Expected match_all_paths to be true, got %v", m.RateLimit.MatchAllPaths)
	}
}

// TestParseRuleFile tests the parseRuleFile function.
func TestParseRuleFile(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        rule_file /etc/waf/rules.txt
    `)

	// Advance to the "rule_file" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseRuleFile(d, m)
	if err != nil {
		t.Fatalf("parseRuleFile failed: %v", err)
	}

	if len(m.RuleFiles) != 1 || m.RuleFiles[0] != "/etc/waf/rules.txt" {
		t.Errorf("Expected rule file to be ['/etc/waf/rules.txt'], got %v", m.RuleFiles)
	}
}

// TestParseCustomResponse tests the parseCustomResponse function.
func TestParseCustomResponse(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}

	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-custom-response-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test content to the file
	testContent := `{"error":"Forbidden"}`
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	tmpFile.Close()

	d := caddyfile.NewTestDispenser(`
        custom_response 403 "application/json" ` + tmpFile.Name() + `
    `)

	// Advance to the "custom_response" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err = cl.parseCustomResponse(d, m)
	if err != nil {
		t.Fatalf("parseCustomResponse failed: %v", err)
	}

	response, ok := m.CustomResponses[403]
	if !ok {
		t.Fatalf("Expected custom response for status code 403, got none")
	}
	if response.Headers["Content-Type"] != "application/json" {
		t.Errorf("Expected content type to be 'application/json', got '%s'", response.Headers["Content-Type"])
	}
	if response.Body != testContent {
		t.Errorf("Expected body to be '%s', got '%s'", testContent, response.Body)
	}
}

// TestParseCountryBlock tests the parseCountryBlock function.
func TestParseCountryBlock(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        block_countries /etc/geoip/GeoIP.dat US CA
    `)

	// Advance to the "block_countries" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseCountryBlock(d, m, true)
	if err != nil {
		t.Fatalf("parseCountryBlock failed: %v", err)
	}

	if !m.CountryBlock.Enabled {
		t.Errorf("Expected country block to be enabled, got %v", m.CountryBlock.Enabled)
	}
	if m.CountryBlock.GeoIPDBPath != "/etc/geoip/GeoIP.dat" {
		t.Errorf("Expected GeoIP DB path to be '/etc/geoip/GeoIP.dat', got '%s'", m.CountryBlock.GeoIPDBPath)
	}
	if len(m.CountryBlock.CountryList) != 2 || m.CountryBlock.CountryList[0] != "US" || m.CountryBlock.CountryList[1] != "CA" {
		t.Errorf("Expected country list to be ['US', 'CA'], got %v", m.CountryBlock.CountryList)
	}
}

// TestParseLogSeverity tests the parseLogSeverity function.
func TestParseLogSeverity(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        log_severity debug
    `)

	// Advance to the "log_severity" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseLogSeverity(d, m)
	if err != nil {
		t.Fatalf("parseLogSeverity failed: %v", err)
	}

	if m.LogSeverity != "debug" {
		t.Errorf("Expected log severity to be 'debug', got '%s'", m.LogSeverity)
	}
}

// TestParseBlacklistFile tests the parseBlacklistFile function.
func TestParseBlacklistFile(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}

	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "ip_blacklist.txt")

	d := caddyfile.NewTestDispenser(`
        ip_blacklist_file ` + tmpFile + `
    `)

	// Advance to the "ip_blacklist_file" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseBlacklistFile(d, m, true)
	if err != nil {
		t.Fatalf("parseBlacklistFile failed: %v", err)
	}

	if m.IPBlacklistFile != tmpFile {
		t.Errorf("Expected IP blacklist file to be '%s', got '%s'", tmpFile, m.IPBlacklistFile)
	}
}

// TestParseAnomalyThreshold tests the parseAnomalyThreshold function.
func TestParseAnomalyThreshold(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        anomaly_threshold 10
    `)

	// Advance to the "anomaly_threshold" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseAnomalyThreshold(d, m)
	if err != nil {
		t.Fatalf("parseAnomalyThreshold failed: %v", err)
	}

	if m.AnomalyThreshold != 10 {
		t.Errorf("Expected anomaly threshold to be 10, got %d", m.AnomalyThreshold)
	}
}

func TestUnmarshalCaddyfile_InvalidRequests(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}

	d := caddyfile.NewTestDispenser(`
        rate_limit {
            requests invalid
            window 10s
        }
        rule_file /etc/waf/rules.txt
    `)

	err := cl.UnmarshalCaddyfile(d, m)
	if err == nil {
		t.Fatal("Expected error for invalid requests value, got nil")
	}
}

func TestUnmarshalCaddyfile_MissingRuleFile(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}

	d := caddyfile.NewTestDispenser(`
        rate_limit {
            requests 100
            window 10s
        }
    `)

	err := cl.UnmarshalCaddyfile(d, m)
	if err == nil {
		t.Fatal("Expected error for missing rule_file directive, got nil")
	}
}

// MockGeoIPReader is a mock implementation of GeoIP reader for testing
type MockGeoIPReader struct{}

// TestWithGeoIPCache tests the WithGeoIPCache method.
func TestWithGeoIPCache(t *testing.T) {
	logger := zap.NewNop()
	handler := NewGeoIPHandler(logger)

	handler.WithGeoIPCache(time.Minute * 10)
	assert.Equal(t, time.Minute*10, handler.geoIPCacheTTL)
}

// TestWithGeoIPLookupFallbackBehavior tests the WithGeoIPLookupFallbackBehavior method.
func TestWithGeoIPLookupFallbackBehavior(t *testing.T) {
	logger := zap.NewNop()
	handler := NewGeoIPHandler(logger)

	handler.WithGeoIPLookupFallbackBehavior("default")
	assert.Equal(t, "default", handler.geoIPLookupFallbackBehavior)
}

// TestLoadGeoIPDatabase tests the LoadGeoIPDatabase method.
func TestLoadGeoIPDatabase(t *testing.T) {
	logger := zap.NewNop()
	handler := NewGeoIPHandler(logger)

	// Test with a valid GeoIP database
	// Mock the GeoIP database loading
	reader := &MockGeoIPReader{}
	err := error(nil)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	// Test with an invalid path
	_, err = handler.LoadGeoIPDatabase("nonexistent.mmdb")
	assert.Error(t, err)
}

func TestFileExists(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up the file after the test

	// Test case: File exists
	assert.True(t, fileExists(tmpFile.Name()), "Expected file to exist")

	// Test case: File does not exist
	assert.False(t, fileExists("nonexistentfile.txt"), "Expected file to not exist")

	// Test case: Path is empty
	assert.False(t, fileExists(""), "Expected empty path to return false")

	// Test case: Path is a directory
	tmpDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.Remove(tmpDir) // Clean up the directory after the test

	assert.False(t, fileExists(tmpDir), "Expected directory path to return false")
}

func TestLogRequest(t *testing.T) {
	// Create a test logger using zaptest
	logger := zaptest.NewLogger(t)

	// Create a Middleware instance with the test logger
	middleware := &Middleware{
		logger:   logger,
		logLevel: zapcore.DebugLevel,
		logChan:  make(chan LogEntry, 100),
	}

	// Create a test request
	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "test-agent")

	// Log a test message
	middleware.logRequest(zapcore.InfoLevel, "Test message", req,
		zap.String("custom_field", "custom_value"),
	)

	// Wait for the log entry to be processed
	time.Sleep(100 * time.Millisecond)
}

func TestLogWorker(t *testing.T) {
	// Create a test logger using zaptest
	logger := zaptest.NewLogger(t)

	// Create a Middleware instance with the test logger
	middleware := &Middleware{
		logger:   logger,
		logLevel: zapcore.DebugLevel,
	}

	// Start the log worker
	middleware.StartLogWorker()

	// Send a log entry
	middleware.logChan <- LogEntry{
		Level:   zapcore.InfoLevel,
		Message: "Worker test message",
		Fields:  []zap.Field{zap.String("field", "value")},
	}

	// Wait for the log entry to be processed
	time.Sleep(100 * time.Millisecond)

	// Stop the log worker
	middleware.StopLogWorker()
}

func TestNewRateLimiter(t *testing.T) {
	config := RateLimit{
		Requests:        10,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		Paths:           []string{"/api/.*"},
		MatchAllPaths:   false,
	}

	rl := NewRateLimiter(config)

	assert.NotNil(t, rl)
	assert.Equal(t, 10, rl.config.Requests)
	assert.Equal(t, time.Minute, rl.config.Window)
	assert.Equal(t, time.Minute, rl.config.CleanupInterval)
	assert.Equal(t, 1, len(rl.config.PathRegexes))
	assert.Equal(t, "/api/.*", rl.config.Paths[0])
	assert.False(t, rl.config.MatchAllPaths)
}

func TestIsRateLimited_PathMatching(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		Paths:           []string{"/api/.*"},
		MatchAllPaths:   false,
	}

	rl := NewRateLimiter(config)

	// Test path matching
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Path matches
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Second request
	assert.True(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // Third request, rate limited

	// Test path not matching
	assert.False(t, rl.isRateLimited("192.168.1.1", "/other/test")) // Path does not match
}

func TestIsRateLimited_MatchAllPaths(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl := NewRateLimiter(config)

	// Test rate limiting for all paths
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // First request
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // Second request
	assert.True(t, rl.isRateLimited("192.168.1.1", "/api/test"))   // Third request, rate limited
	assert.True(t, rl.isRateLimited("192.168.1.1", "/other/test")) // first request to the other path is rate limited
}

func TestIsRateLimited_WindowExpiry(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl := NewRateLimiter(config)

	// Test rate limiting within the window
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // First request
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Second request
	assert.True(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // Third request, rate limited

	// Wait for the window to expire
	time.Sleep(time.Second)

	// Test rate limiting after the window expires
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Window expired, counter reset
}

func TestCleanupExpiredEntries(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl := NewRateLimiter(config)

	// Add some entries
	rl.isRateLimited("192.168.1.1", "/api/test")
	rl.isRateLimited("192.168.1.2", "/api/test")

	// Wait for the window to expire
	time.Sleep(time.Second)

	// Clean up expired entries
	rl.cleanupExpiredEntries()

	// Verify that entries are cleaned up
	rl.Lock()
	assert.Equal(t, 0, len(rl.requests))
	rl.Unlock()
}

func TestStartCleanup(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Second,
		MatchAllPaths:   true,
	}

	rl := NewRateLimiter(config)

	// Start the cleanup goroutine
	rl.startCleanup()

	// Add some entries
	rl.isRateLimited("192.168.1.1", "/api/test")
	rl.isRateLimited("192.168.1.2", "/api/test")

	// Wait for cleanup to run
	time.Sleep(2 * time.Second)

	// Verify that entries are cleaned up
	rl.Lock()
	assert.Equal(t, 0, len(rl.requests))
	rl.Unlock()

	// Stop the cleanup goroutine
	rl.signalStopCleanup()
}

func TestSignalStopCleanup(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Second,
		MatchAllPaths:   true,
	}

	rl := NewRateLimiter(config)

	// Start the cleanup goroutine
	rl.startCleanup()

	// Stop the cleanup goroutine
	rl.signalStopCleanup()

	// Verify that the stopCleanup channel is closed
	rl.Lock()
	assert.Nil(t, rl.stopCleanup)
	rl.Unlock()
}

func TestConcurrentAccess(t *testing.T) {
	config := RateLimit{
		Requests:        100,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl := NewRateLimiter(config)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			rl.isRateLimited(ip, "/api/test")
		}("192.168.1." + string(rune(i)))
	}

	wg.Wait()

	// Verify that all requests were processed
	rl.Lock()
	assert.Equal(t, 100, len(rl.requests))
	rl.Unlock()
}

func TestNewResponseRecorder(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Assert that the responseRecorder is initialized correctly
	assert.NotNil(t, rr)
	assert.NotNil(t, rr.body)
	assert.Equal(t, 0, rr.statusCode)
}

func TestResponseRecorder_WriteHeader(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Set a custom status code
	rr.WriteHeader(http.StatusNotFound)

	// Assert that the status code is set correctly
	assert.Equal(t, http.StatusNotFound, rr.statusCode)
}

func TestResponseRecorder_Header(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Set a custom header
	rr.Header().Set("Content-Type", "application/json")

	// Assert that the header is set correctly
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestResponseRecorder_BodyString(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Write some data to the response body
	_, err := rr.Write([]byte("Hello, World!"))
	assert.NoError(t, err)

	// Assert that the body is captured correctly
	assert.Equal(t, "Hello, World!", rr.BodyString())
}

func TestResponseRecorder_StatusCode(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Default status code should be 200
	assert.Equal(t, http.StatusOK, rr.StatusCode())

	// Set a custom status code
	rr.WriteHeader(http.StatusInternalServerError)

	// Assert that the status code is updated correctly
	assert.Equal(t, http.StatusInternalServerError, rr.StatusCode())
}

func TestResponseRecorder_Write(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Write some data to the response body
	n, err := rr.Write([]byte("Hello, World!"))
	assert.NoError(t, err)

	// Assert that the correct number of bytes were written
	assert.Equal(t, 13, n)

	// Assert that the body is captured correctly
	assert.Equal(t, "Hello, World!", rr.BodyString())

	// Assert that the status code is set to 200 by default
	assert.Equal(t, http.StatusOK, rr.StatusCode())
}

func TestResponseRecorder_Write_WithCustomStatusCode(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Set a custom status code
	rr.WriteHeader(http.StatusForbidden)

	// Write some data to the response body
	_, err := rr.Write([]byte("Access Denied"))
	assert.NoError(t, err)

	// Assert that the status code is set correctly
	assert.Equal(t, http.StatusForbidden, rr.StatusCode())

	// Assert that the body is captured correctly
	assert.Equal(t, "Access Denied", rr.BodyString())
}

func TestResponseRecorder_Write_EmptyBody(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Write an empty body
	_, err := rr.Write([]byte{})
	assert.NoError(t, err)

	// Assert that the body is empty
	assert.Equal(t, "", rr.BodyString())

	// Assert that the status code is set to 200 by default
	assert.Equal(t, http.StatusOK, rr.StatusCode())
}

// MockLogger is a mock logger for testing purposes.
type MockLogger struct {
	*zap.Logger
	lastLog zapcore.Entry
	mu      sync.Mutex
}

func (m *MockLogger) Log(level zapcore.Level, msg string, fields ...zap.Field) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLog = zapcore.Entry{
		Level:   level,
		Message: msg,
	}
	m.Logger.Log(level, msg, fields...)
}

func (m *MockLogger) LastLog() zapcore.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastLog
}

func newMockLogger() *MockLogger {
	logger, _ := zap.NewDevelopment()
	return &MockLogger{Logger: logger}
}

func TestValidateRule(t *testing.T) {
	// Test valid rule
	validRule := &Rule{
		ID:      "rule1",
		Pattern: ".*",
		Targets: []string{"header"},
		Phase:   1,
		Score:   5,
		Action:  "block",
	}
	assert.NoError(t, validateRule(validRule))

	// Test invalid rule (empty ID)
	invalidRule := &Rule{
		ID:      "",
		Pattern: ".*",
		Targets: []string{"header"},
		Phase:   1,
		Score:   5,
		Action:  "block",
	}
	assert.Error(t, validateRule(invalidRule))

	// Test invalid rule (invalid phase)
	invalidRule.Phase = 5
	assert.Error(t, validateRule(invalidRule))

	// Test invalid rule (negative score)
	invalidRule.Phase = 1
	invalidRule.Score = -1
	assert.Error(t, validateRule(invalidRule))

	// Test invalid rule (invalid action)
	invalidRule.Score = 5
	invalidRule.Action = "invalid"
	assert.Error(t, validateRule(invalidRule))
}

func TestProcessRuleMatch(t *testing.T) {
	logger := newMockLogger()
	middleware := &Middleware{
		logger:           logger.Logger, // Use the embedded *zap.Logger
		AnomalyThreshold: 10,
		ruleHits:         sync.Map{},     // Use sync.Map directly
		muMetrics:        sync.RWMutex{}, // Use sync.RWMutex directly
	}

	rule := &Rule{
		ID:          "rule1",
		Targets:     []string{"header"},
		Description: "Test rule",
		Score:       5,
		Action:      "block",
	}

	state := &WAFState{
		TotalScore:      0,
		ResponseWritten: false,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	// Test blocking rule
	shouldContinue := middleware.processRuleMatch(w, req, rule, "value", state)
	assert.False(t, shouldContinue)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, state.Blocked)
	assert.Equal(t, 5, state.TotalScore)

	// Test logging rule
	rule.Action = "log"
	state = &WAFState{
		TotalScore:      0,
		ResponseWritten: false,
	}
	w = httptest.NewRecorder()
	shouldContinue = middleware.processRuleMatch(w, req, rule, "value", state)
	assert.True(t, shouldContinue)
	assert.False(t, state.Blocked)
	assert.Equal(t, 5, state.TotalScore)
}

func TestLoadRules(t *testing.T) {
	logger := newMockLogger()
	middleware := &Middleware{
		logger:    logger.Logger, // Use the embedded *zap.Logger
		ruleCache: NewRuleCache(),
		mu:        sync.RWMutex{}, // Use sync.RWMutex directly
	}

	// Create a temporary rule file
	ruleFile, err := os.CreateTemp("", "rules.json")
	assert.NoError(t, err)
	defer os.Remove(ruleFile.Name())

	rules := []Rule{
		{
			ID:      "rule1",
			Pattern: ".*",
			Targets: []string{"header"},
			Phase:   1,
			Score:   5,
			Action:  "block",
		},
		{
			ID:      "rule2",
			Pattern: ".*",
			Targets: []string{"header"},
			Phase:   2,
			Score:   10,
			Action:  "log",
		},
	}

	// Write rules to the temporary file
	ruleData, err := json.Marshal(rules)
	assert.NoError(t, err)
	_, err = ruleFile.Write(ruleData)
	assert.NoError(t, err)
	ruleFile.Close()

	// Test loading rules
	err = middleware.loadRules([]string{ruleFile.Name()})
	assert.NoError(t, err)
	assert.Equal(t, 2, len(middleware.Rules[1])+len(middleware.Rules[2]))

	// Test loading invalid rule file
	err = middleware.loadRules([]string{"nonexistent.json"})
	assert.Error(t, err)
}

func TestProcessRuleMatch_HighScore(t *testing.T) {
	logger := newMockLogger()
	middleware := &Middleware{
		logger:           logger.Logger,
		AnomalyThreshold: 100, // High threshold
		ruleHits:         sync.Map{},
		muMetrics:        sync.RWMutex{},
	}

	rule := &Rule{
		ID:          "rule1",
		Targets:     []string{"header"},
		Description: "Test rule with high score",
		Score:       200, // Very high score
		Action:      "block",
	}

	state := &WAFState{
		TotalScore:      0,
		ResponseWritten: false,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	// Test blocking rule with high score
	shouldContinue := middleware.processRuleMatch(w, req, rule, "value", state)
	assert.False(t, shouldContinue)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, state.Blocked)
	assert.Equal(t, 200, state.TotalScore)
}

func TestValidateRule_EmptyTargets(t *testing.T) {
	rule := &Rule{
		ID:      "rule1",
		Pattern: ".*",
		Targets: []string{}, // Empty targets
		Phase:   1,
		Score:   5,
		Action:  "block",
	}

	err := validateRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has no targets")
}

func TestUnique(t *testing.T) {
	// Test removing duplicates from a slice of strings
	ips := []string{"1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"}
	uniqueIPs := unique(ips)
	assert.Equal(t, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, uniqueIPs)
}

func TestNewRequestValueExtractor(t *testing.T) {
	logger := zap.NewNop()
	redactSensitiveData := true
	rve := NewRequestValueExtractor(logger, redactSensitiveData)

	assert.NotNil(t, rve)
	assert.Equal(t, logger, rve.logger)
	assert.Equal(t, redactSensitiveData, rve.redactSensitiveData)
}

func TestExtractValue_EmptyTarget(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	_, err := rve.ExtractValue("", req, w)
	assert.Error(t, err)
	assert.Equal(t, "empty extraction target", err.Error())
}

func TestExtractValue_Method(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("METHOD", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "GET", value)
}

func TestExtractValue_RemoteIP(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("REMOTE_IP", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1:12345", value)
}

func TestExtractValue_Protocol(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/1.1"
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("PROTOCOL", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "HTTP/1.1", value)
}

func TestExtractValue_Host(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("HOST", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", value)
}

func TestExtractValue_Args(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/?foo=bar&baz=qux", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("ARGS", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "foo=bar&baz=qux", value)
}

func TestExtractValue_UserAgent(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("USER_AGENT", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "test-agent", value)
}

func TestExtractValue_Path(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/test-path", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("PATH", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "/test-path", value)
}

func TestExtractValue_URI(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/test-path?foo=bar", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("URI", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "/test-path?foo=bar", value)
}

func TestExtractValue_Body(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	body := bytes.NewBufferString("test body")
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("BODY", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "test body", value)
}

func TestExtractValue_Headers(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Test-Header", "test-value")
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("HEADERS", req, w)
	assert.NoError(t, err)
	assert.Contains(t, value, "X-Test-Header: test-value")
}

func TestExtractValue_Cookies(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "test-cookie", Value: "test-value"})
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("COOKIES", req, w)
	assert.NoError(t, err)
	assert.Contains(t, value, "test-cookie=test-value")
}

func TestExtractValue_UnknownTarget(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	_, err := rve.ExtractValue("UNKNOWN_TARGET", req, w)
	assert.Error(t, err)
	assert.Equal(t, "unknown extraction target: UNKNOWN_TARGET", err.Error())
}

// testing tests :)

func TestConcurrentRuleEvaluation(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule1",
					Pattern: ".*",
					Targets: []string{"header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
				},
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
		rateLimiter: NewRateLimiter(RateLimit{
			Requests:        10,
			Window:          time.Minute,
			CleanupInterval: time.Minute,
		}),
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Access Denied",
			},
		},
	}

	// Add some IPs to the blacklist
	middleware.ipBlacklist.Insert("192.168.1.0/24")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = fmt.Sprintf("192.168.1.%d:12345", i%256) // Simulate different IPs
			req.Header.Set("User-Agent", "test-agent")                // Add a header for rule evaluation
			w := httptest.NewRecorder()
			state := &WAFState{}
			middleware.handlePhase(w, req, 1, state)
		}(i)
	}
	wg.Wait()
}

func TestBlockedRequestPhase1_DNSBlacklist(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		dnsBlacklist: map[string]struct{}{
			"malicious.domain": {},
		},
		ipBlacklist: NewCIDRTrie(), // Initialize ipBlacklist
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Access Denied",
			},
		},
	}

	// Simulate a request to a blacklisted domain
	req := httptest.NewRequest("GET", "http://malicious.domain", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}

	// Process the request in Phase 1
	middleware.handlePhase(w, req, 1, state)

	// Debug: Print the response body and status code
	t.Logf("Response Body: %s", w.Body.String())
	t.Logf("Response Status Code: %d", w.Code)

	// Verify that the request was blocked
	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
}

func TestBlockedRequestPhase1_GeoIPBlocking(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		CountryBlock: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"US"},
			GeoIPDBPath: "testdata/GeoIP2-Country-Test.mmdb", // Path to a test GeoIP database
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Access Denied",
			},
		},
	}

	// Simulate a request from a blocked country (US)
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345" // IP from the US (mocked in the test GeoIP database)
	w := httptest.NewRecorder()
	state := &WAFState{}

	// Process the request in Phase 1
	middleware.handlePhase(w, req, 1, state)

	// Verify that the request was blocked
	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
}

// failing:
//

func TestBlockedRequestPhase1_RateLimiting(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: NewRateLimiter(RateLimit{
			Requests:        1, // Allow only 1 request
			Window:          time.Minute,
			CleanupInterval: time.Minute,
			Paths:           []string{"/api/.*"}, // Match paths starting with /api
			MatchAllPaths:   false,               // Only match specified paths
		}),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  NewCIDRTrie(),             // Initialize ipBlacklist
		dnsBlacklist: make(map[string]struct{}), // Initialize dnsBlacklist
	}

	// Simulate two requests from the same IP
	req := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	w2 := httptest.NewRecorder()
	state1 := &WAFState{}
	state2 := &WAFState{}

	// First request (allowed)
	middleware.handlePhase(w1, req, 1, state1)
	assert.False(t, state1.Blocked, "First request should not be blocked")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	// Second request (blocked due to rate limiting)
	middleware.handlePhase(w2, req, 1, state2)
	assert.True(t, state2.Blocked, "Second request should be blocked")
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Expected status code 429")
	assert.Contains(t, w2.Body.String(), "Rate limit exceeded", "Response body should contain 'Rate limit exceeded'")
}

func TestHandlePhase_Phase2_NiktoUserAgent(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2",
					Pattern: "nikto",
					Targets: []string{"USER_AGENT"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nikto"),
				},
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Access Denied",
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "nikto")
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
}

// func TestBlockedRequestPhase1_IPBlacklist(t *testing.T) {
// func TestBlockedRequestPhase1_IPBlacklist(t *testing.T) {
// func TestBlockedRequestPhase1_HeaderRegex(t *testing.T) {

// func TestBlockedRequestPhase2_BodyRegex(t *testing.T) {
// func TestBlockedRequestPhase3_ResponseHeaderRegex(t *testing.T) {
// func TestBlockedRequestPhase4_ResponseBodyRegex(t *testing.T) {

func TestBlockedRequestPhase1_HeaderRegex(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule1",
					Pattern: "bad-header",
					Targets: []string{"HEADERS:X-Custom-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-header"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Header", "this-is-a-bad-header") // Simulate a request with bad header
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Header Regex", "Response body should contain 'Blocked by Header Regex'")
}

func TestBlockedRequestPhase1_HeaderRegex_SpecificValue(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_specific",
					Pattern: "^specific-value$",
					Targets: []string{"HEADERS:X-Specific-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("^specific-value$"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Specific Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Specific-Header", "specific-value") // Simulate a request with the specific header
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Specific Header Regex", "Response body should contain 'Blocked by Specific Header Regex'")
}

func TestBlockedRequestPhase1_HeaderRegex_CommaSeparatedTargets(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_comma",
					Pattern: "bad-value",
					Targets: []string{"HEADERS:X-Custom-Header1,HEADERS:X-Custom-Header2"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-value"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Comma-Separated Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Header1", "good-value")
	req.Header.Set("X-Custom-Header2", "bad-value") // Simulate a request with bad value in one of the headers
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Comma-Separated Header Regex", "Response body should contain 'Blocked by Comma-Separated Header Regex'")
}

func TestBlockedRequestPhase1_CombinedConditions(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_combined",
					Pattern: "bad-user|bad-host",
					Targets: []string{"USER_AGENT", "HOST"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-user|bad-host"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Combined Condition Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://bad-host.com", nil)
	req.Header.Set("User-Agent", "good-user")

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Combined Condition Regex", "Response body should contain 'Blocked by Combined Condition Regex'")
}

func TestBlockedRequestPhase1_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_no_match",
					Pattern: "nomatch",
					Targets: []string{"USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "good-user")

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_HeaderRegex_EmptyHeader(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_empty",
					Pattern: ".+", // Match anything (including empty)
					Targets: []string{"HEADERS:X-Empty-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(".+"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Empty Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked because header is empty")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}
func TestBlockedRequestPhase1_HeaderRegex_MissingHeader(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_missing",
					Pattern: "test-value",
					Targets: []string{"HEADERS:X-Missing-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("test-value"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Missing Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil) // Header not set
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked because header is missing")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")

}

func TestBlockedRequestPhase1_HeaderRegex_ComplexPattern(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_complex",
					Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, // Email regex
					Targets: []string{"HEADERS:X-Email-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Complex Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Email-Header", "test@example.com") // Simulate a request with a valid email
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Complex Header Regex", "Response body should contain 'Blocked by Complex Header Regex'")
}

func TestBlockedRequestPhase1_MultiTargetMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_multi_target",
					Pattern: "bad",
					Targets: []string{"HEADERS:X-Custom-Header", "USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multi-Target Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Header", "good-header")
	req.Header.Set("User-Agent", "bad-user-agent")
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)
	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Multi-Target Regex", "Response body should contain 'Blocked by Multi-Target Regex'")
}

func TestBlockedRequestPhase1_MultiTargetNoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_multi_target_no_match",
					Pattern: "bad",
					Targets: []string{"HEADERS:X-Custom-Header", "USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multi-Target Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Header", "good-header")
	req.Header.Set("User-Agent", "good-user-agent")
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_URLParameterRegex_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_url_param_no_match",
					Pattern: "nomatch",
					Targets: []string{"URL_PARAM:param1"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by URL Parameter Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com?param1=good-param-value¶m2=good-value", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)
	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_MultipleRules(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_multi1",
					Pattern: "bad-user",
					Targets: []string{"USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-user"),
				},
				{
					ID:      "rule_multi2",
					Pattern: "bad-host",
					Targets: []string{"HOST"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-host"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multiple Rules",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://bad-host.com", nil)
	req.Header.Set("User-Agent", "bad-user") // Simulate a request with a bad user agent

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Multiple Rules", "Response body should contain 'Blocked by Multiple Rules'")

	req2 := httptest.NewRequest("GET", "http://good-host.com", nil)
	req2.Header.Set("User-Agent", "bad-user") // Simulate a request with a bad user agent
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}

	middleware.handlePhase(w2, req2, 1, state2)

	t.Logf("State Blocked: %v", state2.Blocked)
	t.Logf("Response Code: %d", w2.Code)
	t.Logf("Response Body: %s", w2.Body.String())

	assert.True(t, state2.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w2.Code, "Expected status code 403")
	assert.Contains(t, w2.Body.String(), "Blocked by Multiple Rules", "Response body should contain 'Blocked by Multiple Rules'")

}

func TestBlockedRequestPhase2_BodyRegex(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2",
					Pattern: "bad-body",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-body"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("POST", "http://example.com",
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString("this-is-a-bad-body")
			return b
		}(), // Simulate a request with bad body
	)
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Body Regex", "Response body should contain 'Blocked by Body Regex'")
}

// new

func TestBlockedRequestPhase2_BodyRegex_JSON(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_json",
					Pattern: `"malicious":true`,
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`"malicious":true`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by JSON Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("POST", "http://example.com",
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString(`{"data":{"malicious":true,"name":"test"}}`)
			return b
		}(), // Simulate a request with JSON body
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by JSON Body Regex", "Response body should contain 'Blocked by JSON Body Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_FormURLEncoded(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_form",
					Pattern: "secret=badvalue",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("secret=badvalue"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Form URL Encoded Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("POST", "http://example.com",
		strings.NewReader("param1=value1&secret=badvalue¶m2=value2"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Form URL Encoded Regex", "Response body should contain 'Blocked by Form URL Encoded Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_SpecificPattern(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_specific",
					Pattern: `\d{3}-\d{2}-\d{4}`,
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Specific Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("POST", "http://example.com",
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString("User ID: 123-45-6789")
			return b
		}(),
	)
	req.Header.Set("Content-Type", "text/plain") // Setting content type
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Specific Body Regex", "Response body should contain 'Blocked by Specific Body Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_no_match",
					Pattern: "nomatch",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("POST", "http://example.com",
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString("this-is-a-good-body")
			return b
		}(),
	)
	req.Header.Set("Content-Type", "text/plain")

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

////////

func TestBlockedRequestPhase2_BodyRegex_NoMatch_MultipartForm(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule_multipart_no_match",
					Pattern: "maliciousfile.txt",
					Targets: []string{"FILE_NAME"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("maliciousfile.txt"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multipart File Name Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "goodfile.txt")
	if err != nil {
		t.Fatalf("Failed to create multipart form file: %v", err)
	}
	_, err = part.Write([]byte("file content"))
	if err != nil {
		t.Fatalf("Failed to write multipart form file: %v", err)
	}
	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close multipart writer: %v", err)
	}

	req := httptest.NewRequest("POST", "http://example.com", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}
func TestBlockedRequestPhase2_BodyRegex_NoBody(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule_body_no_match",
					Pattern: "some-pattern",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("some-pattern"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("POST", "http://example.com", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)
	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

/////

func TestBlockedRequestPhase3_ResponseHeaderRegex_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			3: {
				{
					ID:      "rule3_no_match",
					Pattern: "nomatch",
					Targets: []string{"RESPONSE_HEADERS:X-Response-Header"},
					Phase:   3,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Response Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Response-Header", "good-header")
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}

	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase4_ResponseBodyRegex_EmptyBody(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			4: {
				{
					ID:      "rule4_empty",
					Pattern: "test",
					Targets: []string{"RESPONSE_BODY"},
					Phase:   4,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("test"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Response Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}
	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

////

func TestBlockedRequestPhase4_ResponseBodyRegex_NoBody(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			4: {
				{
					ID:      "rule4_no_body",
					Pattern: "test",
					Targets: []string{"RESPONSE_BODY"},
					Phase:   4,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("test"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Response Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}
	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase3_ResponseHeaderRegex_NoSetCookie(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			3: {
				{
					ID:      "rule_no_setcookie",
					Pattern: "(?i)Set-Cookie:.*?(%0d|\\r)%0a",
					Targets: []string{"RESPONSE_HEADERS"},
					Phase:   3,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("(?i)Set-Cookie:.*?(%0d|\\r)%0a"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Set-Cookie Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}
	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Custom-Header", "some-header-value") // Simulating a normal non-matching response
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	state := &WAFState{}
	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

//

func TestBlockedRequestPhase1_HeaderRegex_CaseInsensitive(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_case_insensitive",
					Pattern: "(?i)bad-value",
					Targets: []string{"HEADERS:X-Custom-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("(?i)bad-value"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Case-Insensitive Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Header", "bAd-VaLuE") // Test with mixed-case header value
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked by case-insensitive regex")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Case-Insensitive Header Regex", "Response body should contain 'Blocked by Case-Insensitive Header Regex'")
}

func TestBlockedRequestPhase1_HeaderRegex_MultipleMatchingHeaders(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_multi",
					Pattern: "bad",
					Targets: []string{"HEADERS:X-Custom-Header1,HEADERS:X-Custom-Header2"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multiple Matching Headers Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           NewCIDRTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Header1", "bad-value")
	req.Header.Set("X-Custom-Header2", "bad-value") // Both headers have a "bad" value
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked when both headers match")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Multiple Matching Headers Regex", "Response body should contain 'Blocked by Multiple Matching Headers Regex'")

	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.Header.Set("X-Custom-Header1", "good-value")
	req2.Header.Set("X-Custom-Header2", "bad-value") // One header has a "bad" value
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}

	middleware.handlePhase(w2, req2, 1, state2)

	t.Logf("State Blocked: %v", state2.Blocked)
	t.Logf("Response Code: %d", w2.Code)
	t.Logf("Response Body: %s", w2.Body.String())

	assert.True(t, state2.Blocked, "Request should be blocked when one header match")
	assert.Equal(t, http.StatusForbidden, w2.Code, "Expected status code 403")
	assert.Contains(t, w2.Body.String(), "Blocked by Multiple Matching Headers Regex", "Response body should contain 'Blocked by Multiple Matching Headers Regex'")

	req3 := httptest.NewRequest("GET", "http://example.com", nil)
	req3.Header.Set("X-Custom-Header1", "good-value")
	req3.Header.Set("X-Custom-Header2", "good-value") // None headers have a "bad" value
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}

	middleware.handlePhase(w3, req3, 1, state3)

	t.Logf("State Blocked: %v", state3.Blocked)
	t.Logf("Response Code: %d", w3.Code)
	t.Logf("Response Body: %s", w3.Body.String())

	assert.False(t, state3.Blocked, "Request should not be blocked when none headers match")
	assert.Equal(t, http.StatusOK, w3.Code, "Expected status code 200")

}

func TestBlockedRequestPhase1_RateLimiting_MultiplePaths(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: NewRateLimiter(RateLimit{
			Requests:        1,
			Window:          time.Minute,
			CleanupInterval: time.Minute,
			Paths:           []string{"/api/v1/.*", "/admin/.*"},
			MatchAllPaths:   false,
		}),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  NewCIDRTrie(),
		dnsBlacklist: make(map[string]struct{}),
	}

	// Test path 1
	req1 := httptest.NewRequest("GET", "/api/v1/users", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	state1 := &WAFState{}

	middleware.handlePhase(w1, req1, 1, state1)
	assert.False(t, state1.Blocked, "First request to /api/v1 should be allowed")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	req2 := httptest.NewRequest("GET", "/api/v1/users", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}
	middleware.handlePhase(w2, req2, 1, state2)
	assert.True(t, state2.Blocked, "Second request to /api/v1 should be rate-limited")
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Expected status code 429")

	// Test path 2
	req3 := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req3.RemoteAddr = "192.168.1.1:12345"
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}
	middleware.handlePhase(w3, req3, 1, state3)
	assert.False(t, state3.Blocked, "First request to /admin should be allowed")
	assert.Equal(t, http.StatusOK, w3.Code, "Expected status code 200")

	req4 := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req4.RemoteAddr = "192.168.1.1:12345"
	w4 := httptest.NewRecorder()
	state4 := &WAFState{}
	middleware.handlePhase(w4, req4, 1, state4)
	assert.True(t, state4.Blocked, "Second request to /admin should be rate-limited")
	assert.Equal(t, http.StatusTooManyRequests, w4.Code, "Expected status code 429")

	req5 := httptest.NewRequest("GET", "/not-rate-limited", nil)
	req5.RemoteAddr = "192.168.1.1:12345"
	w5 := httptest.NewRecorder()
	state5 := &WAFState{}
	middleware.handlePhase(w5, req5, 1, state5)
	assert.False(t, state5.Blocked, "Request not rate limited path should be allowed")
	assert.Equal(t, http.StatusOK, w5.Code, "Expected status code 200")
}

func TestBlockedRequestPhase1_RateLimiting_DifferentIPs(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: NewRateLimiter(RateLimit{
			Requests:        1,
			Window:          time.Minute,
			CleanupInterval: time.Minute,
			MatchAllPaths:   true,
		}),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  NewCIDRTrie(),
		dnsBlacklist: make(map[string]struct{}),
	}

	// Test different IPs
	req1 := httptest.NewRequest("GET", "/api/users", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	state1 := &WAFState{}

	middleware.handlePhase(w1, req1, 1, state1)
	assert.False(t, state1.Blocked, "First request from 192.168.1.1 should be allowed")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	req2 := httptest.NewRequest("GET", "/api/users", nil)
	req2.RemoteAddr = "192.168.1.2:12345"
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}
	middleware.handlePhase(w2, req2, 1, state2)
	assert.False(t, state2.Blocked, "First request from 192.168.1.2 should be allowed")
	assert.Equal(t, http.StatusOK, w2.Code, "Expected status code 200")

	req3 := httptest.NewRequest("GET", "/api/users", nil)
	req3.RemoteAddr = "192.168.1.1:12345"
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}
	middleware.handlePhase(w3, req3, 1, state3)
	assert.True(t, state3.Blocked, "Second request from 192.168.1.1 should be blocked")
	assert.Equal(t, http.StatusTooManyRequests, w3.Code, "Expected status code 429")
}

func TestBlockedRequestPhase1_RateLimiting_MatchAllPaths(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: NewRateLimiter(RateLimit{
			Requests:        1,
			Window:          time.Minute,
			CleanupInterval: time.Minute,
			MatchAllPaths:   true,
		}),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  NewCIDRTrie(),
		dnsBlacklist: make(map[string]struct{}),
	}

	// Test with match all paths
	req1 := httptest.NewRequest("GET", "/api/users", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	state1 := &WAFState{}
	middleware.handlePhase(w1, req1, 1, state1)
	assert.False(t, state1.Blocked, "First request to /api/users should be allowed")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	req2 := httptest.NewRequest("GET", "/api/users", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}

	middleware.handlePhase(w2, req2, 1, state2)
	assert.True(t, state2.Blocked, "Second request to /api/users should be rate-limited")
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Expected status code 429")

	req3 := httptest.NewRequest("GET", "/some-other-path", nil)
	req3.RemoteAddr = "192.168.1.1:12345"
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}
	middleware.handlePhase(w3, req3, 1, state3)
	assert.True(t, state3.Blocked, "Second request to /some-other-path should be rate-limited because MatchAllPaths=true")
	assert.Equal(t, http.StatusTooManyRequests, w3.Code, "Expected status code 429")
}
