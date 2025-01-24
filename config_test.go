// TestNewConfigLoader tests the creation of a new ConfigLoader instance.
package caddywaf

import (
	"path/filepath"

	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"go.uber.org/zap"
)

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

	handler := cl.parseCountryBlockDirective(true) // Get the directive handler
	err := handler(d, m)                           // Execute the handler
	if err != nil {
		t.Fatalf("parseCountryBlockDirective failed: %v", err)
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

	handler := cl.parseBlacklistFileDirective(true) // Get the directive handler for IP blacklist
	err := handler(d, m)                            // Execute the handler
	if err != nil {
		t.Fatalf("parseBlacklistFileDirective failed: %v", err)
	}

	if m.IPBlacklistFile != tmpFile {
		t.Errorf("Expected IP blacklist file to be '%s', got '%s'", tmpFile, m.IPBlacklistFile)
	}

	// Test dns_blacklist_file
	tmpDNSFile := filepath.Join(tmpDir, "dns_blacklist.txt")
	d = caddyfile.NewTestDispenser(`
        dns_blacklist_file ` + tmpDNSFile + `
    `)
	if !d.Next() {
		t.Fatal("Failed to advance to the dns_blacklist_file directive")
	}
	handler = cl.parseBlacklistFileDirective(false) // Get handler for DNS blacklist
	err = handler(d, m)
	if err != nil {
		t.Fatalf("parseBlacklistFileDirective for dns failed: %v", err)
	}
	if m.DNSBlacklistFile != tmpDNSFile {
		t.Errorf("Expected DNS blacklist file to be '%s', got '%s'", tmpDNSFile, m.DNSBlacklistFile)
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
