package caddywaf

import (
	"io/ioutil"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestLoadDNSBlacklistFromFile(t *testing.T) {
	// Create temp file
	content := `example.com
# Comment line
malicious.com
   spaces.com   
`
	tmpfile, err := ioutil.TempFile("", "dnsblacklist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test loading DNS blacklist
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)
	dnsBlacklist := make(map[string]struct{})

	err = bl.LoadDNSBlacklistFromFile(tmpfile.Name(), dnsBlacklist)
	if err != nil {
		t.Errorf("LoadDNSBlacklistFromFile returned error: %v", err)
	}

	// Verify entries
	expected := map[string]struct{}{
		"example.com":   {},
		"malicious.com": {},
		"spaces.com":    {},
	}

	for domain := range expected {
		if _, exists := dnsBlacklist[domain]; !exists {
			t.Errorf("Expected domain %s not found in blacklist", domain)
		}
	}
}

func TestLoadIPBlacklistFromFile(t *testing.T) {
	// Create temp file
	content := `192.168.1.1
# Comment line
10.0.0.0/24
   172.16.1.1   
invalid-ip
`
	tmpfile, err := ioutil.TempFile("", "ipblacklist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test loading IP blacklist
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)
	ipBlacklist := make(map[string]struct{})

	err = bl.LoadIPBlacklistFromFile(tmpfile.Name(), ipBlacklist)
	if err != nil {
		t.Errorf("LoadIPBlacklistFromFile returned error: %v", err)
	}

	// Verify entries
	expected := map[string]struct{}{
		"192.168.1.1": {},
		"10.0.0.0/24": {},
		"172.16.1.1":  {},
	}

	for ip := range expected {
		if _, exists := ipBlacklist[ip]; !exists {
			t.Errorf("Expected IP/CIDR %s not found in blacklist", ip)
		}
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IP with port", "192.168.1.1:8080", "192.168.1.1"},
		{"IP only", "192.168.1.1", "192.168.1.1"},
		{"IPv6 with port", "[2001:db8::1]:8080", "2001:db8::1"},
		{"IPv6 only", "2001:db8::1", "2001:db8::1"},
	}

	logger := zap.NewNop()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIP(tt.input, logger)
			if result != tt.expected {
				t.Errorf("extractIP(%s) = %s; want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAddIPEntry(t *testing.T) {
	logger := zap.NewNop()
	bl := NewBlacklistLoader(logger)
	ipBlacklist := make(map[string]struct{})

	tests := []struct {
		input    string
		wantErr  bool
		expected bool
	}{
		{"192.168.1.1", false, true},
		{"10.0.0.0/24", false, true},
		{"2001:db8::1", false, true},
		{"invalid-ip", true, false},
		{"256.256.256.256", true, false},
	}

	for _, tt := range tests {
		err := bl.addIPEntry(tt.input, ipBlacklist)
		if (err != nil) != tt.wantErr {
			t.Errorf("addIPEntry(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}

		if _, exists := ipBlacklist[tt.input]; exists != tt.expected {
			t.Errorf("addIPEntry(%s) added = %v, want %v", tt.input, exists, tt.expected)
		}
	}
}
