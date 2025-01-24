package caddywaf

import (
	"regexp"
	"testing"
)

func TestNewCIDRTrie(t *testing.T) {
	trie := NewCIDRTrie()
	if trie == nil {
		t.Fatal("NewCIDRTrie() returned nil")
	}
	if trie.ipv4Root == nil {
		t.Fatal("NewCIDRTrie() created a trie with nil ipv4Root")
	}
	if trie.ipv6Root == nil {
		t.Fatal("NewCIDRTrie() created a trie with nil ipv6Root")
	}
	if trie.ipv4Root.children == nil {
		t.Fatal("NewCIDRTrie() created ipv4Root with nil children map")
	}
	if trie.ipv6Root.children == nil {
		t.Fatal("NewCIDRTrie() created ipv6Root with nil children map")
	}
}

func TestCIDRTrie_Insert(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"valid IPv4 CIDR", "192.168.1.0/24", false},
		{"valid IPv6 CIDR", "2001:db8::/32", false}, // IPv6 is now supported
		{"invalid CIDR", "invalid", true},
		{"invalid IPv4 mask", "192.168.1.0/33", true},
		{"invalid IPv6 mask", "2001:db8::/129", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewCIDRTrie()
			err := trie.Insert(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("CIDRTrie.Insert() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCIDRTrie_Contains(t *testing.T) {
	trie := NewCIDRTrie()
	_ = trie.Insert("192.168.1.0/24")
	_ = trie.Insert("2001:db8::/32") // Add an IPv6 CIDR

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"IPv4 in range", "192.168.1.1", true},
		{"IPv4 out of range", "192.168.2.1", false},
		{"Invalid IP", "invalid", false},
		{"IPv6 in range", "2001:db8::1", true},
		{"IPv6 out of range", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trie.Contains(tt.ip); got != tt.want {
				t.Errorf("CIDRTrie.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRuleCache(t *testing.T) {
	cache := NewRuleCache()
	if cache == nil {
		t.Fatal("NewRuleCache() returned nil")
	}
	if cache.rules == nil {
		t.Fatal("NewRuleCache() created a cache with nil rules map")
	}
}

func TestRuleCache_GetSet(t *testing.T) {
	cache := NewRuleCache()
	testRegex := regexp.MustCompile(`test.*`)

	// Test Set
	cache.Set("rule1", testRegex)

	// Test Get
	got, exists := cache.Get("rule1")
	if !exists {
		t.Error("RuleCache.Get() returned exists=false for existing rule")
	}
	if got != testRegex {
		t.Error("RuleCache.Get() returned wrong regex")
	}

	// Test Get for non-existent rule
	_, exists = cache.Get("nonexistent")
	if exists {
		t.Error("RuleCache.Get() returned exists=true for non-existent rule")
	}
}
