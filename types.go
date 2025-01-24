package caddywaf

import (
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Package caddywaf is a Caddy module providing web application firewall functionality.

// ==================== Constants and Globals ====================

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

// Define a custom type for context keys
type ContextKeyRule string

// Define custom types for rule hits
type RuleID string
type HitCount int

// ==================== Struct Definitions ====================

// CIDRTrie is a trie structure for efficiently storing and looking up CIDR ranges.
type CIDRTrie struct {
	mu   sync.RWMutex
	root *cidrTrieNode
}

type cidrTrieNode struct {
	children map[byte]*cidrTrieNode
	isLeaf   bool
}

// RuleCache caches compiled regex patterns for rules.
type RuleCache struct {
	mu    sync.RWMutex
	rules map[string]*regexp.Regexp
}

// CountryAccessFilter struct
type CountryAccessFilter struct {
	Enabled     bool              `json:"enabled"`
	CountryList []string          `json:"country_list"`
	GeoIPDBPath string            `json:"geoip_db_path"`
	geoIP       *maxminddb.Reader `json:"-"` // Explicitly mark as not serialized
}

// GeoIPRecord struct
type GeoIPRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Rule struct
type Rule struct {
	ID          string   `json:"id"`
	Phase       int      `json:"phase"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Severity    string   `json:"severity"` // Used for logging only
	Score       int      `json:"score"`
	Action      string   `json:"mode"` // Determines the action (block/log)
	Description string   `json:"description"`
	regex       *regexp.Regexp
	Priority    int // New field for rule priority
}

// CustomBlockResponse struct
type CustomBlockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// WAFState struct
type WAFState struct {
	TotalScore      int
	Blocked         bool
	StatusCode      int
	ResponseWritten bool
}

// Middleware struct
type Middleware struct {
	mu sync.RWMutex

	RuleFiles        []string            `json:"rule_files"`
	IPBlacklistFile  string              `json:"ip_blacklist_file"`
	DNSBlacklistFile string              `json:"dns_blacklist_file"`
	AnomalyThreshold int                 `json:"anomaly_threshold"`
	CountryBlock     CountryAccessFilter `json:"country_block"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	Rules            map[int][]Rule      `json:"-"`
	ipBlacklist      *CIDRTrie           `json:"-"` // Changed to CIDRTrie
	dnsBlacklist     map[string]struct{} `json:"-"` // Changed to map[string]struct{}
	logger           *zap.Logger
	LogSeverity      string `json:"log_severity,omitempty"`
	LogJSON          bool   `json:"log_json,omitempty"`
	logLevel         zapcore.Level
	isShuttingDown   bool

	geoIPCacheTTL               time.Duration
	geoIPLookupFallbackBehavior string

	CustomResponses     map[int]CustomBlockResponse `json:"custom_responses,omitempty"`
	LogFilePath         string
	RedactSensitiveData bool `json:"redact_sensitive_data,omitempty"`

	ruleHits        sync.Map `json:"-"`
	MetricsEndpoint string   `json:"metrics_endpoint,omitempty"`

	configLoader          *ConfigLoader
	blacklistLoader       *BlacklistLoader
	geoIPHandler          *GeoIPHandler
	requestValueExtractor *RequestValueExtractor

	RateLimit   RateLimit
	rateLimiter *RateLimiter

	totalRequests   int64
	blockedRequests int64
	allowedRequests int64
	ruleHitsByPhase map[int]int64
	geoIPStats      map[string]int64 // Key: country code, Value: count
	muMetrics       sync.RWMutex     // Mutex for metrics synchronization

	Tor TorConfig `json:"tor,omitempty"`

	logChan chan LogEntry // Buffered channel for log entries
	logDone chan struct{} // Signal to stop the logging worker

	ruleCache *RuleCache // New field for RuleCache
}

// ==================== Constructors (New functions) ====================

// NewCIDRTrie creates a new CIDRTrie.
func NewCIDRTrie() *CIDRTrie {
	return &CIDRTrie{
		root: &cidrTrieNode{
			children: make(map[byte]*cidrTrieNode),
		},
	}
}

// NewRuleCache creates a new RuleCache.
func NewRuleCache() *RuleCache {
	return &RuleCache{
		rules: make(map[string]*regexp.Regexp),
	}
}

// ==================== CIDRTrie Methods ====================

// Insert adds a CIDR range to the trie.
func (t *CIDRTrie) Insert(cidr string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("only IPv4 CIDR ranges are supported")
	}

	mask, _ := ipNet.Mask.Size()
	node := t.root

	for i := 0; i < mask; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			node.children[bit] = &cidrTrieNode{
				children: make(map[byte]*cidrTrieNode),
			}
		}
		node = node.children[bit]
	}

	node.isLeaf = true
	return nil
}

// Contains checks if an IP address is within any CIDR range in the trie.
func (t *CIDRTrie) Contains(ipStr string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}

	node := t.root
	for i := 0; i < 32; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			return false
		}
		node = node.children[bit]
		if node.isLeaf {
			return true
		}
	}
	return false
}

// ==================== RuleCache Methods ====================

// Get retrieves a compiled regex pattern from the cache.
func (rc *RuleCache) Get(ruleID string) (*regexp.Regexp, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	regex, exists := rc.rules[ruleID]
	return regex, exists
}

// Set stores a compiled regex pattern in the cache.
func (rc *RuleCache) Set(ruleID string, regex *regexp.Regexp) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.rules[ruleID] = regex
}
