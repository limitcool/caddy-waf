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

// Define custom types for rule hits
type RuleID string
type HitCount int

// ==================== Struct Definitions ====================
type TrieNode struct {
	children map[byte]*TrieNode
	isLeaf   bool
}

func NewTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[byte]*TrieNode), // Initialize the map
		isLeaf:   false,
	}
}

type CIDRTrie struct {
	ipv4Root *TrieNode
	ipv6Root *TrieNode
	mu       sync.RWMutex
}

func NewCIDRTrie() *CIDRTrie {
	return &CIDRTrie{
		ipv4Root: NewTrieNode(), // Initialize with a new TrieNode
		ipv6Root: NewTrieNode(), // Initialize with a new TrieNode
	}
}

func (t *CIDRTrie) Insert(cidr string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	if ip.To4() != nil {
		// IPv4
		return t.insertIPv4(ipNet)
	} else {
		// IPv6
		return t.insertIPv6(ipNet)
	}
}

func (t *CIDRTrie) Contains(ipStr string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		// IPv4
		return t.containsIPv4(ip)
	} else {
		// IPv6
		return t.containsIPv6(ip)
	}
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
	LogBuffer           int  `json:"log_buffer,omitempty"` // Add the LogBuffer field
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

	rateLimiterBlockedRequests int64        // Add rate limiter blocked requests metric
	muRateLimiterMetrics       sync.RWMutex // Mutex to protect rate limiter metrics

	geoIPBlocked int

	Tor TorConfig `json:"tor,omitempty"`

	logChan chan LogEntry // Buffered channel for log entries
	logDone chan struct{} // Signal to stop the logging worker

	ruleCache *RuleCache // New field for RuleCache

	IPBlacklistBlockCount  int64 `json:"ip_blacklist_hits"`
	muIPBlacklistMetrics   sync.Mutex
	DNSBlacklistBlockCount int64 `json:"dns_blacklist_hits"`
	muDNSBlacklistMetrics  sync.Mutex
}

// ==================== Constructors (New functions) ====================

// NewRuleCache creates a new RuleCache.
func NewRuleCache() *RuleCache {
	return &RuleCache{
		rules: make(map[string]*regexp.Regexp),
	}
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

func (t *CIDRTrie) insertIPv4(ipNet *net.IPNet) error {
	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	mask, _ := ipNet.Mask.Size()
	node := t.ipv4Root

	for i := 0; i < mask; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			node.children[bit] = NewTrieNode() // Initialize the child node
		}
		node = node.children[bit]
	}

	node.isLeaf = true
	return nil
}

func (t *CIDRTrie) insertIPv6(ipNet *net.IPNet) error {
	ip := ipNet.IP.To16()
	if ip == nil {
		return fmt.Errorf("invalid IPv6 address")
	}

	mask, _ := ipNet.Mask.Size()
	node := t.ipv6Root

	for i := 0; i < mask; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			node.children[bit] = NewTrieNode() // Initialize the child node
		}
		node = node.children[bit]
	}

	node.isLeaf = true
	return nil
}

func (t *CIDRTrie) containsIPv4(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}

	node := t.ipv4Root
	for i := 0; i < len(ip)*8; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			return false
		}
		node = node.children[bit]
		if node.isLeaf {
			return true
		}
	}
	return node.isLeaf
}

func (t *CIDRTrie) containsIPv6(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}

	node := t.ipv6Root
	for i := 0; i < len(ip)*8; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			return false
		}
		node = node.children[bit]
		if node.isLeaf {
			return true
		}
	}
	return node.isLeaf
}
