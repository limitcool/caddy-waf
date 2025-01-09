package caddywaf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/fsnotify/fsnotify"

	"runtime/debug"
)

func (m *Middleware) logVersion() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		m.logger.Warn("Failed to read build info, version unavailable")
		return
	}

	var moduleVersion string
	for _, mod := range buildInfo.Deps {
		if mod.Path == "github.com/fabriziosalmi/caddy-waf" {
			moduleVersion = mod.Version
			break
		}
	}

	if moduleVersion == "" {
		moduleVersion = "unknown"
	}

	m.logger.Info("Starting caddy-waf", zap.String("version", moduleVersion))
}

func init() {
	// Register the module and directive without logging
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

// requestCounter struct
type requestCounter struct {
	count  int
	window time.Time
}

// RateLimit struct
type RateLimit struct {
	Requests        int           `json:"requests"`
	Window          time.Duration `json:"window"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// RateLimiter struct
type RateLimiter struct {
	sync.RWMutex
	requests    map[string]*requestCounter
	config      RateLimit
	stopCleanup chan struct{} // Channel to signal cleanup goroutine to stop
}

// isRateLimited checks if a given IP is rate limited.
func (rl *RateLimiter) isRateLimited(ip string) bool {
	now := time.Now()

	rl.Lock()
	defer rl.Unlock()

	counter, exists := rl.requests[ip]
	if exists {
		if now.Sub(counter.window) > rl.config.Window {
			// Window expired, reset the counter
			rl.requests[ip] = &requestCounter{count: 1, window: now}
			return false
		}

		// Window not expired, increment the counter
		counter.count++
		return counter.count > rl.config.Requests
	}

	// IP doesn't exist, add it
	rl.requests[ip] = &requestCounter{count: 1, window: now}
	return false
}

// cleanupExpiredEntries removes expired entries from the rate limiter.
func (rl *RateLimiter) cleanupExpiredEntries() {
	now := time.Now()
	var expiredIPs []string

	// Collect expired IPs to delete (read lock)
	rl.RLock()
	for ip, counter := range rl.requests {
		if now.Sub(counter.window) > rl.config.Window {
			expiredIPs = append(expiredIPs, ip)
		}
	}
	rl.RUnlock()

	// Delete expired IPs (write lock)
	if len(expiredIPs) > 0 {
		rl.Lock()
		for _, ip := range expiredIPs {
			delete(rl.requests, ip)
		}
		rl.Unlock()
	}
}

// startCleanup starts the goroutine to periodically clean up expired entries.
func (rl *RateLimiter) startCleanup() {
	// Ensure stopCleanup channel is created only once
	if rl.stopCleanup == nil {
		rl.stopCleanup = make(chan struct{})
	}

	go func() {
		log.Println("[INFO] Starting rate limiter cleanup goroutine") // Added logging
		ticker := time.NewTicker(rl.config.CleanupInterval)           // Use the specified cleanup interval
		defer func() {
			ticker.Stop()
			log.Println("[INFO] Rate limiter cleanup goroutine stopped") // Added logging on exit
		}()
		for {
			select {
			case <-ticker.C:
				rl.cleanupExpiredEntries()
			case <-rl.stopCleanup:
				return
			}
		}
	}()
}

// signalStopCleanup signals the cleanup goroutine to stop.
func (rl *RateLimiter) signalStopCleanup() {
	if rl.stopCleanup != nil {
		log.Println("[INFO] Signaling rate limiter cleanup goroutine to stop") // Added logging
		close(rl.stopCleanup)
		// We avoid setting rl.stopCleanup to nil here for maximum safety.
		// Subsequent calls to signalStopCleanup will still be protected by the nil check.
	}
}

// CountryAccessFilter struct
type CountryAccessFilter struct {
	Enabled     bool     `json:"enabled"`
	CountryList []string `json:"country_list"`
	GeoIPDBPath string   `json:"geoip_db_path"`
	geoIP       *maxminddb.Reader
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
}

// Awesome: Structure to represent a custom block response.
type CustomBlockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

type Middleware struct {
	// Add a RWMutex to protect shared state
	mu sync.RWMutex

	RuleFiles        []string            `json:"rule_files"`
	IPBlacklistFile  string              `json:"ip_blacklist_file"`
	DNSBlacklistFile string              `json:"dns_blacklist_file"`
	AnomalyThreshold int                 `json:"anomaly_threshold"`
	RateLimit        RateLimit           `json:"rate_limit"`
	CountryBlock     CountryAccessFilter `json:"country_block"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	Rules            map[int][]Rule      `json:"-"`
	ipBlacklist      map[string]bool     `json:"-"` // Changed type here
	dnsBlacklist     map[string]bool     `json:"-"`
	rateLimiter      *RateLimiter        `json:"-"`
	logger           *zap.Logger
	LogSeverity      string `json:"log_severity,omitempty"`
	LogJSON          bool   `json:"log_json,omitempty"`
	logLevel         zapcore.Level
	isShuttingDown   bool // Basic flag for rudimentary graceful shutdown

	// Added for caching
	geoIPCache      map[string]GeoIPRecord
	geoIPCacheMutex sync.RWMutex
	geoIPCacheTTL   time.Duration // Configurable TTL for cache

	// Added for configurable fallback
	geoIPLookupFallbackBehavior string // "default", "none", or a specific country code

	CustomResponses map[int]CustomBlockResponse `json:"custom_responses,omitempty"`

	LogFilePath string // New field for configurable log path

	RedactSensitiveData bool `json:"redact_sensitive_data,omitempty"`
}

// WAFState struct: Used to maintain state between phases
type WAFState struct {
	TotalScore      int
	Blocked         bool
	StatusCode      int
	ResponseWritten bool
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return &Middleware{} },
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	logger := zap.L().Named("caddyfile_parser") // Naming the logger can be helpful

	logger.Info("Starting to parse Caddyfile", zap.String("file", h.Dispenser.File()))

	var m Middleware
	dispenser := h.Dispenser

	logger.Debug("Creating dispenser", zap.String("file", dispenser.File()))

	err := m.UnmarshalCaddyfile(dispenser)
	if err != nil {
		// Improve error message by including file and line number
		return nil, fmt.Errorf("Caddyfile parse error: %w", err)
	}

	logger.Info("Successfully parsed Caddyfile", zap.String("file", h.Dispenser.File()))
	return &m, nil
}

func (m *Middleware) Shutdown(ctx context.Context) error {
	m.logger.Info("Starting WAF middleware shutdown procedures")
	m.isShuttingDown = true // Signal that shutdown is in progress

	// Signal the rate limiter cleanup goroutine to stop
	if m.rateLimiter != nil {
		m.logger.Debug("Signaling rate limiter cleanup to stop...")
		m.rateLimiter.signalStopCleanup()
		m.logger.Debug("Rate limiter cleanup signaled.")
	} else {
		m.logger.Debug("Rate limiter is nil, no cleanup signaling needed.")
	}

	var firstError error // Capture the first error encountered

	// Close the GeoIP database for CountryBlock
	if m.CountryBlock.geoIP != nil {
		m.logger.Debug("Closing country block GeoIP database...")
		err := m.CountryBlock.geoIP.Close()
		if err != nil {
			m.logger.Error("Error encountered while closing country block GeoIP database", zap.Error(err))
			if firstError == nil {
				firstError = fmt.Errorf("error closing country block GeoIP: %w", err)
			}
		} else {
			m.logger.Debug("Country block GeoIP database closed successfully.")
		}
		m.CountryBlock.geoIP = nil // Ensure the reference is cleared
	} else {
		m.logger.Debug("Country block GeoIP database was not open, skipping close.")
	}

	// Close the GeoIP database for CountryWhitelist
	if m.CountryWhitelist.geoIP != nil {
		m.logger.Debug("Closing country whitelist GeoIP database...")
		err := m.CountryWhitelist.geoIP.Close()
		if err != nil {
			m.logger.Error("Error encountered while closing country whitelist GeoIP database", zap.Error(err))
			if firstError == nil {
				firstError = fmt.Errorf("error closing country whitelist GeoIP: %w", err)
			}
		} else {
			m.logger.Debug("Country whitelist GeoIP database closed successfully.")
		}
		m.CountryWhitelist.geoIP = nil // Ensure the reference is cleared
	} else {
		m.logger.Debug("Country whitelist GeoIP database was not open, skipping close.")
	}

	m.logger.Info("WAF middleware shutdown procedures completed")
	return firstError // Return the first error encountered, if any
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if m.logger == nil {
		m.logger = zap.NewNop()
	}

	m.logger.Debug("WAF UnmarshalCaddyfile Called", zap.String("file", d.File()), zap.Int("line", d.Line()))

	// Explicitly set default values
	m.LogSeverity = "info"
	m.LogJSON = false
	m.AnomalyThreshold = 5
	m.CountryBlock.Enabled = false
	m.CountryWhitelist.Enabled = false
	m.LogFilePath = "debug.json"
	m.RedactSensitiveData = false // Initialize with default value

	for d.Next() {
		for d.NextBlock(0) {
			directive := d.Val()
			m.logger.Debug("Processing directive", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))

			switch directive {
			case "log_path":
				if !d.NextArg() {
					return fmt.Errorf("File: %s, Line: %d: missing value for log_path", d.File(), d.Line())
				}
				m.LogFilePath = d.Val()
				m.logger.Debug("Log path set from Caddyfile",
					zap.String("log_path", m.LogFilePath),
					zap.String("file", d.File()),
					zap.Int("line", d.Line()),
				)
			case "rate_limit":
				if err := m.parseRateLimit(d); err != nil {
					return err
				}
			case "block_countries":
				if err := m.parseCountryBlock(d, true); err != nil {
					return err
				}
			case "whitelist_countries":
				if err := m.parseCountryBlock(d, false); err != nil {
					return err
				}
			case "log_severity":
				if err := m.parseLogSeverity(d); err != nil {
					return err
				}
			case "log_json":
				m.LogJSON = true
				m.logger.Debug("Log JSON enabled", zap.String("file", d.File()), zap.Int("line", d.Line()))
			case "rule_file":
				if err := m.parseRuleFile(d); err != nil {
					return err
				}
			case "ip_blacklist_file":
				if err := m.parseBlacklistFile(d, true); err != nil {
					return err
				}
			case "dns_blacklist_file":
				if err := m.parseBlacklistFile(d, false); err != nil {
					return err
				}
			case "anomaly_threshold":
				if err := m.parseAnomalyThreshold(d); err != nil {
					return err
				}
			case "custom_response":
				if err := m.parseCustomResponse(d); err != nil {
					return err
				}
			case "redact_sensitive_data":
				m.RedactSensitiveData = true
				m.logger.Debug("Redact sensitive data enabled", zap.String("file", d.File()), zap.Int("line", d.Line()))
			default:
				m.logger.Warn("WAF Unrecognized SubDirective", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))
				return fmt.Errorf("File: %s, Line: %d: unrecognized subdirective: %s", d.File(), d.Line(), d.Val())
			}
		}
	}

	return m.validateConfig()
}

func (m *Middleware) parseRuleFile(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing path for rule_file", d.File(), d.Line())
	}
	ruleFile := d.Val()
	m.RuleFiles = append(m.RuleFiles, ruleFile)

	m.logger.Info("WAF Loading Rule File",
		zap.String("file", ruleFile),
		zap.String("caddyfile", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

func (m *Middleware) parseCustomResponse(d *caddyfile.Dispenser) error {
	if m.CustomResponses == nil {
		m.CustomResponses = make(map[int]CustomBlockResponse)
	}

	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing status code for custom_response", d.File(), d.Line())
	}
	statusCode, err := strconv.Atoi(d.Val())
	if err != nil {
		return fmt.Errorf("File: %s, Line: %d: invalid status code for custom_response: %v", d.File(), d.Line(), err)
	}

	if m.CustomResponses[statusCode].Headers == nil {
		m.CustomResponses[statusCode] = CustomBlockResponse{
			StatusCode: statusCode,
			Headers:    make(map[string]string),
		}
	}

	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing content_type or file path for custom_response", d.File(), d.Line())
	}
	contentTypeOrFile := d.Val()

	if d.NextArg() {
		filePath := d.Val()
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("File: %s, Line: %d: could not read custom response file '%s': %v", d.File(), d.Line(), filePath, err)
		}
		m.CustomResponses[statusCode] = CustomBlockResponse{
			StatusCode: statusCode,
			Headers: map[string]string{
				"Content-Type": contentTypeOrFile,
			},
			Body: string(content),
		}
		m.logger.Debug("Loaded custom response from file",
			zap.Int("status_code", statusCode),
			zap.String("file", filePath),
			zap.String("content_type", contentTypeOrFile),
			zap.String("caddyfile", d.File()),
			zap.Int("line", d.Line()),
		)
	} else {
		remaining := d.RemainingArgs()
		if len(remaining) == 0 {
			return fmt.Errorf("File: %s, Line: %d: missing custom response body", d.File(), d.Line())
		}
		body := strings.Join(remaining, " ")
		m.CustomResponses[statusCode] = CustomBlockResponse{
			StatusCode: statusCode,
			Headers: map[string]string{
				"Content-Type": contentTypeOrFile,
			},
			Body: body,
		}
		m.logger.Debug("Loaded inline custom response",
			zap.Int("status_code", statusCode),
			zap.String("content_type", contentTypeOrFile),
			zap.String("body", body),
			zap.String("caddyfile", d.File()),
			zap.Int("line", d.Line()),
		)
	}
	return nil
}

func (m *Middleware) parseRateLimit(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing requests value for rate_limit", d.File(), d.Line())
	}
	requests, err := strconv.Atoi(d.Val())
	if err != nil {
		return fmt.Errorf("File: %s, Line: %d: invalid requests value for rate_limit: %v", d.File(), d.Line(), err)
	}

	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing window duration for rate_limit", d.File(), d.Line())
	}
	window, err := time.ParseDuration(d.Val())
	if err != nil {
		return fmt.Errorf("File: %s, Line: %d: invalid duration for rate_limit: %v", d.File(), d.Line(), err)
	}

	cleanupInterval := time.Minute
	if d.NextArg() {
		cleanupInterval, err = time.ParseDuration(d.Val())
		if err != nil {
			return fmt.Errorf("File: %s, Line: %d: invalid cleanup interval: %v", d.File(), d.Line(), err)
		}
	}

	m.RateLimit = RateLimit{
		Requests:        requests,
		Window:          window,
		CleanupInterval: cleanupInterval,
	}

	m.logger.Debug("Rate limit configured",
		zap.Int("requests", requests),
		zap.Duration("window", window),
		zap.Duration("cleanup_interval", cleanupInterval),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

func (m *Middleware) parseCountryBlock(d *caddyfile.Dispenser, isBlock bool) error {
	target := &m.CountryBlock
	if !isBlock {
		target = &m.CountryWhitelist
	}
	target.Enabled = true

	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing GeoIP DB path", d.File(), d.Line())
	}
	target.GeoIPDBPath = d.Val()
	target.CountryList = []string{}

	for d.NextArg() {
		country := strings.ToUpper(d.Val())
		target.CountryList = append(target.CountryList, country)
	}

	m.logger.Debug("Country list configured",
		zap.Bool("block_mode", isBlock),
		zap.Strings("countries", target.CountryList),
		zap.String("geoip_db_path", target.GeoIPDBPath),
		zap.String("file", d.File()), zap.Int("line", d.Line()),
	)
	return nil
}

func (m *Middleware) parseLogSeverity(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing value for log_severity", d.File(), d.Line())
	}
	m.LogSeverity = d.Val()
	m.logger.Debug("Log severity set",
		zap.String("severity", m.LogSeverity),
		zap.String("file", d.File()), zap.Int("line", d.Line()),
	)
	return nil
}

func (m *Middleware) parseBlacklistFile(d *caddyfile.Dispenser, isIP bool) error {
	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing blacklist file path", d.File(), d.Line())
	}
	if isIP {
		m.IPBlacklistFile = d.Val()
	} else {
		m.DNSBlacklistFile = d.Val()
	}
	m.logger.Info("Blacklist file loaded", zap.String("file", d.Val()), zap.Bool("is_ip", isIP))
	return nil
}

func (m *Middleware) parseAnomalyThreshold(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return fmt.Errorf("File: %s, Line: %d: missing threshold value", d.File(), d.Line())
	}
	threshold, err := strconv.Atoi(d.Val())
	if err != nil {
		return fmt.Errorf("File: %s, Line: %d: invalid threshold: %v", d.File(), d.Line(), err)
	}
	m.AnomalyThreshold = threshold
	m.logger.Debug("Anomaly threshold set", zap.Int("threshold", threshold))
	return nil
}

func (m *Middleware) validateConfig() error {
	if m.RateLimit.Requests <= 0 || m.RateLimit.Window <= 0 {
		return fmt.Errorf("invalid rate limit configuration: requests and window must be greater than zero")
	}
	if m.CountryBlock.Enabled && m.CountryBlock.GeoIPDBPath == "" {
		return fmt.Errorf("country block is enabled but no GeoIP database path specified")
	}
	if len(m.RuleFiles) == 0 {
		return fmt.Errorf("no rule files specified")
	}
	return nil
}

// Option for configuring the Middleware
type MiddlewareOption func(*Middleware)

// WithGeoIPCache enables GeoIP lookup caching.
func WithGeoIPCache(ttl time.Duration) MiddlewareOption {
	return func(m *Middleware) {
		m.geoIPCache = make(map[string]GeoIPRecord)
		m.geoIPCacheTTL = ttl
	}
}

// WithGeoIPLookupFallbackBehavior configures the fallback behavior for GeoIP lookups.
func WithGeoIPLookupFallbackBehavior(behavior string) MiddlewareOption {
	return func(m *Middleware) {
		m.geoIPLookupFallbackBehavior = behavior
	}
}

// NewMiddleware creates a new Middleware with options.
func NewMiddleware(logger *zap.Logger, options ...MiddlewareOption) *Middleware {
	m := &Middleware{
		logger: logger,
	}
	for _, option := range options {
		option(m)
	}
	return m
}

func (m *Middleware) extractIPFromRemoteAddr(remoteAddr string) (string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, nil // If it's not in host:port format, assume it's just the IP
	}
	return host, nil
}

// isCountryInList function with improvements
func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if geoIP == nil {
		return false, fmt.Errorf("geoip database not loaded")
	}

	ip, err := m.extractIPFromRemoteAddr(remoteAddr)
	if err != nil {
		return false, err
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		m.logger.Error("invalid IP address", zap.String("ip", ip))
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Easy: Add caching of GeoIP lookups for performance.
	if m.geoIPCache != nil {
		m.geoIPCacheMutex.RLock()
		if record, ok := m.geoIPCache[ip]; ok {
			m.geoIPCacheMutex.RUnlock()
			for _, country := range countryList {
				if strings.EqualFold(record.Country.ISOCode, country) {
					return true, nil
				}
			}
			return false, nil
		}
		m.geoIPCacheMutex.RUnlock()
	}

	var record GeoIPRecord
	err = geoIP.Lookup(parsedIP, &record)
	if err != nil {
		m.logger.Error("geoip lookup failed", zap.String("ip", ip), zap.Error(err))

		// Critical: Handle cases where the GeoIP database lookup fails more gracefully.
		switch m.geoIPLookupFallbackBehavior {
		case "default":
			// Log and treat as not in the list
			return false, nil
		case "none":
			return false, fmt.Errorf("geoip lookup failed: %w", err)
		case "": // No fallback configured, maintain existing behavior
			return false, fmt.Errorf("geoip lookup failed: %w", err)
		default:
			// Configurable fallback country code
			for _, country := range countryList {
				if strings.EqualFold(m.geoIPLookupFallbackBehavior, country) {
					return true, nil
				}
			}
			return false, nil
		}
	}

	// Easy: Add caching of GeoIP lookups for performance.
	if m.geoIPCache != nil {
		m.geoIPCacheMutex.Lock()
		m.geoIPCache[ip] = record
		m.geoIPCacheMutex.Unlock()

		// Invalidate cache entry after TTL (basic implementation)
		if m.geoIPCacheTTL > 0 {
			time.AfterFunc(m.geoIPCacheTTL, func() {
				m.geoIPCacheMutex.Lock()
				delete(m.geoIPCache, ip)
				m.geoIPCacheMutex.Unlock()
			})
		}
	}

	for _, country := range countryList {
		if strings.EqualFold(record.Country.ISOCode, country) {
			return true, nil
		}
	}

	return false, nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Generate a unique log ID for this request
	logID := uuid.New().String()
	ctx := context.WithValue(r.Context(), "logID", logID)
	r = r.WithContext(ctx)

	// Example within your ServeHTTP method
	m.logRequest(zapcore.DebugLevel, "Entering ServeHTTP", zap.String("path", r.URL.Path))

	state := &WAFState{
		TotalScore:      0,
		Blocked:         false,
		StatusCode:      http.StatusOK,
		ResponseWritten: false,
	}

	m.logger.Info("WAF evaluation started",
		zap.String("log_id", logID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
		zap.String("query_params", r.URL.RawQuery),
	)

	// Helper function to handle blocking actions
	block := func(statusCode int, reason string, fields ...zap.Field) error {
		if !state.ResponseWritten {
			m.blockRequest(w, r, state, statusCode, append(fields, zap.String("reason", reason))...)
			return nil
		}
		m.logger.Debug("Blocking action skipped, response already written", zap.String("log_id", logID), zap.String("reason", reason))
		return nil
	}

	// Whitelist Check
	if m.CountryWhitelist.Enabled {
		whitelisted, err := m.isCountryInList(r.RemoteAddr, m.CountryWhitelist.CountryList, m.CountryWhitelist.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check whitelist",
				zap.String("log_id", logID),
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
			// Consider blocking or allowing based on your policy if whitelist check fails
			// For now, proceeding to blacklist as if not whitelisted
		} else if whitelisted {
			m.logRequest(zapcore.InfoLevel, "Request allowed - country whitelisted",
				zap.String("log_id", logID),
				zap.String("country", m.getCountryCode(r.RemoteAddr, m.CountryWhitelist.geoIP)),
			)
			return next.ServeHTTP(w, r) // Allow immediately
		}
	}

	// Blacklist Check (only if not whitelisted or whitelist disabled)
	if m.CountryBlock.Enabled {
		blacklisted, err := m.isCountryInList(r.RemoteAddr, m.CountryBlock.CountryList, m.CountryBlock.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check blacklist",
				zap.String("log_id", logID),
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
			return block(http.StatusInternalServerError, "blacklist_check_error", zap.String("message", "Internal error during blacklist check"))
		} else if blacklisted {
			m.logRequest(zapcore.WarnLevel, "Request blocked - country blacklisted",
				zap.String("log_id", logID),
				zap.String("country", m.getCountryCode(r.RemoteAddr, m.CountryBlock.geoIP)),
			)
			return block(http.StatusForbidden, "country_blacklist", zap.String("message", "Request blocked by country blacklist"))
		}
	}

	// Phase 1 - Request Headers
	m.logger.Debug("Executing Phase 1 (Request Headers)",
		zap.String("log_id", logID),
	)
	m.handlePhase(w, r, 1, state)
	if state.Blocked && !state.ResponseWritten {
		m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 1",
			zap.String("log_id", logID),
			zap.Int("status_code", state.StatusCode),
			zap.String("reason", "phase_1_block"),
		)
		w.WriteHeader(state.StatusCode)
		return nil
	}

	// Phase 2 - Request Body
	if !state.ResponseWritten {
		m.logger.Debug("Executing Phase 2 (Request Body)",
			zap.String("log_id", logID),
		)
		m.handlePhase(w, r, 2, state)
		if state.Blocked && !state.ResponseWritten {
			m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 2",
				zap.String("log_id", logID),
				zap.Int("status_code", state.StatusCode),
				zap.String("reason", "phase_2_block"),
			)
			w.WriteHeader(state.StatusCode)
			return nil
		}
	}

	// Response Recorder for Phase 3 and 4
	recorder := &responseRecorder{ResponseWriter: w, body: new(bytes.Buffer)}
	w = recorder

	// Pass request to upstream handler
	err := next.ServeHTTP(w, r)

	// Phase 3 - Response Headers
	m.logger.Debug("Executing Phase 3 (Response Headers)",
		zap.String("log_id", logID),
	)
	m.handlePhase(recorder, r, 3, state)
	if state.Blocked && !state.ResponseWritten {
		m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 3",
			zap.String("log_id", logID),
			zap.Int("status_code", state.StatusCode),
			zap.String("reason", "phase_3_block"),
		)
		w.WriteHeader(state.StatusCode)
		return nil
	}

	// Phase 4 - Response Body (after response is written)
	m.logger.Debug("Executing Phase 4 (Response Body)",
		zap.String("log_id", logID),
		zap.Int("response_length", recorder.body.Len()), // Use recorder.body.Len()
	)

	// Check if recorder.body is nil before accessing it
	if recorder.body != nil {
		body := recorder.body.String()
		m.logger.Debug("Phase 4 Response Body", zap.String("response_body", body))

		for _, rule := range m.Rules[4] {
			m.logger.Debug("Checking rule", zap.String("rule_id", rule.ID), zap.String("pattern", rule.Pattern), zap.String("description", rule.Description))
			if rule.regex.MatchString(body) {
				m.processRuleMatch(recorder, r, &rule, body, state)
				if state.Blocked && !state.ResponseWritten {
					m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 4 (Response Body)",
						zap.String("log_id", logID),
						zap.String("rule_id", rule.ID),
						zap.String("description", rule.Description),
						zap.Int("status_code", state.StatusCode),
						zap.String("reason", "phase_4_block"),
					)
					recorder.WriteHeader(state.StatusCode) // Use recorder to ensureWriteHeader is called only once
					return nil
				}
			}
		}

		// If not blocked, flush the recorded body to the client
		if !state.Blocked && !state.ResponseWritten {
			_, err = w.Write(recorder.body.Bytes())
			if err != nil {
				m.logger.Error("Failed to flush response body", zap.Error(err))
			}
		}
	} else {
		m.logger.Debug("Phase 4: Response body is nil, skipping rule evaluation")
	}

	m.logger.Info("WAF evaluation complete",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
	)

	return err
}

// getCountryCode extracts the country code for logging purposes
func (m *Middleware) getCountryCode(remoteAddr string, geoIP *maxminddb.Reader) string {
	if geoIP == nil {
		return "N/A"
	}
	ip, err := m.extractIPFromRemoteAddr(remoteAddr)
	if err != nil {
		return "N/A"
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "N/A"
	}
	var record GeoIPRecord
	err = geoIP.Lookup(parsedIP, &record)
	if err != nil {
		return "N/A"
	}
	return record.Country.ISOCode
}

func (m *Middleware) blockRequest(w http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, fields ...zap.Field) {
	// Critical: Ensure that WriteHeader is called only once.
	if !state.ResponseWritten {
		state.Blocked = true
		state.StatusCode = statusCode
		state.ResponseWritten = true

		// Awesome: Allow customization of the blocking response (e.g., custom error pages).
		if resp, ok := m.CustomResponses[statusCode]; ok {
			for key, value := range resp.Headers {
				w.Header().Set(key, value)
			}
			w.WriteHeader(resp.StatusCode)
			_, err := w.Write([]byte(resp.Body))
			if err != nil {
				m.logger.Error("Failed to write custom block response body", zap.Error(err), zap.Int("status_code", resp.StatusCode), zap.String("log_id", r.Context().Value("logID").(string)))
			}
			return
		}

		// Default blocking behavior if no custom response is configured.
		// Extract or generate log ID from request context
		logID, _ := r.Context().Value("logID").(string)
		if logID == "" {
			logID = uuid.New().String()
		}

		// Prepare standard fields for logging
		blockFields := append(fields,
			zap.String("log_id", logID),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
			zap.Int("status_code", statusCode),
			zap.Time("timestamp", time.Now()),
		)

		// Log the blocked request at WARN level
		m.logRequest(zapcore.WarnLevel, "Request blocked", blockFields...)

		// Respond with the status code
		w.WriteHeader(statusCode)
	} else {
		// Easy: Add more context to the debug logging when blocking is skipped.
		m.logger.Debug("blockRequest called but response already written",
			zap.Int("intended_status_code", statusCode),
			zap.String("path", r.URL.Path),
			zap.String("log_id", r.Context().Value("logID").(string)),
			zap.Int("current_status_code", state.StatusCode), // Add current status code
		)
	}
}

// extractIP extracts the IP address from a remote address string.
func extractIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	// Remove brackets from IPv6 addresses
	if strings.HasPrefix(remoteAddr, "[") && strings.HasSuffix(remoteAddr, "]") {
		remoteAddr = strings.TrimPrefix(remoteAddr, "[")
		remoteAddr = strings.TrimSuffix(remoteAddr, "]")
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}

	ip := net.ParseIP(remoteAddr)
	if ip != nil {
		return ip.String()
	}

	return ""
}

type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func NewResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		body:           new(bytes.Buffer),
		statusCode:     0, // Zero means not explicitly set
	}
}

// WriteHeader captures the response status code
func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Header returns the response headers
func (r *responseRecorder) Header() http.Header {
	return r.ResponseWriter.Header()
}

// BodyString returns the captured response body as a string
func (r *responseRecorder) BodyString() string {
	return r.body.String()
}

// StatusCode returns the captured status code
func (r *responseRecorder) StatusCode() int {
	if r.statusCode == 0 {
		return http.StatusOK // Default to 200 if not explicitly set
	}
	return r.statusCode
}

// Write captures the response body and writes to the buffer only
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 {
		// Ensure status code is set if WriteHeader wasn't called
		r.WriteHeader(http.StatusOK)
	}
	// Only write to the buffer, not the underlying ResponseWriter
	return r.body.Write(b)
}

func (m *Middleware) processRuleMatch(w http.ResponseWriter, r *http.Request, rule *Rule, value string, state *WAFState) {
	// Default action to "block" if empty
	if rule.Action == "" {
		rule.Action = "block"
		m.logger.Debug("Rule action is empty, defaulting to 'block'", zap.String("rule_id", rule.ID))
	}

	// Extract log ID from request context
	logID, _ := r.Context().Value("logID").(string)
	if logID == "" {
		logID = uuid.New().String() // Fallback to new UUID if missing
	}

	// Log that a rule was matched
	m.logRequest(zapcore.DebugLevel, "Rule matched during evaluation",
		zap.String("log_id", logID),
		zap.String("rule_id", rule.ID),
		zap.String("target", strings.Join(rule.Targets, ",")),
		zap.String("value", value),
		zap.String("description", rule.Description),
		zap.Int("score", rule.Score),
	)

	// Increase the total anomaly score
	oldScore := state.TotalScore
	state.TotalScore += rule.Score
	m.logRequest(zapcore.DebugLevel, "Increased anomaly score",
		zap.String("log_id", logID),
		zap.String("rule_id", rule.ID),
		zap.Int("score_increase", rule.Score),
		zap.Int("old_total_score", oldScore),
		zap.Int("new_total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	// Capture detailed request and rule information for comprehensive logging
	requestInfo := []zap.Field{
		zap.String("log_id", logID),
		zap.String("rule_id", rule.ID),
		zap.String("target", strings.Join(rule.Targets, ",")),
		zap.String("value", value), // Be cautious with logging sensitive data
		zap.String("description", rule.Description),
		zap.Int("score", rule.Score),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
		zap.String("mode", rule.Action),
		zap.String("severity", rule.Severity),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
		zap.String("request_method", r.Method),
		zap.String("request_path", r.URL.Path),
		zap.String("query_params", r.URL.RawQuery),
		zap.Time("timestamp", time.Now()),
	}

	// Log the rule match in detail with Info level
	m.logRequest(zapcore.InfoLevel, "Detailed rule match information", requestInfo...)

	// Determine if a blocking action should be taken
	shouldBlock := false
	blockReason := ""

	if !state.ResponseWritten {
		if state.TotalScore >= m.AnomalyThreshold {
			shouldBlock = true
			blockReason = "Anomaly threshold exceeded"
		} else if rule.Action == "block" {
			shouldBlock = true
			blockReason = "Rule action is 'block'"
		} else if rule.Action != "log" {
			shouldBlock = true
			blockReason = "Unknown rule action"
		}
	} else {
		m.logger.Debug("Blocking actions skipped, response already written", zap.String("log_id", logID), zap.String("rule_id", rule.ID))
	}

	// Perform blocking action if needed and response not already written
	if shouldBlock && !state.ResponseWritten {
		state.Blocked = true
		state.StatusCode = http.StatusForbidden
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true

		m.logRequest(zapcore.WarnLevel, "Request blocked",
			zap.String("log_id", logID),
			zap.String("rule_id", rule.ID),
			zap.Int("status_code", state.StatusCode),
			zap.String("reason", blockReason),
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
		)
		return // Exit after blocking
	}

	// Handle the rule's defined action (log) if not blocked
	if rule.Action == "log" {
		m.logRequest(zapcore.InfoLevel, "Rule action is 'log', request allowed but logged",
			zap.String("log_id", logID),
			zap.String("rule_id", rule.ID),
		)
	} else if !shouldBlock && !state.ResponseWritten {
		// Log when a rule matches but doesn't lead to blocking
		m.logRequest(zapcore.DebugLevel, "Rule matched, no blocking action taken",
			zap.String("log_id", logID),
			zap.String("rule_id", rule.ID),
			zap.String("action", rule.Action),
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
		)
	}
}

func (m *Middleware) handlePhase(w http.ResponseWriter, r *http.Request, phase int, state *WAFState) {
	m.logger.Debug("Starting phase evaluation",
		zap.Int("phase", phase),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	// Phase 1 - Country Blocking
	if phase == 1 && m.CountryBlock.Enabled {
		m.logger.Debug("Starting country blocking phase")
		blocked, err := m.isCountryInList(r.RemoteAddr, m.CountryBlock.CountryList, m.CountryBlock.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check country block",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
			m.blockRequest(w, r, state, http.StatusForbidden,
				zap.String("message", "Request blocked due to internal error"),
				zap.String("reason", "internal_error"),
			)
			m.logger.Debug("Country blocking phase completed - blocked due to error")
			return
		} else if blocked {
			m.blockRequest(w, r, state, http.StatusForbidden,
				zap.String("message", "Request blocked by country"),
				zap.String("reason", "country_block"),
			)
			m.logger.Debug("Country blocking phase completed - blocked by country")
			return
		}
		m.logger.Debug("Country blocking phase completed - not blocked")
	}

	// Phase 1 - Rate Limiting
	if phase == 1 && m.rateLimiter != nil {
		m.logger.Debug("Starting rate limiting phase")
		ip := extractIP(r.RemoteAddr)
		if m.rateLimiter.isRateLimited(ip) {
			m.blockRequest(w, r, state, http.StatusTooManyRequests,
				zap.String("message", "Request blocked by rate limit"),
				zap.String("reason", "rate_limit"),
			)
			m.logger.Debug("Rate limiting phase completed - blocked by rate limit")
			return
		}
		m.logger.Debug("Rate limiting phase completed - not blocked")
	}

	// Phase 1 - IP Blacklist
	if phase == 1 && m.isIPBlacklisted(r.RemoteAddr) {
		m.logger.Debug("Starting IP blacklist phase")
		m.blockRequest(w, r, state, http.StatusForbidden,
			zap.String("message", "Request blocked by IP blacklist"),
			zap.String("reason", "ip_blacklist"),
		)
		m.logger.Debug("IP blacklist phase completed - blocked")
		return
	}

	// Phase 1 - DNS Blacklist
	if phase == 1 && m.isDNSBlacklisted(r.Host) {
		m.logger.Debug("Starting DNS blacklist phase")
		m.blockRequest(w, r, state, http.StatusForbidden,
			zap.String("message", "Request blocked by DNS blacklist"),
			zap.String("reason", "dns_blacklist"),
			zap.String("host", r.Host),
		)
		m.logger.Debug("DNS blacklist phase completed - blocked")
		return
	}

	// Phase 1 to 4 - Rule Evaluation
	rules, ok := m.Rules[phase]
	if !ok {
		m.logger.Debug("No rules found for phase",
			zap.Int("phase", phase),
		)
		return
	}

	m.logger.Debug("Starting rule evaluation for phase", zap.Int("phase", phase), zap.Int("rule_count", len(rules)))
	for _, rule := range rules {
		m.logger.Debug("Processing rule", zap.String("rule_id", rule.ID), zap.Int("target_count", len(rule.Targets)))
		ctx := context.WithValue(r.Context(), "rule_id", rule.ID)
		r = r.WithContext(ctx)
		for _, target := range rule.Targets {
			m.logger.Debug("Extracting value for target", zap.String("target", target), zap.String("rule_id", rule.ID))
			var value string
			var err error

			// Correctly pass response recorder when available
			if phase == 3 || phase == 4 {
				if recorder, ok := w.(*responseRecorder); ok {
					value, err = m.extractValue(target, r, recorder)
				} else {
					// Should not happen, but log it if we reach here
					m.logger.Error("response recorder is not available in phase 3 or 4 when required")
					value, err = m.extractValue(target, r, nil)
				}
			} else {
				value, err = m.extractValue(target, r, nil)
			}

			if err != nil {
				m.logger.Debug("Failed to extract value for target, skipping rule for this target",
					zap.String("target", target),
					zap.String("rule_id", rule.ID),
					zap.Error(err),
				)
				continue
			}

			// Redact sensitive fields from being logged

			m.logger.Debug("Extracted value",
				zap.String("rule_id", rule.ID),
				zap.String("target", target),
				zap.String("value", value),
			)

			if rule.regex.MatchString(value) {
				m.logger.Debug("Rule matched",
					zap.String("rule_id", rule.ID),
					zap.String("target", target),
					zap.String("value", value),
				)
				m.processRuleMatch(w, r, &rule, value, state)
				if state.Blocked || state.ResponseWritten {
					m.logger.Debug("Rule evaluation completed early due to blocking or response written", zap.Int("phase", phase), zap.String("rule_id", rule.ID))
					return
				}
			} else {
				m.logger.Debug("Rule did not match",
					zap.String("rule_id", rule.ID),
					zap.String("target", target),
					zap.String("value", value),
				)
			}
		}
	}
	m.logger.Debug("Rule evaluation completed for phase", zap.Int("phase", phase))

	// Phase 3 - Response Headers
	if phase == 3 {
		m.logger.Debug("Starting response headers phase")
		if recorder, ok := w.(*responseRecorder); ok {
			headers := recorder.Header()
			m.logger.Debug("Processing response headers", zap.Any("headers", headers))
			for _, rule := range m.Rules[3] {
				m.logger.Debug("Processing rule for response headers", zap.String("rule_id", rule.ID), zap.Int("target_count", len(rule.Targets)))
				for _, target := range rule.Targets {
					value := headers.Get(target)
					m.logger.Debug("Checking response header", zap.String("rule_id", rule.ID), zap.String("target", target), zap.String("value", value))
					if value != "" && rule.regex.MatchString(value) {
						m.logger.Debug("Rule matched on response header", zap.String("rule_id", rule.ID), zap.String("target", target), zap.String("value", value))
						m.processRuleMatch(recorder, r, &rule, value, state)
						if state.Blocked || state.ResponseWritten {
							m.logger.Debug("Response headers phase completed early due to blocking or response written", zap.Int("phase", phase), zap.String("rule_id", rule.ID))
							return
						}
					} else {
						m.logger.Debug("Rule did not match on response header", zap.String("rule_id", rule.ID), zap.String("target", target), zap.String("value", value))
					}
				}
			}
		}
		m.logger.Debug("Response headers phase completed")
	}

	// Phase 4 - Response Body
	if phase == 4 {
		m.logger.Debug("Starting response body phase")
		if recorder, ok := w.(*responseRecorder); ok {
			body := recorder.BodyString()
			m.logger.Debug("Processing response body", zap.Int("body_length", len(body)))
			for _, rule := range m.Rules[4] {
				m.logger.Debug("Processing rule for response body", zap.String("rule_id", rule.ID), zap.Int("target_count", len(rule.Targets)))
				for _, target := range rule.Targets {
					if target == "RESPONSE_BODY" {
						m.logger.Debug("Checking rule against response body", zap.String("rule_id", rule.ID))
						if rule.regex.MatchString(body) {
							m.logger.Debug("Rule matched on response body", zap.String("rule_id", rule.ID))
							m.processRuleMatch(recorder, r, &rule, body, state)
							if state.Blocked || state.ResponseWritten {
								m.logger.Debug("Response body phase completed early due to blocking or response written", zap.Int("phase", phase), zap.String("rule_id", rule.ID))
								return
							}
						} else {
							m.logger.Debug("Rule did not match on response body", zap.String("rule_id", rule.ID))
						}
					}
				}
			}
		}
		m.logger.Debug("Response body phase completed")
	}

	m.logger.Debug("Completed phase evaluation",
		zap.Int("phase", phase),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)
}

func (m *Middleware) logRequest(level zapcore.Level, msg string, fields ...zap.Field) {
	if m.logger == nil {
		return
	}

	// Extract log ID from fields or request context
	var logID string
	var foundLogID bool
	for i, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
			fields = append(fields[:i], fields[i+1:]...) // Remove log_id from fields
			foundLogID = true
			break
		}
	}

	// Fallback to generating a new log ID if missing or not found in fields
	if !foundLogID {
		logID = uuid.New().String()
	}
	fields = append(fields, zap.String("log_id", logID))

	// Attach common request metadata (IP, User-Agent, etc.)
	commonFields := m.getCommonLogFields(fields)
	fields = append(fields, commonFields...)

	// Set logging threshold if unset
	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}

	// Cache log level for efficiency
	if m.logLevel == 0 {
		switch strings.ToLower(m.LogSeverity) {
		case "debug":
			m.logLevel = zapcore.DebugLevel
		case "warn":
			m.logLevel = zapcore.WarnLevel
		case "error":
			m.logLevel = zapcore.ErrorLevel
		default:
			m.logLevel = zapcore.InfoLevel
		}
	}

	// Skip logging if level is below threshold
	if level < m.logLevel {
		return
	}

	// Perform JSON or plaintext logging
	if m.LogJSON {
		fields = append(fields, zap.String("message", msg))
		m.logger.Log(level, "", fields...)
	} else {
		m.logger.Log(level, msg, fields...)
	}
}

func (m *Middleware) getCommonLogFields(fields []zap.Field) []zap.Field {
	var logID string
	var sourceIP string
	var userAgent string
	var requestMethod string
	var requestPath string
	var queryParams string
	var statusCode int

	for _, field := range fields {
		switch field.Key {
		case "log_id":
			logID = field.String
		case "source_ip":
			sourceIP = field.String
		case "user_agent":
			userAgent = field.String
		case "request_method":
			requestMethod = field.String
		case "request_path":
			requestPath = field.String
		case "query_params":
			queryParams = field.String
		case "status_code":
			statusCode = int(field.Integer) // Explicit conversion here
		}
	}

	// Create the common fields
	commonFields := []zap.Field{
		zap.String("log_id", logID),
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.Int("status_code", statusCode),
	}
	if m.RedactSensitiveData {
		redactedQueryParams := m.redactQueryParams(queryParams)
		commonFields = append(commonFields, zap.String("query_params", redactedQueryParams))

	} else {
		commonFields = append(commonFields, zap.String("query_params", queryParams))
	}

	return commonFields
}

func (m *Middleware) redactQueryParams(queryParams string) string {
	if queryParams == "" {
		return ""
	}

	parts := strings.Split(queryParams, "&")
	for i, part := range parts {
		if strings.Contains(part, "=") {
			keyValue := strings.SplitN(part, "=", 2)
			if len(keyValue) == 2 {
				key := strings.ToLower(keyValue[0])
				if strings.Contains(key, "password") || strings.Contains(key, "token") || strings.Contains(key, "apikey") || strings.Contains(key, "authorization") || strings.Contains(key, "secret") {
					parts[i] = keyValue[0] + "=REDACTED"
				}
			}
		}
	}
	return strings.Join(parts, "&")
}

func (m *Middleware) startFileWatcher(filePaths []string) {
	for _, path := range filePaths {
		go func(file string) {
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				m.logger.Error("Failed to start file watcher", zap.Error(err))
				return
			}
			defer watcher.Close()

			err = watcher.Add(file)
			if err != nil {
				m.logger.Error("Failed to watch file", zap.String("file", file), zap.Error(err))
				return
			}

			for {
				select {
				case event := <-watcher.Events:
					if event.Op&fsnotify.Write == fsnotify.Write {
						m.logger.Info("Detected configuration change. Reloading...",
							zap.String("file", file),
						)
						err := m.ReloadConfig()
						if err != nil {
							m.logger.Error("Failed to reload config after change",
								zap.Error(err),
							)
						} else {
							m.logger.Info("Configuration reloaded successfully")
						}
					}
				case err := <-watcher.Errors:
					m.logger.Error("File watcher error", zap.Error(err))
				}
			}
		}(path)
	}
}

func caddyTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006/01/02 15:04:05.000"))
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	// Use Caddy's logger for console (default if custom logger fails)
	m.logger = ctx.Logger(m)

	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}

	// Default log file path (fallback)
	logFilePath := m.LogFilePath
	if logFilePath == "" {
		logFilePath = "/var/log/caddy/waf.json"
	}

	// Set logging level based on severity
	var logLevel zapcore.Level
	switch strings.ToLower(m.LogSeverity) {
	case "debug":
		logLevel = zapcore.DebugLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	default:
		logLevel = zapcore.InfoLevel
	}

	// Zap production config for console with colors
	consoleCfg := zap.NewProductionConfig()
	consoleCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	consoleCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // Keep colors for console
	consoleCfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg.EncoderConfig)
	consoleSync := zapcore.AddSync(os.Stdout)

	// Zap production config for file logging without colors
	fileCfg := zap.NewProductionConfig()
	fileCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	fileCfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder // No colors for file
	fileCfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	fileEncoder := zapcore.NewJSONEncoder(fileCfg.EncoderConfig)

	// Attempt to open the log file
	fileSync, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		m.logger.Warn("Failed to open log file, logging only to console",
			zap.String("path", logFilePath), zap.Error(err))
		// Fall back to console-only logging with color
		m.logger = zap.New(zapcore.NewCore(consoleEncoder, consoleSync, logLevel))
		return nil
	}

	// Combine console (with color) and file (no color) logging
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleSync, logLevel),                  // Console with color (matches severity)
		zapcore.NewCore(fileEncoder, zapcore.AddSync(fileSync), zap.DebugLevel), // File without color (always logs Debug)
	)

	m.logger = zap.New(core)
	m.logger.Info("Provisioning WAF middleware",
		zap.String("log_level", m.LogSeverity),
		zap.String("log_path", logFilePath),
		zap.Bool("log_json", m.LogJSON),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	// Log the dynamically fetched version
	m.logVersion()

	// Start watching files for reload (IP blacklist, DNS blacklist)
	m.startFileWatcher([]string{m.IPBlacklistFile, m.DNSBlacklistFile})

	// Rate Limiter Setup
	if m.RateLimit.Requests > 0 {
		m.logger.Info("Rate limit configuration",
			zap.Int("requests", m.RateLimit.Requests),
			zap.Duration("window", m.RateLimit.Window),
			zap.Duration("cleanup_interval", m.RateLimit.CleanupInterval),
		)
		m.rateLimiter = &RateLimiter{
			requests: make(map[string]*requestCounter),
			config:   m.RateLimit,
		}
		m.rateLimiter.startCleanup()
	} else {
		m.logger.Info("Rate limiting is disabled")
	}

	// GeoIP Loading
	var geoIPReader *maxminddb.Reader
	if m.CountryBlock.Enabled || m.CountryWhitelist.Enabled {
		geoIPPath := m.CountryBlock.GeoIPDBPath
		if m.CountryWhitelist.Enabled && m.CountryWhitelist.GeoIPDBPath != "" {
			geoIPPath = m.CountryWhitelist.GeoIPDBPath
		}

		if !fileExists(geoIPPath) {
			m.logger.Warn("GeoIP database not found. Country blocking/whitelisting will be disabled",
				zap.String("path", geoIPPath),
			)
		} else {
			m.logger.Debug("Attempting to load GeoIP database",
				zap.String("path", geoIPPath),
			)
			reader, err := maxminddb.Open(geoIPPath)
			if err != nil {
				m.logger.Error("Failed to load GeoIP database",
					zap.String("path", geoIPPath),
					zap.Error(err),
				)
			} else {
				m.logger.Info("GeoIP database loaded successfully",
					zap.String("path", geoIPPath),
				)
				geoIPReader = reader
			}
		}
	}

	// Assign GeoIP Reader
	if geoIPReader != nil {
		if m.CountryBlock.Enabled {
			m.CountryBlock.geoIP = geoIPReader
		}
		if m.CountryWhitelist.Enabled {
			m.CountryWhitelist.geoIP = geoIPReader
		}
	}

	// Rule, Blacklists File Loading
	if err := m.loadRules(m.RuleFiles, m.IPBlacklistFile, m.DNSBlacklistFile); err != nil {
		return fmt.Errorf("failed to load rules and blacklists: %w", err)
	}

	m.logger.Info("WAF middleware provisioned successfully")
	return nil
}

func (m *Middleware) loadRules(paths []string, ipBlacklistPath string, dnsBlacklistPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Loading rules and blacklists from files", zap.Strings("rule_files", paths), zap.String("ip_blacklist", ipBlacklistPath), zap.String("dns_blacklist", dnsBlacklistPath))

	m.Rules = make(map[int][]Rule)
	totalRules := 0
	var invalidFiles []string
	var allInvalidRules []string
	ruleIDs := make(map[string]bool) // Track rule IDs across all files

	// Load Rules
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			m.logger.Error("Failed to read rule file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue
		}

		var rules []Rule
		if err := json.Unmarshal(content, &rules); err != nil {
			m.logger.Error("Failed to unmarshal rules from file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue
		}

		var invalidRulesInFile []string
		for i, rule := range rules {
			// Validate rule structure
			if err := validateRule(&rule); err != nil {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule at index %d: %v", i, err))
				continue
			}

			// Check for duplicate IDs across all files
			if _, exists := ruleIDs[rule.ID]; exists {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Duplicate rule ID '%s' at index %d", rule.ID, i))
				continue
			}
			ruleIDs[rule.ID] = true

			// Compile regex pattern
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				m.logger.Error("Failed to compile regex for rule", zap.String("rule_id", rule.ID), zap.String("pattern", rule.Pattern), zap.Error(err))
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule '%s': invalid regex pattern: %v", rule.ID, err))
				continue
			}
			rule.regex = regex

			// Initialize phase if missing
			if _, ok := m.Rules[rule.Phase]; !ok {
				m.Rules[rule.Phase] = []Rule{}
			}

			// Add rule to appropriate phase
			m.Rules[rule.Phase] = append(m.Rules[rule.Phase], rule)
			totalRules++
		}
		if len(invalidRulesInFile) > 0 {
			m.logger.Warn("Some rules failed validation", zap.String("file", path), zap.Strings("invalid_rules", invalidRulesInFile))
			allInvalidRules = append(allInvalidRules, invalidRulesInFile...)
		}

		m.logger.Info("Rules loaded", zap.String("file", path), zap.Int("total_rules", len(rules)), zap.Int("invalid_rules", len(invalidRulesInFile)))
	}

	// Load IP Blacklist
	m.ipBlacklist = make(map[string]bool) // Initialize the IP blacklist map
	if ipBlacklistPath != "" {
		content, err := os.ReadFile(ipBlacklistPath)
		if err != nil {
			m.logger.Warn("Failed to read IP blacklist file", zap.String("file", ipBlacklistPath), zap.Error(err))
		} else {
			lines := strings.Split(string(content), "\n")
			validEntries := 0
			for i, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue // Skip empty lines and comments
				}

				// Check if the line is a valid IP or CIDR range
				if _, _, err := net.ParseCIDR(line); err == nil {
					// It's a valid CIDR range
					m.ipBlacklist[line] = true
					validEntries++
					m.logger.Debug("Added CIDR range to blacklist",
						zap.String("cidr", line),
					)
					continue
				}

				if ip := net.ParseIP(line); ip != nil {
					// It's a valid IP address
					m.ipBlacklist[line] = true
					validEntries++
					m.logger.Debug("Added IP to blacklist",
						zap.String("ip", line),
					)
					continue
				}

				// Log invalid entries for debugging
				m.logger.Warn("Invalid IP or CIDR range in blacklist file, skipping",
					zap.String("file", ipBlacklistPath),
					zap.Int("line", i+1),
					zap.String("entry", line),
				)
			}
			m.logger.Info("IP blacklist loaded successfully",
				zap.String("file", ipBlacklistPath),
				zap.Int("valid_entries", validEntries),
				zap.Int("total_lines", len(lines)),
			)
		}
	}
	// Load DNS Blacklist
	m.dnsBlacklist = make(map[string]bool) // Initialize DNS Blacklist
	if dnsBlacklistPath != "" {
		content, err := os.ReadFile(dnsBlacklistPath)
		if err != nil {
			m.logger.Warn("Failed to read DNS blacklist file", zap.String("file", dnsBlacklistPath), zap.Error(err))
		} else {
			lines := strings.Split(string(content), "\n")
			validEntriesCount := 0
			for _, line := range lines {
				line = strings.ToLower(strings.TrimSpace(line))
				if line == "" || strings.HasPrefix(line, "#") {
					continue // Skip empty lines and comments
				}
				m.dnsBlacklist[line] = true
				validEntriesCount++
			}
			m.logger.Info("DNS blacklist loaded successfully",
				zap.String("file", dnsBlacklistPath),
				zap.Int("valid_entries", validEntriesCount),
				zap.Int("total_lines", len(lines)),
			)
		}
	}

	if len(invalidFiles) > 0 {
		m.logger.Warn("Some rule files could not be loaded", zap.Strings("invalid_files", invalidFiles))
	}
	if len(allInvalidRules) > 0 {
		m.logger.Warn("Some rules across files failed validation", zap.Strings("invalid_rules", allInvalidRules))
	}

	if totalRules == 0 && len(invalidFiles) > 0 {
		return fmt.Errorf("no valid rules were loaded from any file")
	}
	m.logger.Info("Rules and Blacklists loaded successfully", zap.Int("total_rules", totalRules))

	return nil
}

// fileExists checks if a file exists and is readable.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (m *Middleware) isIPBlacklisted(remoteAddr string) bool {
	ipStr := extractIP(remoteAddr)
	if ipStr == "" {
		return false
	}

	// Check if the IP is directly blacklisted
	if m.ipBlacklist[ipStr] {
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

	m.logger.Debug("Host is not blacklisted",
		zap.String("host", host),
	)
	return false
}

func (m *Middleware) extractValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	target = strings.ToUpper(strings.TrimSpace(target))
	var unredactedValue string

	switch {
	// Query Parameters
	case target == "ARGS":
		if r.URL.RawQuery == "" {
			m.logger.Debug("Query string is empty", zap.String("target", target))
			return "", fmt.Errorf("query string is empty for target: %s", target)
		}
		unredactedValue = r.URL.RawQuery

	// Request Body
	case target == "BODY":
		if r.Body == nil {
			m.logger.Warn("Request body is nil", zap.String("target", target))
			return "", fmt.Errorf("request body is nil for target: %s", target)
		}
		if r.ContentLength == 0 {
			m.logger.Debug("Request body is empty", zap.String("target", target))
			return "", fmt.Errorf("request body is empty for target: %s", target)
		}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			m.logger.Error("Failed to read request body", zap.Error(err))
			return "", fmt.Errorf("failed to read request body for target %s: %w", target, err)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for next read
		unredactedValue = string(bodyBytes)

	// Full Header Dump (Request)
	case target == "HEADERS", target == "REQUEST_HEADERS":
		if len(r.Header) == 0 {
			m.logger.Debug("Request headers are empty", zap.String("target", target))
			return "", fmt.Errorf("request headers are empty for target: %s", target)
		}
		headers := make([]string, 0)
		for name, values := range r.Header {
			headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
		}
		unredactedValue = strings.Join(headers, "; ")

	// Response Headers (Phase 3)
	case target == "RESPONSE_HEADERS":
		if w == nil {
			return "", fmt.Errorf("response headers not accessible outside Phase 3 for target: %s", target)
		}
		headers := make([]string, 0)
		for name, values := range w.Header() {
			headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
		}
		unredactedValue = strings.Join(headers, "; ")

	// Response Body (Phase 4)
	case target == "RESPONSE_BODY":
		if w == nil {
			return "", fmt.Errorf("response body not accessible outside Phase 4 for target: %s", target)
		}
		if recorder, ok := w.(*responseRecorder); ok {
			if recorder.body.Len() == 0 {
				m.logger.Debug("Response body is empty", zap.String("target", target))
				return "", fmt.Errorf("response body is empty for target: %s", target)
			}
			unredactedValue = recorder.BodyString()

		} else {
			return "", fmt.Errorf("response recorder not available for target: %s", target)
		}

	// Dynamic Header Extraction (Request)
	case strings.HasPrefix(target, "HEADERS:"):
		headerName := strings.TrimPrefix(target, "HEADERS:")
		headerValue := r.Header.Get(headerName)
		if headerValue == "" {
			m.logger.Debug("Header not found", zap.String("header", headerName))
			return "", fmt.Errorf("header '%s' not found for target: %s", headerName, target)
		}
		unredactedValue = headerValue

	// Dynamic Response Header Extraction (Phase 3)
	case strings.HasPrefix(target, "RESPONSE_HEADERS:"):
		if w == nil {
			return "", fmt.Errorf("response headers not available during this phase for target: %s", target)
		}
		headerName := strings.TrimPrefix(target, "RESPONSE_HEADERS:")
		headerValue := w.Header().Get(headerName)
		if headerValue == "" {
			m.logger.Debug("Response header not found", zap.String("header", headerName))
			return "", fmt.Errorf("response header '%s' not found for target: %s", headerName, target)
		}
		unredactedValue = headerValue

	// Cookies Extraction
	case target == "COOKIES":
		cookies := make([]string, 0)
		for _, c := range r.Cookies() {
			cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		if len(cookies) == 0 {
			m.logger.Debug("No cookies found", zap.String("target", target))
			return "", fmt.Errorf("no cookies found for target: %s", target)
		}
		unredactedValue = strings.Join(cookies, "; ")

	case strings.HasPrefix(target, "COOKIES:"):
		cookieName := strings.TrimPrefix(target, "COOKIES:")
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			m.logger.Debug("Cookie not found", zap.String("cookie", cookieName))
			return "", fmt.Errorf("cookie '%s' not found for target: %s", cookieName, target)
		}
		unredactedValue = cookie.Value

	// User Agent
	case target == "USER_AGENT":
		userAgent := r.UserAgent()
		if userAgent == "" {
			m.logger.Debug("User-Agent is empty", zap.String("target", target))
		}
		unredactedValue = userAgent

	// Path
	case target == "PATH":
		path := r.URL.Path
		if path == "" {
			m.logger.Debug("Request path is empty", zap.String("target", target))
		}
		unredactedValue = path
	// URI (full request URI)
	case target == "URI":
		uri := r.URL.RequestURI()
		if uri == "" {
			m.logger.Debug("Request URI is empty", zap.String("target", target))
		}
		unredactedValue = uri
	// Catch-all for Unrecognized Targets
	default:
		m.logger.Warn("Unknown extraction target", zap.String("target", target))
		return "", fmt.Errorf("unknown extraction target: %s", target)
	}

	// Redact sensitive fields
	value := unredactedValue
	if m.RedactSensitiveData {
		sensitiveTargets := []string{"password", "token", "apikey", "authorization", "secret"}
		for _, sensitive := range sensitiveTargets {
			if strings.Contains(strings.ToLower(target), sensitive) {
				value = "REDACTED"
				break
			}
		}
	}

	m.logger.Debug("Extracted value",
		zap.String("rule_id", r.Context().Value("rule_id").(string)),
		zap.String("target", target),
		zap.String("value", value), // Now logging the potentially redacted value
	)

	return unredactedValue, nil // Return the unredacted value for rule matching

}

// validateRule checks if a rule is valid
func validateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule has an empty ID")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("rule '%s' has an empty pattern", rule.ID)
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("rule '%s' has no targets", rule.ID)
	}
	if rule.Phase < 1 || rule.Phase > 4 {
		return fmt.Errorf("rule '%s' has an invalid phase: %d. Valid phases are 1 to 4", rule.ID, rule.Phase)
	}
	if rule.Score < 0 {
		return fmt.Errorf("rule '%s' has a negative score", rule.ID)
	}
	if rule.Action != "" && rule.Action != "block" && rule.Action != "log" {
		return fmt.Errorf("rule '%s' has an invalid action: '%s'. Valid actions are 'block' or 'log'", rule.ID, rule.Action)
	}
	return nil
}

func (m *Middleware) loadIPBlacklistFromFile(path string) error {
	// Acquire a write lock to protect shared state
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize the IP blacklist
	m.ipBlacklist = make(map[string]bool)

	// Log the attempt to load the IP blacklist file
	m.logger.Debug("Loading IP blacklist from file",
		zap.String("file", path),
	)

	// Attempt to read the file
	content, err := os.ReadFile(path)
	if err != nil {
		m.logger.Warn("Failed to read IP blacklist file",
			zap.String("file", path),
			zap.Error(err),
		)
		return nil // Continue with an empty blacklist
	}

	// Split the file content into lines
	lines := strings.Split(string(content), "\n")
	validEntries := 0

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Check if the line is a valid IP or CIDR range
		if _, _, err := net.ParseCIDR(line); err == nil {
			// It's a valid CIDR range
			m.ipBlacklist[line] = true
			validEntries++
			m.logger.Debug("Added CIDR range to blacklist",
				zap.String("cidr", line),
			)
			continue
		}

		if ip := net.ParseIP(line); ip != nil {
			// It's a valid IP address
			m.ipBlacklist[line] = true
			validEntries++
			m.logger.Debug("Added IP to blacklist",
				zap.String("ip", line),
			)
			continue
		}

		// Log invalid entries for debugging
		m.logger.Warn("Invalid IP or CIDR range in blacklist file, skipping",
			zap.String("file", path),
			zap.Int("line", i+1),
			zap.String("entry", line),
		)
	}

	m.logger.Info("IP blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", validEntries),
		zap.Int("total_lines", len(lines)),
	)
	return nil
}

func (m *Middleware) loadDNSBlacklistFromFile(path string) error {
	// Acquire a write lock to protect shared state
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize an empty DNS blacklist map
	m.dnsBlacklist = make(map[string]bool)

	// Log the attempt to load the DNS blacklist file
	m.logger.Debug("Loading DNS blacklist from file",
		zap.String("file", path),
	)

	// Attempt to read the file
	content, err := os.ReadFile(path)
	if err != nil {
		m.logger.Warn("Failed to read DNS blacklist file",
			zap.String("file", path),
			zap.Error(err),
		)
		return nil // Continue with an empty blacklist
	}

	// Convert all entries to lowercase and trim whitespace and add to the map
	lines := strings.Split(string(content), "\n")
	validEntriesCount := 0

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		m.dnsBlacklist[line] = true
		validEntriesCount++
	}

	// Log the successful loading of the DNS blacklist
	m.logger.Info("DNS blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("valid_entries", validEntriesCount),
		zap.Int("total_lines", len(lines)),
	)

	return nil
}

func (m *Middleware) ReloadConfig() error {
	// Acquire a write lock to protect shared state during reload
	m.mu.Lock()
	defer m.mu.Unlock()

	// Log the start of the reload process
	m.logger.Info("Reloading WAF configuration")

	// Create a temporary map to hold the new rules
	newRules := make(map[int][]Rule)

	// Reload rules into the temporary map
	if err := m.loadRulesIntoMap(newRules); err != nil {
		m.logger.Error("Failed to reload rules",
			zap.Error(err),
		)
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	// Reload IP blacklist into a temporary map
	newIPBlacklist := make(map[string]bool)
	if m.IPBlacklistFile != "" {
		if err := m.loadIPBlacklistIntoMap(m.IPBlacklistFile, newIPBlacklist); err != nil {
			m.logger.Error("Failed to reload IP blacklist",
				zap.String("file", m.IPBlacklistFile),
				zap.Error(err),
			)
			return fmt.Errorf("failed to reload IP blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No IP blacklist file specified, skipping reload")
	}

	// Reload DNS blacklist into a temporary map
	newDNSBlacklist := make(map[string]bool)
	if m.DNSBlacklistFile != "" {
		if err := m.loadDNSBlacklistIntoMap(m.DNSBlacklistFile, newDNSBlacklist); err != nil {
			m.logger.Error("Failed to reload DNS blacklist",
				zap.String("file", m.DNSBlacklistFile),
				zap.Error(err),
			)
			return fmt.Errorf("failed to reload DNS blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No DNS blacklist file specified, skipping reload")
	}

	// Swap the old configuration with the new one atomically
	m.Rules = newRules
	m.ipBlacklist = newIPBlacklist
	m.dnsBlacklist = newDNSBlacklist

	// Log the successful completion of the reload process
	m.logger.Info("WAF configuration reloaded successfully")

	return nil
}

// loadRulesIntoMap loads rules into a provided map instead of directly updating the middleware's rule set
func (m *Middleware) loadRulesIntoMap(rulesMap map[int][]Rule) error {
	for _, file := range m.RuleFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			m.logger.Error("Failed to read rule file",
				zap.String("file", file),
				zap.Error(err),
			)
			return fmt.Errorf("failed to read rule file: %s, error: %v", file, err)
		}

		var rules []Rule
		if err := json.Unmarshal(content, &rules); err != nil {
			m.logger.Error("Failed to unmarshal rules from file",
				zap.String("file", file),
				zap.Error(err),
			)
			return fmt.Errorf("failed to unmarshal rules from file: %s, error: %v. Ensure valid JSON.", file, err)
		}

		for _, rule := range rules {
			if _, ok := rulesMap[rule.Phase]; !ok {
				rulesMap[rule.Phase] = []Rule{}
			}
			rulesMap[rule.Phase] = append(rulesMap[rule.Phase], rule)
		}
	}
	return nil
}

// loadIPBlacklistIntoMap loads IP blacklist entries into a provided map
func (m *Middleware) loadIPBlacklistIntoMap(path string, blacklistMap map[string]bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read IP blacklist file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blacklistMap[line] = true
	}
	return nil
}

// loadDNSBlacklistIntoMap loads DNS blacklist entries into a provided map
func (m *Middleware) loadDNSBlacklistIntoMap(path string, blacklistMap map[string]bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read DNS blacklist file: %v", err)
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
