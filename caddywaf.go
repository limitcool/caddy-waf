package caddywaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
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
	rl.Lock()
	defer rl.Unlock()

	now := time.Now()

	// Check if the IP already exists in the map
	if counter, exists := rl.requests[ip]; exists {
		// If the window has expired, reset the counter
		if now.Sub(counter.window) > rl.config.Window {
			counter.count = 1
			counter.window = now
			return false
		}

		// Increment the counter and check if it exceeds the limit
		counter.count++
		return counter.count > rl.config.Requests
	}

	// If the IP is not in the map, add it with a count of 1
	rl.requests[ip] = &requestCounter{
		count:  1,
		window: now,
	}

	return false
}

// cleanupExpiredEntries removes expired entries from the rate limiter.
func (rl *RateLimiter) cleanupExpiredEntries() {
	rl.Lock()
	defer rl.Unlock()

	now := time.Now()

	for ip, counter := range rl.requests {
		if now.Sub(counter.window) > rl.config.Window {
			delete(rl.requests, ip)
		}
	}
}

// startCleanup starts the goroutine to periodically clean up expired entries.
func (rl *RateLimiter) startCleanup() {
	rl.stopCleanup = make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Minute) // Adjust cleanup interval as needed
		defer ticker.Stop()
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
		close(rl.stopCleanup)
		rl.stopCleanup = nil
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
	Action      string   `json:"action"`   // Deprecated (remove if unused)
	Score       int      `json:"score"`
	Mode        string   `json:"mode"` // Determines the action (block/log)
	Description string   `json:"description"`
	regex       *regexp.Regexp
}

type Middleware struct {
	RuleFiles        []string            `json:"rule_files"`
	IPBlacklistFile  string              `json:"ip_blacklist_file"`
	DNSBlacklistFile string              `json:"dns_blacklist_file"`
	AnomalyThreshold int                 `json:"anomaly_threshold"`
	RateLimit        RateLimit           `json:"rate_limit"`
	CountryBlock     CountryAccessFilter `json:"country_block"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	Rules            map[int][]Rule      `json:"-"`
	ipBlacklist      map[string]bool     `json:"-"` // Changed type here
	dnsBlacklist     []string            `json:"-"`
	rateLimiter      *RateLimiter        `json:"-"`
	logger           *zap.Logger
	LogSeverity      string `json:"log_severity,omitempty"`
	LogJSON          bool   `json:"log_json,omitempty"`
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
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Initialize a temporary logger if it's nil
	if m.logger == nil {
		m.logger = zap.NewNop() // Use a no-op logger if no logger is available
	}

	m.logger.Debug("WAF UnmarshalCaddyfile Called")
	m.LogSeverity = "info" // Default log level if not specified
	m.LogJSON = false      // Default log json to false if not specified

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "rate_limit":
				if !d.NextArg() {
					return d.ArgErr()
				}
				requests, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid rate limit request count: %v", err)
				}
				if !d.NextArg() {
					return d.ArgErr()
				}
				window, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid rate limit window: %v", err)
				}
				m.RateLimit = RateLimit{
					Requests: requests,
					Window:   window,
				}
			case "block_countries":
				m.CountryBlock.Enabled = true
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CountryBlock.GeoIPDBPath = d.Val()
				for d.NextArg() {
					m.CountryBlock.CountryList = append(m.CountryBlock.CountryList, strings.ToUpper(d.Val()))
				}
			case "whitelist_countries":
				m.CountryWhitelist.Enabled = true
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CountryWhitelist.GeoIPDBPath = d.Val()
				for d.NextArg() {
					m.CountryWhitelist.CountryList = append(m.CountryWhitelist.CountryList, strings.ToUpper(d.Val()))
				}
			case "log_severity":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.LogSeverity = d.Val()
			case "log_json":
				m.LogJSON = true
			case "rule_file":
				m.logger.Info("WAF Loading Rule File", zap.String("file", d.Val()))
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RuleFiles = append(m.RuleFiles, d.Val())
			case "ip_blacklist_file":
				m.logger.Info("WAF Loading IP Blacklist File", zap.String("file", d.Val()))
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.IPBlacklistFile = d.Val()
			case "dns_blacklist_file":
				m.logger.Info("WAF Loading DNS Blacklist File", zap.String("file", d.Val()))
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.DNSBlacklistFile = d.Val()
			case "anomaly_threshold":
				if !d.NextArg() {
					return d.ArgErr()
				}
				threshold, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid anomaly threshold: %v", err)
				}
				m.AnomalyThreshold = threshold
			default:
				m.logger.Warn("WAF Unrecognized SubDirective", zap.String("directive", d.Val()))
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if geoIP == nil {
		return false, fmt.Errorf("GeoIP database not loaded")
	}

	ip := remoteAddr
	if strings.Contains(remoteAddr, ":") {
		var err error
		ip, _, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			ip = remoteAddr
		}
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	var record GeoIPRecord
	err := geoIP.Lookup(parsedIP, &record)
	if err != nil {
		return false, err
	}

	for _, country := range countryList {
		if strings.EqualFold(record.Country.ISOCode, country) {
			return true, nil
		}
	}

	return false, nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	state := &WAFState{
		TotalScore:      0,
		Blocked:         false,
		StatusCode:      http.StatusOK,
		ResponseWritten: false,
	}

	// Handle Phase 1
	if !state.ResponseWritten {
		m.handlePhase(w, r, 1, state)
	}

	// If the request is blocked after Phase 1, return early
	if state.Blocked {
		m.logRequest(zapcore.InfoLevel, "Request blocked in Phase 1",
			zap.Int("status_code", state.StatusCode),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
		)
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true
		return nil
	}

	// Handle Phase 2
	if !state.Blocked && !state.ResponseWritten {
		m.handlePhase(w, r, 2, state)
	}

	// If the request is blocked after Phase 2, return early
	if state.Blocked {
		m.logRequest(zapcore.InfoLevel, "Request blocked in Phase 2",
			zap.Int("status_code", state.StatusCode),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
		)
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true
		return nil
	}

	// Proceed to the next handler only if the request is not blocked
	return next.ServeHTTP(w, r)
}

func (m *Middleware) blockRequest(w http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, reason string, fields ...zap.Field) {
	state.Blocked = true
	state.StatusCode = statusCode
	state.ResponseWritten = true

	m.logRequest(zapcore.InfoLevel, reason,
		append(fields,
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
			zap.Int("status_code", statusCode),
		)...,
	)

	w.WriteHeader(statusCode)
}

// extractIP extracts the IP address from a remote address string.
// It handles cases where the remote address includes a port (e.g., "192.168.1.1:12345" or "[2001:db8::1]:8080").
func extractIP(remoteAddr string) string {
	// Try to split the address into host and port
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		// If successful, return the host part (IP address)
		return host
	}

	// If SplitHostPort fails, assume the remoteAddr is just an IP address
	// Try to parse it as a standalone IP address
	ip := net.ParseIP(remoteAddr)
	if ip != nil {
		// If parsing succeeds, return the IP address as a string
		return ip.String()
	}

	// If all else fails, return the original remoteAddr
	return remoteAddr
}

func (m *Middleware) handlePhase(w http.ResponseWriter, r *http.Request, phase int, state *WAFState) {
	m.logger.Debug("Starting phase evaluation",
		zap.Int("phase", phase),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	// Check country blocking
	if phase == 1 && m.CountryBlock.Enabled {
		blocked, err := m.isCountryInList(r.RemoteAddr, m.CountryBlock.CountryList, m.CountryBlock.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check country block",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
			m.blockRequest(w, r, state, http.StatusForbidden, "Request blocked due to internal error",
				zap.String("reason", "internal_error"),
			)
			return
		} else if blocked {
			m.blockRequest(w, r, state, http.StatusForbidden, "Request blocked by country",
				zap.String("reason", "country_block"),
			)
			return
		}
	}

	// Check country whitelisting
	if phase == 1 && m.CountryWhitelist.Enabled {
		whitelisted, err := m.isCountryInList(r.RemoteAddr, m.CountryWhitelist.CountryList, m.CountryWhitelist.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check country whitelist",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
			m.blockRequest(w, r, state, http.StatusForbidden, "Request blocked due to internal error",
				zap.String("reason", "internal_error"),
			)
			return
		} else if !whitelisted {
			m.blockRequest(w, r, state, http.StatusForbidden, "Request blocked by country whitelist",
				zap.String("reason", "country_whitelist"),
			)
			return
		}
	}

	// Check rate limiting
	if phase == 1 && m.rateLimiter != nil {
		ip := extractIP(r.RemoteAddr)
		if m.rateLimiter.isRateLimited(ip) {
			m.blockRequest(w, r, state, http.StatusTooManyRequests, "Request blocked by rate limit",
				zap.String("reason", "rate_limit"),
			)
			return
		}
	}

	// Check IP blacklist
	if phase == 1 && m.isIPBlacklisted(r.RemoteAddr) {
		m.blockRequest(w, r, state, http.StatusForbidden, "Request blocked by IP blacklist",
			zap.String("reason", "ip_blacklist"),
		)
		return
	}

	// Check DNS blacklist
	if phase == 1 && m.isDNSBlacklisted(r.Host) {
		m.blockRequest(w, r, state, http.StatusForbidden, "Request blocked by DNS blacklist",
			zap.String("reason", "dns_blacklist"),
		)
		return
	}

	// Check if there are rules for the current phase
	rules, ok := m.Rules[phase]
	if !ok {
		m.logger.Debug("No rules found for phase",
			zap.Int("phase", phase),
		)
		return
	}

	// Evaluate rules for the current phase
	for _, rule := range rules {
		for _, target := range rule.Targets {
			value, err := m.extractValue(target, r)
			if err != nil {
				m.logger.Debug("Failed to extract value for target",
					zap.String("target", target),
					zap.Error(err),
				)
				continue
			}

			m.logger.Debug("Checking rule",
				zap.String("rule_id", rule.ID),
				zap.String("target", target),
				zap.String("value", value),
			)

			if rule.regex.MatchString(value) {
				m.processRuleMatch(w, r, &rule, value, state)
				if state.Blocked || state.ResponseWritten {
					return // Exit early if the request is blocked
				}
			}
		}
	}

	m.logger.Debug("Completed phase evaluation",
		zap.Int("phase", phase),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)
}

func (m *Middleware) processRuleMatch(w http.ResponseWriter, r *http.Request, rule *Rule, value string, state *WAFState) {
	// If rule.Mode is empty, default to "block"
	if rule.Mode == "" {
		rule.Mode = "block"
	}

	// Add the rule's score to the total score for all rules
	state.TotalScore += rule.Score

	// Prepare detailed request information for logging
	requestInfo := []zap.Field{
		zap.String("rule_id", rule.ID),
		zap.String("target", strings.Join(rule.Targets, ",")),
		zap.String("value", value),
		zap.String("description", rule.Description),
		zap.Int("score", rule.Score),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
		zap.String("mode", rule.Mode),
		zap.String("severity", rule.Severity), // Log the severity level
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
		zap.String("request_method", r.Method),
		zap.String("request_path", r.URL.Path),
		zap.String("query_params", r.URL.RawQuery),
		zap.Any("headers", r.Header),
		zap.Time("timestamp", time.Now()),
	}

	// Log the rule match with detailed request information
	m.logRequest(zapcore.InfoLevel, "Rule matched", requestInfo...)

	// Check if the total score exceeds the anomaly threshold
	if state.TotalScore >= m.AnomalyThreshold {
		m.logRequest(zapcore.WarnLevel, "Request blocked by Anomaly Threshold",
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
			zap.Int("status_code", http.StatusForbidden),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
		)
		state.Blocked = true
		state.StatusCode = http.StatusForbidden
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true
		return
	}

	// Handle the rule action based on the mode
	switch rule.Mode {
	case "block":
		m.logRequest(zapcore.WarnLevel, "Request blocked by rule", requestInfo...)
		state.Blocked = true
		state.StatusCode = http.StatusForbidden
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true
		return

	case "log":
		// No further action needed; logging is already done above
		return

	default:
		// Handle unknown actions by blocking the request (security-first approach)
		m.logRequest(zapcore.WarnLevel, "Unknown rule action - Blocking request", zap.String("action", rule.Mode))
		state.Blocked = true
		state.StatusCode = http.StatusForbidden
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true
		return
	}
}

func (m *Middleware) logRequest(level zapcore.Level, msg string, fields ...zap.Field) {
	if m.logger == nil {
		return
	}
	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}
	logLevel := zapcore.InfoLevel
	switch strings.ToLower(m.LogSeverity) {
	case "debug":
		logLevel = zapcore.DebugLevel
	case "info":
		logLevel = zapcore.InfoLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	}

	if level < logLevel {
		return
	}
	if m.LogJSON {
		fields = append(fields, zap.String("message", msg))
		switch level {
		case zapcore.DebugLevel:
			m.logger.Debug("", fields...)
		case zapcore.InfoLevel:
			m.logger.Info("", fields...)
		case zapcore.WarnLevel:
			m.logger.Warn("", fields...)
		case zapcore.ErrorLevel:
			m.logger.Error("", fields...)
		default:
			m.logger.Info("", fields...)
		}
	} else {
		switch level {
		case zapcore.DebugLevel:
			m.logger.Debug(msg, fields...)
		case zapcore.InfoLevel:
			m.logger.Info(msg, fields...)
		case zapcore.WarnLevel:
			m.logger.Warn(msg, fields...)
		case zapcore.ErrorLevel:
			m.logger.Error(msg, fields...)
		default:
			m.logger.Info(msg, fields...)
		}
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	// Initialize the logger
	m.logger = ctx.Logger(m)
	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}

	// Log that the middleware is being provisioned
	m.logger.Info("Provisioning WAF middleware",
		zap.String("log_level", m.LogSeverity),
		zap.Bool("log_json", m.LogJSON),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	// Initialize rate limiter if configured
	if m.RateLimit.Requests > 0 {
		m.logger.Debug("Initializing rate limiter",
			zap.Int("requests", m.RateLimit.Requests),
			zap.Duration("window", m.RateLimit.Window),
		)
		m.rateLimiter = &RateLimiter{
			requests: make(map[string]*requestCounter),
			config:   m.RateLimit,
		}
		m.rateLimiter.startCleanup() // Start the cleanup goroutine
	}

	// Load GeoIP database if either country blocking or whitelisting is enabled
	if m.CountryBlock.Enabled || m.CountryWhitelist.Enabled {
		// Determine the GeoIP database path
		geoIPPath := m.CountryBlock.GeoIPDBPath
		if m.CountryWhitelist.Enabled {
			geoIPPath = m.CountryWhitelist.GeoIPDBPath
		}

		// Validate the GeoIP database path
		if !fileExists(geoIPPath) {
			return fmt.Errorf("GeoIP database does not exist or is not readable: %s", geoIPPath)
		}

		// Load the GeoIP database
		m.logger.Debug("Loading GeoIP database",
			zap.String("path", geoIPPath),
		)
		reader, err := maxminddb.Open(geoIPPath)
		if err != nil {
			return fmt.Errorf("failed to load GeoIP database: %v", err)
		}

		// Share the GeoIP database between CountryBlock and CountryWhitelist
		if m.CountryBlock.Enabled {
			m.CountryBlock.geoIP = reader
		}
		if m.CountryWhitelist.Enabled {
			m.CountryWhitelist.geoIP = reader
		}

		m.logger.Info("GeoIP database loaded successfully",
			zap.String("path", geoIPPath),
		)
	}

	// Load rules from rule files
	m.Rules = make(map[int][]Rule)
	for _, file := range m.RuleFiles {
		m.logger.Debug("Loading rules from file",
			zap.String("file", file),
		)
		if err := m.loadRulesFromFile(file); err != nil {
			return fmt.Errorf("failed to load rules from %s: %v", file, err)
		}
	}

	// Validate and log each rule
	m.logger.Info("Validating loaded rules")
	var invalidRules []string
	totalRules := 0 // Track the total number of rules

	for phase, rules := range m.Rules {
		for _, rule := range rules {
			m.logger.Debug("Validating rule",
				zap.String("rule_id", rule.ID),
				zap.Int("phase", phase),
				zap.String("pattern", rule.Pattern),
				zap.Strings("targets", rule.Targets),
				zap.String("severity", rule.Severity),
				zap.String("action", rule.Action),
				zap.Int("score", rule.Score),
				zap.String("description", rule.Description),
				zap.String("mode", rule.Mode),
			)

			// Validate the rule
			if rule.ID == "" {
				invalidRules = append(invalidRules, fmt.Sprintf("Rule with empty ID: %v", rule))
				continue
			}
			if rule.Pattern == "" {
				invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s' has an empty pattern", rule.ID))
				continue
			}
			if len(rule.Targets) == 0 {
				invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s' has no targets", rule.ID))
				continue
			}
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s' has an invalid regex pattern: %v", rule.ID, err))
				continue
			}
			if rule.Score < 0 {
				invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s' has a negative score", rule.ID))
				continue
			}
			if rule.Mode == "" {
				rule.Mode = "log" // Default to log if mode is empty
			}

			totalRules++ // Increment the total rule count
		}
	}

	// Log invalid rules
	if len(invalidRules) > 0 {
		m.logger.Warn("Some rules failed validation",
			zap.Strings("invalid_rules", invalidRules),
		)
	} else {
		m.logger.Info("All rules validated successfully")
	}

	// Log the total number of rules loaded
	m.logger.Info("Total rules loaded",
		zap.Int("total_rules", totalRules),
	)

	// Set default anomaly threshold if not configured
	if m.AnomalyThreshold == 0 {
		m.AnomalyThreshold = 5
		m.logger.Debug("Setting default anomaly threshold",
			zap.Int("threshold", m.AnomalyThreshold),
		)
	}

	// Load IP blacklist from file
	if m.IPBlacklistFile != "" {
		m.logger.Debug("Loading IP blacklist from file",
			zap.String("file", m.IPBlacklistFile),
		)
		if err := m.loadIPBlacklistFromFile(m.IPBlacklistFile); err != nil {
			return fmt.Errorf("failed to load IP blacklist from %s: %v", m.IPBlacklistFile, err)
		}
	} else {
		m.ipBlacklist = make(map[string]bool)
		m.logger.Debug("No IP blacklist file specified, initializing empty blacklist")
	}

	// Load DNS blacklist from file
	if m.DNSBlacklistFile != "" {
		m.logger.Debug("Loading DNS blacklist from file",
			zap.String("file", m.DNSBlacklistFile),
		)
		if err := m.loadDNSBlacklistFromFile(m.DNSBlacklistFile); err != nil {
			return fmt.Errorf("failed to load DNS blacklist from %s: %v", m.DNSBlacklistFile, err)
		}
	} else {
		m.dnsBlacklist = []string{}
		m.logger.Debug("No DNS blacklist file specified, initializing empty blacklist")
	}

	m.logger.Info("WAF middleware provisioned successfully")
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
	if len(m.ipBlacklist) == 0 {
		return false
	}

	// Extract the IP from the remote address
	ipStr := extractIP(remoteAddr)
	if ipStr == "" {
		return false
	}

	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check if the IP is directly blacklisted
	if m.ipBlacklist[ipStr] {
		m.logger.Debug("IP is directly blacklisted",
			zap.String("ip", ipStr),
		)
		return true
	}

	// Check if the IP falls within any CIDR range in the blacklist
	for blacklistEntry := range m.ipBlacklist {
		// Try to parse the blacklist entry as a CIDR range
		_, ipNet, err := net.ParseCIDR(blacklistEntry)
		if err != nil {
			// If it's not a CIDR range, skip
			continue
		}

		// Check if the IP falls within the CIDR range
		if ipNet.Contains(ip) {
			m.logger.Debug("IP falls within a blacklisted CIDR range",
				zap.String("ip", ipStr),
				zap.String("cidr", blacklistEntry),
			)
			return true
		}
	}

	return false
}

func (m *Middleware) isDNSBlacklisted(host string) bool {
	if m.dnsBlacklist == nil || len(m.dnsBlacklist) == 0 {
		return false
	}

	// Normalize the host to lowercase and trim whitespace
	host = strings.ToLower(strings.TrimSpace(host))

	// Check if the host is in the blacklist
	for _, blacklistedDomain := range m.dnsBlacklist {
		if host == blacklistedDomain {
			return true
		}
	}

	return false
}

func (m *Middleware) extractValue(target string, r *http.Request) (string, error) {
	switch {
	case target == "ARGS":
		return r.URL.RawQuery, nil
	case target == "BODY":
		if r.Body == nil || r.ContentLength == 0 {
			return "", nil
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read request body: %v", err)
		}
		// Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		return string(bodyBytes), nil

	case target == "HEADERS":
		return fmt.Sprintf("%v", r.Header), nil
	case target == "URL":
		return r.URL.Path, nil
	case target == "USER_AGENT":
		return r.UserAgent(), nil
	case target == "COOKIES":
		return fmt.Sprintf("%v", r.Cookies()), nil
	case target == "PATH":
		return r.URL.Path, nil
	case target == "URI":
		return r.RequestURI, nil
	case strings.HasPrefix(target, "HEADERS:"):
		headerName := strings.TrimPrefix(target, "HEADERS:")
		return r.Header.Get(headerName), nil
	case strings.HasPrefix(target, "ARGS:"):
		argName := strings.TrimPrefix(target, "ARGS:")
		return r.URL.Query().Get(argName), nil
	case strings.HasPrefix(target, "COOKIES:"):
		cookieName := strings.TrimPrefix(target, "COOKIES:")
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return "", nil
		}
		return cookie.Value, nil
	case strings.HasPrefix(target, "FORM:"):
		fieldName := strings.TrimPrefix(target, "FORM:")
		if err := r.ParseForm(); err != nil {
			return "", err
		}
		return r.Form.Get(fieldName), nil
	case strings.HasPrefix(target, "JSON:"):
		fieldName := strings.TrimPrefix(target, "JSON:")
		if r.Body == nil || r.ContentLength == 0 {
			return "", nil
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read request body: %v", err)
		}
		// Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		var jsonData map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
			return "", fmt.Errorf("failed to unmarshal JSON: %v", err)
		}
		if value, ok := jsonData[fieldName]; ok {
			return fmt.Sprintf("%v", value), nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("unknown target: %s", target)
	}
}

func (m *Middleware) loadRulesFromFile(path string) error {
	// Read the rule file
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %s: %v", path, err)
	}

	// Unmarshal the JSON content into a slice of Rule structs
	var rules []Rule
	if err := json.Unmarshal(content, &rules); err != nil {
		return fmt.Errorf("failed to unmarshal rules from %s: %v", path, err)
	}

	var invalidRules []string        // Track invalid rules for logging
	ruleIDs := make(map[string]bool) // Track rule IDs to detect duplicates

	// Iterate through each rule in the file
	for i, rule := range rules {
		// Validate the rule ID
		if rule.ID == "" {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule %d: empty ID", i+1))
			continue
		}

		// Check for duplicate rule IDs
		if _, exists := ruleIDs[rule.ID]; exists {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule %d: duplicate ID '%s'", i+1, rule.ID))
			continue
		}
		ruleIDs[rule.ID] = true

		// Validate the rule phase
		if rule.Phase < 1 || rule.Phase > 2 {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule %s: invalid phase '%d'", rule.ID, rule.Phase))
			continue
		}

		// Validate the rule mode
		if rule.Mode != "" && rule.Mode != "block" && rule.Mode != "log" {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule %s: invalid mode '%s'", rule.ID, rule.Mode))
			continue
		}

		// Validate the regex pattern
		if rule.Pattern == "" {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule %s: empty pattern", rule.ID))
			continue
		}

		// Compile the regex pattern and log detailed errors if it fails
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			// Log the exact error with context
			m.logger.Error("Failed to compile regex pattern for rule",
				zap.String("rule_id", rule.ID),
				zap.String("pattern", rule.Pattern),
				zap.Error(err), // Log the exact error from regexp.Compile
			)
			invalidRules = append(invalidRules, fmt.Sprintf("Rule %s: invalid regex pattern '%s' (error: %v)", rule.ID, rule.Pattern, err))
			continue
		}
		rules[i].regex = regex

		// Initialize the phase map if it doesn't exist
		if _, ok := m.Rules[rule.Phase]; !ok {
			m.Rules[rule.Phase] = []Rule{}
		}

		// Append the rule to the appropriate phase
		m.Rules[rule.Phase] = append(m.Rules[rule.Phase], rules[i])
	}

	// Log warnings for invalid rules
	if len(invalidRules) > 0 {
		m.logger.Warn("Skipped invalid rules in file",
			zap.String("file", path),
			zap.Strings("invalid_rules", invalidRules),
		)
	}

	return nil
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
	if rule.Phase < 1 || rule.Phase > 2 {
		return fmt.Errorf("rule '%s' has an invalid phase: %d", rule.ID, rule.Phase)
	}
	if rule.Score < 0 {
		return fmt.Errorf("rule '%s' has a negative score", rule.ID)
	}
	return nil
}

func (m *Middleware) loadIPBlacklistFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read IP blacklist file: %v", err)
	}

	// Initialize the IP blacklist
	m.ipBlacklist = make(map[string]bool)

	// Split the file content into lines
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Check if the line is a valid IP or CIDR range
		if _, _, err := net.ParseCIDR(line); err == nil {
			// It's a valid CIDR range
			m.ipBlacklist[line] = true
			m.logger.Debug("Added CIDR range to blacklist",
				zap.String("cidr", line),
			)
		} else if ip := net.ParseIP(line); ip != nil {
			// It's a valid IP address
			m.ipBlacklist[line] = true
			m.logger.Debug("Added IP to blacklist",
				zap.String("ip", line),
			)
		} else {
			// Log invalid entries for debugging
			m.logger.Warn("Invalid IP or CIDR range in blacklist",
				zap.String("entry", line),
			)
		}
	}

	m.logger.Info("IP blacklist loaded successfully",
		zap.Int("count", len(m.ipBlacklist)),
	)
	return nil
}

func (m *Middleware) loadDNSBlacklistFromFile(path string) error {
	// Log the attempt to load the DNS blacklist file
	m.logger.Debug("Loading DNS blacklist from file", zap.String("file", path))

	// Read the file content
	content, err := os.ReadFile(path)
	if err != nil {
		// Log the error and return a descriptive error message
		m.logger.Error("Failed to read DNS blacklist file",
			zap.String("file", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to read DNS blacklist file %s: %v", path, err)
	}

	// Convert all entries to lowercase and trim whitespace
	lines := strings.Split(string(content), "\n")
	validEntries := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		validEntries = append(validEntries, line)
	}

	// Update the DNS blacklist
	m.dnsBlacklist = validEntries

	// Log the successful loading of the DNS blacklist
	m.logger.Info("DNS blacklist loaded successfully",
		zap.String("file", path),
		zap.Int("entries_loaded", len(validEntries)),
	)

	return nil
}

func (m *Middleware) ReloadConfig() error {
	m.Rules = make(map[int][]Rule)
	if err := m.loadRulesFromFiles(); err != nil {
		return fmt.Errorf("failed to reload rules: %v", err)
	}
	if err := m.loadIPBlacklistFromFile(m.IPBlacklistFile); err != nil {
		return fmt.Errorf("failed to reload IP blacklist: %v", err)
	}
	if err := m.loadDNSBlacklistFromFile(m.DNSBlacklistFile); err != nil {
		return fmt.Errorf("failed to reload DNS blacklist: %v", err)
	}
	return nil
}

func (m *Middleware) loadRulesFromFiles() error {
	totalRules := 0 // Initialize a counter for total rules

	for _, file := range m.RuleFiles {
		// Load rules from the current file
		if err := m.loadRulesFromFile(file); err != nil {
			return err
		}

		// Count the number of rules loaded from the current file
		rulesInFile := 0
		for _, rules := range m.Rules {
			rulesInFile += len(rules)
		}

		// Log the number of rules loaded from the current file
		m.logger.Info("Loaded rules from file",
			zap.String("file", file),
			zap.Int("rules_loaded", rulesInFile),
		)

		// Add the rules from this file to the total count
		totalRules += rulesInFile
	}

	// Log the total number of rules loaded
	m.logger.Info("Total rules loaded",
		zap.Int("total_rules", totalRules),
	)

	return nil
}
