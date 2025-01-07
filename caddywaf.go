package caddywaf

import (
	"bytes"
	"context"
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
	"github.com/google/uuid"
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
		ticker := time.NewTicker(rl.config.CleanupInterval) // Use the specified cleanup interval
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
	Score       int      `json:"score"`
	Action      string   `json:"mode"` // Determines the action (block/log)
	Description string   `json:"description"`
	regex       *regexp.Regexp
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

func (m *Middleware) Shutdown(ctx context.Context) error {
	// Log the start of the shutdown process
	m.logger.Info("Shutting down WAF middleware")

	// Signal the rate limiter cleanup goroutine to stop
	if m.rateLimiter != nil {
		m.logger.Debug("Stopping rate limiter cleanup goroutine")
		m.rateLimiter.signalStopCleanup()
	}

	// Close the GeoIP database if it is open
	if m.CountryBlock.geoIP != nil {
		m.logger.Debug("Closing country block GeoIP database")
		if err := m.CountryBlock.geoIP.Close(); err != nil {
			m.logger.Error("Failed to close country block GeoIP database",
				zap.Error(err),
			)
			return fmt.Errorf("failed to close country block GeoIP database: %w", err)
		}
		m.CountryBlock.geoIP = nil // Ensure the reference is cleared
	}

	if m.CountryWhitelist.geoIP != nil {
		m.logger.Debug("Closing country whitelist GeoIP database")
		if err := m.CountryWhitelist.geoIP.Close(); err != nil {
			m.logger.Error("Failed to close country whitelist GeoIP database",
				zap.Error(err),
			)
			return fmt.Errorf("failed to close country whitelist GeoIP database: %w", err)
		}
		m.CountryWhitelist.geoIP = nil // Ensure the reference is cleared
	}

	// Log the successful completion of the shutdown process
	m.logger.Info("WAF middleware shutdown complete")

	return nil
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
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				requests, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("parsing rate_limit requests: invalid integer: %v", err)
				}
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				window, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("parsing rate_limit window: invalid duration: %v", err)
				}
				// Default cleanup interval to 1 minute if not specified
				cleanupInterval := time.Minute
				if d.NextArg() {
					cleanupInterval, err = time.ParseDuration(d.Val())
					if err != nil {
						return d.Errf("parsing rate_limit cleanup_interval: invalid duration: %v", err)
					}
				}
				m.RateLimit = RateLimit{
					Requests:        requests,
					Window:          window,
					CleanupInterval: cleanupInterval,
				}
			case "block_countries":
				m.CountryBlock.Enabled = true
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				m.CountryBlock.GeoIPDBPath = d.Val()
				// No error here directly, as missing country codes will just result in an empty list.
				for d.NextArg() {
					m.CountryBlock.CountryList = append(m.CountryBlock.CountryList, strings.ToUpper(d.Val()))
				}
			case "whitelist_countries":
				m.CountryWhitelist.Enabled = true
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				m.CountryWhitelist.GeoIPDBPath = d.Val()
				// No error here directly, as missing country codes will just result in an empty list.
				for d.NextArg() {
					m.CountryWhitelist.CountryList = append(m.CountryWhitelist.CountryList, strings.ToUpper(d.Val()))
				}
			case "log_severity":
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				m.LogSeverity = d.Val()
			case "log_json":
				// No arguments expected, so no direct error here.
			case "rule_file":
				m.logger.Info("WAF Loading Rule File", zap.String("file", d.Val()))
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				m.RuleFiles = append(m.RuleFiles, d.Val())
			case "ip_blacklist_file":
				m.logger.Info("WAF Loading IP Blacklist File", zap.String("file", d.Val()))
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				m.IPBlacklistFile = d.Val()
			case "dns_blacklist_file":
				m.logger.Info("WAF Loading DNS Blacklist File", zap.String("file", d.Val()))
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				m.DNSBlacklistFile = d.Val()
			case "anomaly_threshold":
				if !d.NextArg() {
					return d.ArgErr() // Remains as it points to the Caddyfile syntax error
				}
				threshold, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("parsing anomaly_threshold: invalid integer: %v", err)
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

	var record GeoIPRecord
	err = geoIP.Lookup(parsedIP, &record)
	if err != nil {
		m.logger.Error("geoip lookup failed", zap.String("ip", ip), zap.Error(err))
		return false, fmt.Errorf("geoip lookup failed: %w", err)
	}

	for _, country := range countryList {
		if strings.EqualFold(record.Country.ISOCode, country) {
			return true, nil
		}
	}

	return false, nil
}

func (m *Middleware) extractIPFromRemoteAddr(remoteAddr string) (string, error) {
	ip := remoteAddr
	if strings.Contains(remoteAddr, ":") {
		var err error
		ip, _, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			m.logger.Error("failed to split host and port", zap.String("remote_addr", remoteAddr), zap.Error(err))
			return "", fmt.Errorf("failed to split host and port: %w", err)
		}
	}
	return ip, nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// Generate a unique log ID for this request
	logID := uuid.New().String()

	// Store the log ID in the request context
	ctx := context.WithValue(r.Context(), "logID", logID)
	r = r.WithContext(ctx)

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
			zap.String("log_id", logID),
			zap.Int("status_code", state.StatusCode),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
			zap.String("reason", "phase_1_block"),
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
			zap.String("log_id", logID),
			zap.Int("status_code", state.StatusCode),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
			zap.String("reason", "phase_2_block"),
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

	// Extract the log ID from the context
	var logID string
	if ctxValue := r.Context().Value("logID"); ctxValue != nil {
		if id, ok := ctxValue.(string); ok {
			logID = id
		}
	}

	// If logID is not found in the context, generate a new one (fallback)
	if logID == "" {
		logID = uuid.New().String()
	}

	// Log the blocked request with the log ID
	m.logRequest(zapcore.WarnLevel, "Request blocked",
		append(fields,
			zap.String("log_id", logID),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
			zap.Int("status_code", statusCode),
			zap.String("reason", reason),
		)...,
	)

	w.WriteHeader(statusCode)
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
			zap.String("host", r.Host),
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
					return
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
	// If rule.Action is empty, default to "block"
	if rule.Action == "" {
		rule.Action = "block"
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
		zap.String("mode", rule.Action),
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
	switch rule.Action {
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
		m.logRequest(zapcore.WarnLevel, "Unknown rule action - Blocking request", zap.String("action", rule.Action))
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

	// Extract the log ID from the fields (if it exists)
	var logID string
	for i, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
			fields = append(fields[:i], fields[i+1:]...) // Remove the log_id field
			break
		}
	}

	// If logID is not found in the fields, generate a new one (fallback)
	if logID == "" {
		logID = uuid.New().String()
	}

	// Include the log ID in the log entry
	fields = append(fields, zap.String("log_id", logID))

	// Get common log fields and merge them
	commonFields := m.getCommonLogFields(fields)
	fields = append(fields, commonFields...)

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

	return []zap.Field{
		zap.String("log_id", logID),
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
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
			zap.Duration("cleanup_interval", m.RateLimit.CleanupInterval),
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
			m.logger.Error("GeoIP database does not exist or is not readable",
				zap.String("path", geoIPPath),
			)
			return fmt.Errorf("GeoIP database does not exist or is not readable: %s", geoIPPath)
		}

		// Load the GeoIP database
		m.logger.Debug("Loading GeoIP database",
			zap.String("path", geoIPPath),
		)
		reader, err := maxminddb.Open(geoIPPath)
		if err != nil {
			m.logger.Error("Failed to load GeoIP database",
				zap.String("path", geoIPPath),
				zap.Error(err),
			)
			return fmt.Errorf("failed to load GeoIP database: %w", err)
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
			m.logger.Error("Failed to load rules from file",
				zap.String("file", file),
				zap.Error(err),
			)
			return fmt.Errorf("failed to load rules from %s: %w", file, err)
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
				zap.String("mode", rule.Action),
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
			if rule.Action == "" {
				rule.Action = "block" // Default to block if mode is empty
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
			m.logger.Error("Failed to load IP blacklist from file",
				zap.String("file", m.IPBlacklistFile),
				zap.Error(err),
			)
			return fmt.Errorf("failed to load IP blacklist from %s: %w", m.IPBlacklistFile, err)
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
			m.logger.Error("Failed to load DNS blacklist from file",
				zap.String("file", m.DNSBlacklistFile),
				zap.Error(err),
			)
			return fmt.Errorf("failed to load DNS blacklist from %s: %w", m.DNSBlacklistFile, err)
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
	// Acquire a read lock to protect shared state
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Early return if the blacklist is empty
	if len(m.ipBlacklist) == 0 {
		m.logger.Debug("IP blacklist is empty, skipping check")
		return false
	}

	// Extract and validate the IP from the remote address
	ipStr := extractIP(remoteAddr)
	if ipStr == "" {
		m.logger.Warn("Failed to extract IP from remote address",
			zap.String("remoteAddr", remoteAddr),
		)
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		m.logger.Warn("Invalid IP address extracted",
			zap.String("ipStr", ipStr),
		)
		return false
	}

	// Check if the IP is directly blacklisted
	if m.ipBlacklist[ipStr] {
		m.logger.Info("IP is directly blacklisted",
			zap.String("ip", ipStr),
		)
		return true
	}

	// Check if the IP falls within any CIDR range in the blacklist
	for blacklistEntry := range m.ipBlacklist {
		// Skip if the entry is not a CIDR range
		if !strings.Contains(blacklistEntry, "/") {
			continue
		}

		// Parse the CIDR range
		_, ipNet, err := net.ParseCIDR(blacklistEntry)
		if err != nil {
			m.logger.Warn("Invalid CIDR range in blacklist",
				zap.String("cidr", blacklistEntry),
				zap.Error(err),
			)
			continue
		}

		// Check if the IP falls within the CIDR range
		if ipNet.Contains(ip) {
			m.logger.Info("IP falls within a blacklisted CIDR range",
				zap.String("ip", ipStr),
				zap.String("cidr", blacklistEntry),
			)
			return true
		}
	}

	m.logger.Debug("IP is not blacklisted",
		zap.String("ip", ipStr),
	)
	return false
}

func (m *Middleware) isDNSBlacklisted(host string) bool {
	// Acquire a read lock to protect shared state
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Early return if the blacklist is empty or nil
	if len(m.dnsBlacklist) == 0 {
		m.logger.Debug("DNS blacklist is empty, skipping check")
		return false
	}

	// Normalize the host to lowercase and trim whitespace
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		m.logger.Warn("Empty host provided for DNS blacklist check")
		return false
	}

	// Check if the host is an exact match to any blacklisted domain
	for _, blacklistedDomain := range m.dnsBlacklist {
		blacklistedDomain = strings.ToLower(strings.TrimSpace(blacklistedDomain)) // Normalize blacklisted domain as well
		if host == blacklistedDomain {
			m.logger.Info("Host is blacklisted",
				zap.String("host", host),
				zap.String("blacklisted_domain", blacklistedDomain),
			)
			return true
		}
	}

	m.logger.Debug("Host is not blacklisted",
		zap.String("host", host),
	)
	return false
}

func (m *Middleware) extractValue(target string, r *http.Request) (string, error) {
	target = strings.ToUpper(strings.TrimSpace(target))

	switch {
	// Query Parameters
	case target == "ARGS":
		return r.URL.RawQuery, nil

	// Request Body
	case target == "BODY":
		if r.Body == nil || r.ContentLength == 0 {
			return "", nil
		}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			m.logger.Error("Failed to read request body", zap.Error(err))
			return "", fmt.Errorf("failed to read request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for next read
		return string(bodyBytes), nil

	// Full Header Dump
	case target == "HEADERS", target == "REQUEST_HEADERS":
		headers := make([]string, 0)
		for name, values := range r.Header {
			headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
		}
		return strings.Join(headers, "; "), nil

	// Dynamic Header Extraction
	case strings.HasPrefix(target, "HEADERS:"):
		headerName := strings.TrimPrefix(target, "HEADERS:")
		return r.Header.Get(headerName), nil

	// URL or Path
	case target == "URL", target == "PATH":
		return r.URL.Path, nil

	// Full URI (Path + Query String)
	case target == "URI":
		return r.RequestURI, nil

	// User-Agent
	case target == "USER_AGENT":
		return r.UserAgent(), nil

	// Cookies
	case target == "COOKIES":
		cookies := make([]string, 0)
		for _, c := range r.Cookies() {
			cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		return strings.Join(cookies, "; "), nil

	// Specific Cookie Extraction
	case strings.HasPrefix(target, "COOKIES:"):
		cookieName := strings.TrimPrefix(target, "COOKIES:")
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			m.logger.Warn("Missing or invalid cookie", zap.String("cookie", cookieName))
			return "", fmt.Errorf("cookie not found: %s", cookieName)
		}
		return cookie.Value, nil

	// Query Parameter Extraction
	case strings.HasPrefix(target, "ARGS:"):
		argName := strings.TrimPrefix(target, "ARGS:")
		return r.URL.Query().Get(argName), nil

	// Content-Type Header
	case target == "CONTENT_TYPE":
		return r.Header.Get("Content-Type"), nil

	// TLS Information (Client Hello / Server Name)
	case target == "TLS_CLIENT_HELLO":
		if r.TLS != nil && len(r.TLS.ServerName) > 0 {
			return r.TLS.ServerName, nil
		}
		return "", nil

	// IP Address (Remote Client)
	case target == "REMOTE_ADDR":
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr, nil
		}
		return host, nil

	// Remote Port
	case target == "REMOTE_PORT":
		_, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return "", nil
		}
		return port, nil

	// Server Address
	case target == "SERVER_ADDR":
		if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			return addr.String(), nil
		}
		return "", nil

	// HTTP Method (GET, POST, etc.)
	case target == "METHOD":
		return r.Method, nil

	// HTTP Protocol (HTTP/1.1, HTTP/2)
	case target == "PROTOCOL":
		return r.Proto, nil

	// Hostname (from Host header)
	case target == "HOST":
		return r.Host, nil

	// Referer Header
	case target == "REFERER":
		return r.Referer(), nil

	// Forwarded Headers
	case target == "FORWARDED":
		return r.Header.Get("Forwarded"), nil

	// Specific Header Extraction (X-Forwarded-For, etc.)
	case target == "X_FORWARDED_FOR":
		return r.Header.Get("X-Forwarded-For"), nil

	// Scheme (http or https)
	case target == "SCHEME":
		if r.TLS != nil {
			return "https", nil
		}
		return "http", nil

	// TLS Version
	case target == "TLS_VERSION":
		if r.TLS != nil {
			return fmt.Sprintf("%x", r.TLS.Version), nil
		}
		return "", nil

	// TLS Cipher Suite
	case target == "TLS_CIPHER":
		if r.TLS != nil {
			return fmt.Sprintf("%x", r.TLS.CipherSuite), nil
		}
		return "", nil

	// Request Timestamp
	case target == "REQUEST_TIME":
		return time.Now().Format(time.RFC3339), nil

	// Accept Header
	case target == "ACCEPT":
		return r.Header.Get("Accept"), nil

	// Origin Header
	case target == "ORIGIN":
		return r.Header.Get("Origin"), nil

	// Connection Header
	case target == "CONNECTION":
		return r.Header.Get("Connection"), nil

	// Accept-Encoding Header
	case target == "ACCEPT_ENCODING":
		return r.Header.Get("Accept-Encoding"), nil

	// Accept-Language Header
	case target == "ACCEPT_LANGUAGE":
		return r.Header.Get("Accept-Language"), nil

	// Authorization Header
	case target == "AUTHORIZATION":
		return r.Header.Get("Authorization"), nil

	// Content-Length Header
	case target == "CONTENT_LENGTH":
		return r.Header.Get("Content-Length"), nil

	// Raw Query String (similar to ARGS)
	case target == "QUERY_STRING":
		return r.URL.RawQuery, nil

	default:
		m.logger.Warn("Unknown target", zap.String("target", target))
		return "", fmt.Errorf("unknown target: %s", target)
	}
}

// extractNestedJSONField extracts a nested field from a JSON object.
// Supports dot notation (e.g., "user.name") and array indexing (e.g., "items[0].id").
func extractNestedJSONField(data interface{}, fieldPath string) (interface{}, error) {
	parts := strings.Split(fieldPath, ".")
	var current interface{} = data

	for _, part := range parts {
		// Handle array indexing (e.g., "items[0]")
		if strings.Contains(part, "[") && strings.HasSuffix(part, "]") {
			indexStr := strings.TrimPrefix(strings.TrimSuffix(part, "]"), "[")
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid array index '%s': %w", indexStr, err)
			}

			// Ensure the current value is a slice
			slice, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected array at '%s', got %T", part, current)
			}

			// Check if the index is within bounds
			if index < 0 || index >= len(slice) {
				return nil, fmt.Errorf("index %d out of bounds for array at '%s'", index, part)
			}

			current = slice[index]
		} else {
			// Handle nested objects
			obj, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected object at '%s', got %T", part, current)
			}

			// Check if the field exists
			value, exists := obj[part]
			if !exists {
				return nil, fmt.Errorf("field '%s' not found", part)
			}

			current = value
		}
	}

	return current, nil
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

	// Initialize an empty DNS blacklist
	m.dnsBlacklist = []string{}

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
		zap.Int("valid_entries", len(validEntries)),
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

	// Reload rules
	if err := m.loadRulesFromFiles(); err != nil {
		m.logger.Error("Failed to reload rules",
			zap.Error(err),
		)
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	// Reload IP blacklist
	if m.IPBlacklistFile != "" {
		if err := m.loadIPBlacklistFromFile(m.IPBlacklistFile); err != nil {
			m.logger.Error("Failed to reload IP blacklist",
				zap.String("file", m.IPBlacklistFile),
				zap.Error(err),
			)
			return fmt.Errorf("failed to reload IP blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No IP blacklist file specified, skipping reload")
	}

	// Reload DNS blacklist
	if m.DNSBlacklistFile != "" {
		if err := m.loadDNSBlacklistFromFile(m.DNSBlacklistFile); err != nil {
			m.logger.Error("Failed to reload DNS blacklist",
				zap.String("file", m.DNSBlacklistFile),
				zap.Error(err),
			)
			return fmt.Errorf("failed to reload DNS blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No DNS blacklist file specified, skipping reload")
	}

	// Log the successful completion of the reload process
	m.logger.Info("WAF configuration reloaded successfully")

	return nil
}

func (m *Middleware) loadRulesFromFiles() error {
	totalRules := 0
	var invalidFiles []string

	for _, file := range m.RuleFiles {
		// Attempt to load rules from the file
		if err := m.loadRulesFromFile(file); err != nil {
			// Log a warning and skip this file
			m.logger.Warn("Failed to load rules from file",
				zap.String("file", file),
				zap.Error(err),
			)
			invalidFiles = append(invalidFiles, file)
			continue
		}

		// Count the number of rules loaded from this file
		rulesInFile := 0
		for _, rules := range m.Rules {
			rulesInFile += len(rules)
		}

		m.logger.Info("Loaded rules from file",
			zap.String("file", file),
			zap.Int("rules_loaded", rulesInFile),
		)

		totalRules += rulesInFile
	}

	// Log the total number of rules loaded
	m.logger.Info("Total rules loaded",
		zap.Int("total_rules", totalRules),
	)

	// Log a warning if any files were invalid or missing
	if len(invalidFiles) > 0 {
		m.logger.Warn("Some rule files could not be loaded",
			zap.Strings("invalid_files", invalidFiles),
		)
	}

	// If no rules were loaded at all, return an error
	if totalRules == 0 {
		return fmt.Errorf("no valid rules were loaded from any file")
	}

	return nil
}

func (m *Middleware) loadRulesFromFile(path string) error {
	// Acquire a write lock to protect shared state
	m.mu.Lock()
	defer m.mu.Unlock()

	// Log the attempt to load the rule file
	m.logger.Debug("Loading rules from file",
		zap.String("file", path),
	)

	// Read the rule file
	content, err := os.ReadFile(path)
	if err != nil {
		m.logger.Error("Failed to read rule file",
			zap.String("file", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to read rule file: %s, error: %v", path, err)
	}

	// Unmarshal the JSON content into a slice of Rule structs
	var rules []Rule
	if err := json.Unmarshal(content, &rules); err != nil {
		m.logger.Error("Failed to unmarshal rules from file",
			zap.String("file", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to unmarshal rules from file: %s, error: %v. Ensure the file contains valid JSON for a list of WAF rules", path, err)
	}

	var invalidRules []string        // Track invalid rules for logging
	ruleIDs := make(map[string]bool) // Track rule IDs to detect duplicates

	// Iterate through each rule in the file
	for i, rule := range rules {
		// Validate the rule ID
		if rule.ID == "" {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule at index %d: empty ID. Each rule must have a unique identifier.", i))
			continue
		}

		// Check for duplicate rule IDs
		if _, exists := ruleIDs[rule.ID]; exists {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule with ID '%s' at index %d: duplicate ID. Rule IDs must be unique within the rule file.", rule.ID, i))
			continue
		}
		ruleIDs[rule.ID] = true

		// Validate the rule phase
		if rule.Phase < 1 || rule.Phase > 2 {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s': invalid phase '%d'. Phase must be 1 or 2.", rule.ID, rule.Phase))
			continue
		}

		// Validate the rule mode
		if rule.Action != "" && rule.Action != "block" && rule.Action != "log" {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s': invalid mode '%s'. Mode must be 'block' or 'log', or left empty (defaults to 'block' during processing).", rule.ID, rule.Action))
			continue
		}

		// Validate the regex pattern
		if rule.Pattern == "" {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s': empty pattern. A regex pattern is required for matching.", rule.ID))
			continue
		}

		// Compile the regex pattern and log detailed errors if it fails
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			m.logger.Error("Failed to compile regex pattern for rule",
				zap.String("rule_id", rule.ID),
				zap.String("pattern", rule.Pattern),
				zap.Error(err),
			)
			invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s': invalid regex pattern '%s'. Error: %v. Ensure the pattern is a valid regular expression.", rule.ID, rule.Pattern, err))
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

	// Log the successful loading of the rule file
	m.logger.Info("Rules loaded successfully",
		zap.String("file", path),
		zap.Int("total_rules", len(rules)),
		zap.Int("invalid_rules", len(invalidRules)),
	)

	return nil
}
