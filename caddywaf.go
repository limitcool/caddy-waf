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

	// First, attempt a read to check if the IP exists and its current state
	rl.RLock()
	counter, exists := rl.requests[ip]
	rl.RUnlock()

	if exists {
		// Check if the window has expired (outside the write lock if possible)
		if now.Sub(counter.window) > rl.config.Window {
			// Window expired, reset the counter (requires write lock)
			rl.Lock()
			defer rl.Unlock()
			rl.requests[ip] = &requestCounter{
				count:  1,
				window: now,
			}
			return false
		}

		// Window not expired, increment the counter (requires write lock)
		rl.Lock()
		defer rl.Unlock()
		counter.count++
		return counter.count > rl.config.Requests
	}

	// IP doesn't exist, add it (requires write lock)
	rl.Lock()
	defer rl.Unlock()
	rl.requests[ip] = &requestCounter{
		count:  1,
		window: now,
	}
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
	logLevel         zapcore.Level
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

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Generate a unique log ID for this request
	logID := uuid.New().String()
	ctx := context.WithValue(r.Context(), "logID", logID)
	r = r.WithContext(ctx)

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

	// Phase 1 - Request Headers
	if !state.ResponseWritten {
		m.logger.Debug("Executing Phase 1 (Request Headers)",
			zap.String("log_id", logID),
		)
		m.handlePhase(w, r, 1, state)
		if state.Blocked {
			m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 1",
				zap.String("log_id", logID),
				zap.Int("status_code", state.StatusCode),
				zap.String("reason", "phase_1_block"),
			)
			w.WriteHeader(state.StatusCode)
			return nil
		}
	}

	// Phase 2 - Request Body
	if !state.ResponseWritten {
		m.logger.Debug("Executing Phase 2 (Request Body)",
			zap.String("log_id", logID),
		)
		m.handlePhase(w, r, 2, state)
		if state.Blocked {
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
	if !state.Blocked && !state.ResponseWritten {
		m.logger.Debug("Executing Phase 3 (Response Headers)",
			zap.String("log_id", logID),
		)
		m.handlePhase(recorder, r, 3, state)
		if state.Blocked {
			m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 3",
				zap.String("log_id", logID),
				zap.Int("status_code", state.StatusCode),
				zap.String("reason", "phase_3_block"),
			)
			if !state.ResponseWritten {
				w.WriteHeader(state.StatusCode)
			}
			return nil
		}
	}

	// Phase 4 - Response Body (after response is written)
	if !state.Blocked && !state.ResponseWritten {
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
					if state.Blocked && !state.ResponseWritten { // Check ResponseWritten before logging and writing
						m.logRequest(zapcore.WarnLevel, "Request blocked in Phase 4 (Response Body)",
							zap.String("log_id", logID),
							zap.String("rule_id", rule.ID),
							zap.String("description", rule.Description),
							zap.Int("status_code", state.StatusCode),
							zap.String("reason", "phase_4_block"),
						)
						w.WriteHeader(state.StatusCode)
						return nil // Return immediately after writing header
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
	}

	m.logger.Info("WAF evaluation complete",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
	)

	return err
}

func (m *Middleware) blockRequest(w http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, fields ...zap.Field) {
	// Atomically update the state
	stateUpdate := func() {
		state.Blocked = true
		state.StatusCode = statusCode
		state.ResponseWritten = true
	}

	// Execute the state update only if the response hasn't been written yet
	if !state.ResponseWritten {
		stateUpdate()

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

		// Respond with status code
		w.WriteHeader(statusCode)
	} else {
		m.logger.Debug("blockRequest called but response already written",
			zap.Int("intended_status_code", statusCode),
			zap.String("path", r.URL.Path),
			zap.String("log_id", r.Context().Value("logID").(string)), // Assuming logID is in context
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
	}

	// Increase the total anomaly score
	state.TotalScore += rule.Score

	// Extract log ID from request context
	logID, _ := r.Context().Value("logID").(string)
	if logID == "" {
		logID = uuid.New().String() // Fallback to new UUID if missing
	}

	// Capture detailed request and rule information
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

	// Log the rule match in detail
	m.logRequest(zapcore.InfoLevel, "Rule matched during evaluation", requestInfo...)

	// Block if anomaly threshold is exceeded
	if state.TotalScore >= m.AnomalyThreshold && !state.ResponseWritten {
		m.logRequest(zapcore.WarnLevel, "Request blocked - Anomaly threshold exceeded",
			zap.String("log_id", logID),
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
			zap.Int("status_code", http.StatusForbidden),
			zap.String("rule_id", rule.ID),
		)
		state.Blocked = true
		state.StatusCode = http.StatusForbidden
		w.WriteHeader(state.StatusCode)
		state.ResponseWritten = true
		return
	}

	// Handle the rule's defined action (block or log)
	switch rule.Action {
	case "block":
		if !state.ResponseWritten {
			m.logRequest(zapcore.WarnLevel, "Request blocked by rule match",
				zap.String("log_id", logID),
				zap.String("rule_id", rule.ID),
				zap.Int("status_code", http.StatusForbidden),
			)
			state.Blocked = true
			state.StatusCode = http.StatusForbidden
			w.WriteHeader(state.StatusCode)
			state.ResponseWritten = true
			return
		}

	case "log":
		m.logRequest(zapcore.InfoLevel, "Rule matched - Request allowed but logged",
			zap.String("log_id", logID),
			zap.String("rule_id", rule.ID),
		)
		return

	default:
		if !state.ResponseWritten {
			m.logRequest(zapcore.ErrorLevel, "Unknown rule action - Blocking request",
				zap.String("log_id", logID),
				zap.String("rule_id", rule.ID),
				zap.String("action", rule.Action),
				zap.Int("status_code", http.StatusForbidden),
			)
			state.Blocked = true
			state.StatusCode = http.StatusForbidden
			w.WriteHeader(state.StatusCode)
			state.ResponseWritten = true
			return
		}
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
			return
		} else if blocked {
			m.blockRequest(w, r, state, http.StatusForbidden,
				zap.String("message", "Request blocked by country"),
				zap.String("reason", "country_block"),
			)
			return
		}
	}

	// Phase 1 - Rate Limiting
	if phase == 1 && m.rateLimiter != nil {
		ip := extractIP(r.RemoteAddr)
		if m.rateLimiter.isRateLimited(ip) {
			m.blockRequest(w, r, state, http.StatusTooManyRequests,
				zap.String("message", "Request blocked by rate limit"),
				zap.String("reason", "rate_limit"),
			)
			return
		}
	}

	// Phase 1 - IP Blacklist
	if phase == 1 && m.isIPBlacklisted(r.RemoteAddr) {
		m.blockRequest(w, r, state, http.StatusForbidden,
			zap.String("message", "Request blocked by IP blacklist"),
			zap.String("reason", "ip_blacklist"),
		)
		return
	}

	// Phase 1 - DNS Blacklist
	if phase == 1 && m.isDNSBlacklisted(r.Host) {
		m.blockRequest(w, r, state, http.StatusForbidden,
			zap.String("message", "Request blocked by DNS blacklist"),
			zap.String("reason", "dns_blacklist"),
			zap.String("host", r.Host),
		)
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

	for _, rule := range rules {
		for _, target := range rule.Targets {
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

	// Phase 3 - Response Headers
	if phase == 3 {
		if recorder, ok := w.(*responseRecorder); ok {
			headers := recorder.Header()
			for _, rule := range m.Rules[3] {
				for _, target := range rule.Targets {
					value := headers.Get(target)
					if value != "" && rule.regex.MatchString(value) {
						m.processRuleMatch(recorder, r, &rule, value, state)
						if state.Blocked || state.ResponseWritten {
							return
						}
					}
				}
			}
		}
	}

	// Phase 4 - Response Body
	if phase == 4 {
		if recorder, ok := w.(*responseRecorder); ok {
			body := recorder.BodyString()
			for _, rule := range m.Rules[4] {
				for _, target := range rule.Targets {
					if target == "RESPONSE_BODY" {
						if rule.regex.MatchString(body) {
							m.processRuleMatch(recorder, r, &rule, body, state)
							if state.Blocked || state.ResponseWritten {
								return
							}
						}
					}
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

func (m *Middleware) logRequest(level zapcore.Level, msg string, fields ...zap.Field) {
	if m.logger == nil {
		return
	}

	// Extract log ID from fields or request context
	var logID string
	for i, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
			fields = append(fields[:i], fields[i+1:]...) // Remove log_id from fields
			break
		}
	}

	// Fallback to generating a new log ID if missing
	if logID == "" {
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

	// Initialize logLevel based on LogSeverity
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

	// Log that the middleware is being provisioned
	m.logger.Info("Provisioning WAF middleware",
		zap.String("log_level", m.LogSeverity),
		zap.Bool("log_json", m.LogJSON),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	// Log rate limit configuration if enabled
	if m.RateLimit.Requests > 0 {
		m.logger.Info("Rate limit configuration",
			zap.Int("requests", m.RateLimit.Requests),
			zap.Duration("window", m.RateLimit.Window),
			zap.Duration("cleanup_interval", m.RateLimit.CleanupInterval),
		)
	} else {
		m.logger.Info("Rate limiting is disabled")
	}

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
	m.logger.Debug("Validating loaded rules")
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
		m.logger.Debug("All rules validated successfully")
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

func (m *Middleware) extractValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
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

	// Full Header Dump (Request)
	case target == "HEADERS", target == "REQUEST_HEADERS":
		headers := make([]string, 0)
		for name, values := range r.Header {
			headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
		}
		return strings.Join(headers, "; "), nil

	// Response Headers (Phase 3)
	case target == "RESPONSE_HEADERS":
		if w != nil {
			headers := make([]string, 0)
			for name, values := range w.Header() {
				headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
			}
			return strings.Join(headers, "; "), nil
		}
		return "", fmt.Errorf("response headers not available during this phase")

	// Response Body (Phase 4)
	case target == "RESPONSE_BODY":
		if w != nil {
			if recorder, ok := w.(*responseRecorder); ok {
				return recorder.BodyString(), nil
			}
		}
		return "", fmt.Errorf("response body not available during this phase")

	// Dynamic Header Extraction (Request)
	case strings.HasPrefix(target, "HEADERS:"):
		headerName := strings.TrimPrefix(target, "HEADERS:")
		headerValue := r.Header.Get(headerName)
		if headerValue == "" {
			m.logger.Debug("Header not found or empty", zap.String("header", headerName))
			return "", nil
		}
		return headerValue, nil

	// Dynamic Response Header Extraction (Phase 3)
	case strings.HasPrefix(target, "RESPONSE_HEADERS:"):
		if w != nil {
			headerName := strings.TrimPrefix(target, "RESPONSE_HEADERS:")
			headerValue := w.Header().Get(headerName)
			if headerValue == "" {
				m.logger.Debug("Response header not found or empty", zap.String("header", headerName))
				return "", nil
			}
			return headerValue, nil
		}
		return "", fmt.Errorf("response header not available during this phase")

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
			m.logger.Debug("Cookie not found", zap.String("cookie", cookieName))
			return "", nil
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
		referer := r.Header.Get("Referer")
		if referer == "" {
			m.logger.Debug("Referer header not found or empty")
			return "", nil
		}
		return referer, nil

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

	// Raw Query String (similar to ARGS)
	case target == "QUERY_STRING":
		return r.URL.RawQuery, nil

	default:
		m.logger.Warn("Unknown target", zap.String("target", target))
		return "", fmt.Errorf("unknown target: %s", target)
	}
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
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Loading rules from file",
		zap.String("file", path),
	)

	content, err := os.ReadFile(path)
	if err != nil {
		m.logger.Error("Failed to read rule file",
			zap.String("file", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to read rule file: %s, error: %v", path, err)
	}

	var rules []Rule
	if err := json.Unmarshal(content, &rules); err != nil {
		m.logger.Error("Failed to unmarshal rules from file",
			zap.String("file", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to unmarshal rules from file: %s, error: %v. Ensure valid JSON.", path, err)
	}

	var invalidRules []string
	ruleIDs := make(map[string]bool)

	for i, rule := range rules {
		// Validate rule structure
		if err := validateRule(&rule); err != nil {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule at index %d: %v", i, err))
			continue
		}

		// Check for duplicate IDs
		if _, exists := ruleIDs[rule.ID]; exists {
			invalidRules = append(invalidRules, fmt.Sprintf("Duplicate rule ID '%s' at index %d", rule.ID, i))
			continue
		}
		ruleIDs[rule.ID] = true

		// Compile regex pattern
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			m.logger.Error("Failed to compile regex for rule",
				zap.String("rule_id", rule.ID),
				zap.String("pattern", rule.Pattern),
				zap.Error(err),
			)
			invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s': invalid regex pattern: %v", rule.ID, err))
			continue
		}
		rule.regex = regex

		// Initialize phase if missing
		if _, ok := m.Rules[rule.Phase]; !ok {
			m.Rules[rule.Phase] = []Rule{}
		}

		// Add rule to appropriate phase
		m.Rules[rule.Phase] = append(m.Rules[rule.Phase], rule)
	}

	if len(invalidRules) > 0 {
		m.logger.Warn("Some rules failed validation",
			zap.String("file", path),
			zap.Strings("invalid_rules", invalidRules),
		)
	}

	m.logger.Info("Rules loaded",
		zap.String("file", path),
		zap.Int("total_rules", len(rules)),
		zap.Int("invalid_rules", len(invalidRules)),
	)

	return nil
}
