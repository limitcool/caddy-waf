package caddywaf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
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
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

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
	CountryBlock     CountryAccessFilter `json:"country_block"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	Rules            map[int][]Rule      `json:"-"`
	ipBlacklist      map[string]bool     `json:"-"` // Changed type here
	dnsBlacklist     map[string]bool     `json:"-"`
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

	// rules hits stats
	ruleHits        sync.Map `json:"-"` // Use sync.Map for concurrent access, don't serialize
	MetricsEndpoint string   `json:"metrics_endpoint,omitempty"`

	configLoader          *ConfigLoader          `json:"-"`
	blacklistLoader       *BlacklistLoader       `json:"-"`
	geoIPHandler          *GeoIPHandler          `json:"-"`
	requestValueExtractor *RequestValueExtractor `json:"-"`

	RateLimit   RateLimit    `json:"rate_limit,omitempty"`
	rateLimiter *RateLimiter `json:"-"`
}

// WAFState struct: Used to maintain state between phases
type WAFState struct {
	TotalScore      int
	Blocked         bool
	StatusCode      int
	ResponseWritten bool
}

func (*Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return &Middleware{} },
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	logger := zap.L().Named("caddyfile_parser") // Naming the logger can be helpful

	logger.Info("Starting to parse Caddyfile", zap.String("file", h.Dispenser.File()))

	var m Middleware
	// dispenser := h.Dispenser

	logger.Debug("Creating dispenser", zap.String("file", h.Dispenser.File()))

	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		// Improve error message by including file and line number
		return nil, fmt.Errorf("caddyfile parse error: %w", err)
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

	// Log rule hit statistics
	m.logger.Info("Rule Hit Statistics:")
	m.ruleHits.Range(func(key, value interface{}) bool {
		m.logger.Info(fmt.Sprintf("Rule ID: %s, Hits: %d", key.(string), value.(int)))
		return true // Continue iterating
	})

	m.logger.Info("WAF middleware shutdown procedures completed")
	return firstError // Return the first error encountered, if any
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if m.configLoader == nil {
		m.configLoader = NewConfigLoader(m.logger)
	}
	return m.configLoader.UnmarshalCaddyfile(d, m)
}

func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if m.geoIPHandler == nil {
		return false, fmt.Errorf("geoip handler not initialized")
	}
	return m.geoIPHandler.IsCountryInList(remoteAddr, countryList, geoIP)
}

func (m *Middleware) getCountryCode(remoteAddr string, geoIP *maxminddb.Reader) string {
	if m.geoIPHandler == nil {
		return "N/A"
	}
	return m.geoIPHandler.GetCountryCode(remoteAddr, geoIP)
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Generate a unique log ID for this request
	logID := uuid.New().String()
	ctx := context.WithValue(r.Context(), "logID", logID)
	r = r.WithContext(ctx)

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

	// Phase 1: Country Whitelist and Blacklist Check
	if m.CountryWhitelist.Enabled {
		whitelisted, err := m.isCountryInList(r.RemoteAddr, m.CountryWhitelist.CountryList, m.CountryWhitelist.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check whitelist", zap.String("log_id", logID), zap.Error(err))
		} else if whitelisted {
			m.logRequest(zapcore.InfoLevel, "Request allowed - country whitelisted", zap.String("log_id", logID))
			return next.ServeHTTP(w, r)
		}
	}

	if m.CountryBlock.Enabled {
		blacklisted, err := m.isCountryInList(r.RemoteAddr, m.CountryBlock.CountryList, m.CountryBlock.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check blacklist", zap.String("log_id", logID), zap.Error(err))
			return block(http.StatusInternalServerError, "blacklist_check_error")
		} else if blacklisted {
			m.logRequest(zapcore.WarnLevel, "Request blocked - country blacklisted", zap.String("log_id", logID))
			return block(http.StatusForbidden, "country_blacklist")
		}
	}

	// Phase 2: Request Body Handling
	m.handlePhase(w, r, 1, state)
	if state.Blocked {
		w.WriteHeader(state.StatusCode)
		return nil
	}

	m.handlePhase(w, r, 2, state)
	if state.Blocked {
		w.WriteHeader(state.StatusCode)
		return nil
	}

	// Set up response recorder for Phase 3 and Phase 4
	recorder := &responseRecorder{ResponseWriter: w, body: new(bytes.Buffer)}
	err := next.ServeHTTP(recorder, r)

	// Phase 3: Response Header Rules
	m.handlePhase(recorder, r, 3, state)
	if state.Blocked {
		recorder.WriteHeader(state.StatusCode)
		return nil
	}

	// Phase 4: Response Body Rules
	if recorder.body != nil {
		body := recorder.body.String()
		m.logger.Debug("Response body captured", zap.String("body", body))

		for _, rule := range m.Rules[4] {
			if rule.regex.MatchString(body) {
				m.processRuleMatch(recorder, r, &rule, body, state)
				if state.Blocked {
					recorder.WriteHeader(state.StatusCode)
					return nil
				}
			}
		}

		// If not blocked, write the body to the client
		if !state.ResponseWritten {
			_, writeErr := w.Write(recorder.body.Bytes())
			if writeErr != nil {
				m.logger.Error("Failed to write response body", zap.Error(writeErr))
			}
		}
	}

	// Check if the request matches the metrics endpoint
	if m.MetricsEndpoint != "" && r.URL.Path == m.MetricsEndpoint {
		return m.handleMetricsRequest(w, r)
	}

	m.logger.Info("WAF evaluation complete",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
	)

	return err
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
		r.WriteHeader(http.StatusOK) // Default to 200 if not set
	}
	n, err := r.body.Write(b)
	// log.Printf("[DEBUG] Recorder Body Written: %d bytes, Error: %v", n, err)
	return n, err
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

	// Increment rule hit counter
	if count, ok := m.ruleHits.Load(rule.ID); ok {
		m.ruleHits.Store(rule.ID, count.(int)+1)
	} else {
		m.ruleHits.Store(rule.ID, 1)
	}

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

	// Extract log ID or generate a new one
	var logID string
	var newFields []zap.Field
	foundLogID := false

	for _, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
			foundLogID = true
		} else {
			newFields = append(newFields, field)
		}
	}

	if !foundLogID {
		logID = uuid.New().String()
	}

	// Append log_id explicitly to newFields
	newFields = append(newFields, zap.String("log_id", logID))

	// Attach common request metadata
	commonFields := m.getCommonLogFields(newFields)
	newFields = append(newFields, commonFields...)

	// Determine the log level if unset
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

	// Skip logging if level is below the threshold
	if level < m.logLevel {
		return
	}

	// Log the message with the appropriate format
	if m.LogJSON {
		newFields = append(newFields, zap.String("message", msg))
		m.logger.Log(level, "", newFields...)
	} else {
		m.logger.Log(level, msg, newFields...)
	}
}

func (m *Middleware) getCommonLogFields(fields []zap.Field) []zap.Field {
	// Extract or assign default values for metadata fields
	var sourceIP, userAgent, requestMethod, requestPath, queryParams string
	var statusCode int

	for _, field := range fields {
		switch field.Key {
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
			statusCode = int(field.Integer)
		}
	}

	// Default values for missing fields
	if sourceIP == "" {
		sourceIP = "unknown"
	}
	if userAgent == "" {
		userAgent = "unknown"
	}
	if requestMethod == "" {
		requestMethod = "unknown"
	}
	if requestPath == "" {
		requestPath = "unknown"
	}

	// Redact query parameters if required
	if m.RedactSensitiveData {
		queryParams = m.redactQueryParams(queryParams)
	}

	// Construct and return common fields
	return []zap.Field{
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
		zap.Time("timestamp", time.Now()), // Include a timestamp
	}
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
						if strings.Contains(file, "rule") { // Detect rule file changes
							if err := m.ReloadRules(); err != nil {
								m.logger.Error("Failed to reload rules after change",
									zap.String("file", file),
									zap.Error(err),
								)
							} else {
								m.logger.Info("Rules reloaded successfully",
									zap.String("file", file),
								)
							}
						} else {
							err := m.ReloadConfig()
							if err != nil {
								m.logger.Error("Failed to reload config after change",
									zap.Error(err),
								)
							} else {
								m.logger.Info("Configuration reloaded successfully")
							}
						}
					}
				case err := <-watcher.Errors:
					m.logger.Error("File watcher error", zap.Error(err))
				}
			}
		}(path)
	}
}

func (m *Middleware) ReloadRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Reloading WAF rules")

	// Temporary map for new rules
	newRules := make(map[int][]Rule)

	// Load rules into temporary map
	for _, file := range m.RuleFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			m.logger.Error("Failed to read rule file",
				zap.String("file", file),
				zap.Error(err),
			)
			continue
		}

		var rules []Rule
		if err := json.Unmarshal(content, &rules); err != nil {
			m.logger.Error("Failed to unmarshal rules from file",
				zap.String("file", file),
				zap.Error(err),
			)
			continue
		}

		for _, rule := range rules {
			// Validate and compile rule
			if err := validateRule(&rule); err != nil {
				m.logger.Warn("Invalid rule encountered",
					zap.String("file", file),
					zap.String("rule_id", rule.ID),
					zap.Error(err),
				)
				continue
			}

			// Compile regex
			rule.regex, err = regexp.Compile(rule.Pattern)
			if err != nil {
				m.logger.Error("Failed to compile regex for rule",
					zap.String("rule_id", rule.ID),
					zap.Error(err),
				)
				continue
			}

			// Add to appropriate phase
			if _, exists := newRules[rule.Phase]; !exists {
				newRules[rule.Phase] = []Rule{}
			}
			newRules[rule.Phase] = append(newRules[rule.Phase], rule)
		}
	}

	// Replace the old rules with the new rules
	m.Rules = newRules
	m.logger.Info("WAF rules reloaded successfully")

	return nil
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
		logFilePath = "log.json"
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

	// rules hits stats
	m.ruleHits = sync.Map{}

	// Log the dynamically fetched version
	m.logVersion()

	// Watch rule files for changes
	m.startFileWatcher(m.RuleFiles)

	// Watch IP and DNS blacklist files
	m.startFileWatcher([]string{m.IPBlacklistFile, m.DNSBlacklistFile})

	// Rate Limiter Setup
	if m.RateLimit.Requests > 0 {
		if m.RateLimit.Window <= 0 {
			return fmt.Errorf("invalid rate limit configuration: requests and window must be greater than zero")
		}
		m.logger.Info("Rate limit configuration",
			zap.Int("requests", m.RateLimit.Requests),
			zap.Duration("window", m.RateLimit.Window),
			zap.Duration("cleanup_interval", m.RateLimit.CleanupInterval),
		)
		m.rateLimiter = NewRateLimiter(m.RateLimit)
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

	m.configLoader = NewConfigLoader(m.logger)
	m.blacklistLoader = NewBlacklistLoader(m.logger)
	m.geoIPHandler = NewGeoIPHandler(m.logger)
	m.requestValueExtractor = NewRequestValueExtractor(m.logger, m.RedactSensitiveData)

	// GeoIP configuration must be set before loading the database
	m.geoIPHandler.WithGeoIPCache(m.geoIPCacheTTL)
	m.geoIPHandler.WithGeoIPLookupFallbackBehavior(m.geoIPLookupFallbackBehavior)

	dispenser := caddyfile.NewDispenser([]caddyfile.Token{})
	err = m.configLoader.UnmarshalCaddyfile(dispenser, m)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	//Blacklist Loading
	m.ipBlacklist = make(map[string]bool)
	if m.IPBlacklistFile != "" {
		err = m.blacklistLoader.LoadIPBlacklistFromFile(m.IPBlacklistFile, m.ipBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load IP blacklist: %w", err)
		}
	}
	m.dnsBlacklist = make(map[string]bool)
	if m.DNSBlacklistFile != "" {
		err = m.blacklistLoader.LoadDNSBlacklistFromFile(m.DNSBlacklistFile, m.dnsBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load DNS blacklist: %w", err)
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
	m.logger.Debug("Rules and Blacklists loaded successfully", zap.Int("total_rules", totalRules))

	return nil
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
	return m.requestValueExtractor.ExtractValue(target, r, w)
}

// Helper function for JSON path extraction.
func (m *Middleware) extractJSONPath(jsonStr string, jsonPath string) (string, error) {
	if m.requestValueExtractor == nil {
		return "", fmt.Errorf("requestValueExtractor is not initialized")
	}
	return m.requestValueExtractor.extractJSONPath(jsonStr, jsonPath)
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

// rules hits stats
// logRuleHitStats logs the rule hit statistics
func (m *Middleware) getRuleHitStats() map[string]int {
	stats := make(map[string]int)
	m.ruleHits.Range(func(key, value interface{}) bool {
		stats[key.(string)] = value.(int)
		return true
	})
	return stats
}

// handleMetricsRequest handles the request to the metrics endpoint.
func (m *Middleware) handleMetricsRequest(w http.ResponseWriter, r *http.Request) error {
	m.logger.Debug("Handling metrics request", zap.String("path", r.URL.Path))
	w.Header().Set("Content-Type", "application/json")

	stats := m.getRuleHitStats()

	// Convert stats to JSON
	jsonStats, err := json.Marshal(stats)
	if err != nil {
		m.logger.Error("Failed to marshal rule hit stats to JSON", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("failed to marshal rule hit stats to JSON: %v", err)
	}

	_, err = w.Write(jsonStats)
	if err != nil {
		m.logger.Error("Failed to write metrics response", zap.Error(err))
		return fmt.Errorf("failed to write metrics response: %v", err)
	}
	return nil
}
