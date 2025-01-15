package caddywaf

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/fsnotify/fsnotify"

	"runtime/debug"
)

// ==================== Constants and Globals ====================

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

// ==================== Struct Definitions ====================

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
}

// CustomBlockResponse struct
type CustomBlockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
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
	ipBlacklist      map[string]struct{} `json:"-"` // Changed to map[string]struct{}
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
}

// WAFState struct
type WAFState struct {
	TotalScore      int
	Blocked         bool
	StatusCode      int
	ResponseWritten bool
}

// Define a custom type for context keys
type ContextKeyRule string

// Define custom types for rule hits
type RuleID string
type HitCount int

// ==================== Initialization and Setup ====================

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return &Middleware{} },
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	logger := zap.L().Named("caddyfile_parser")
	logger.Info("Starting to parse Caddyfile", zap.String("file", h.Dispenser.File()))

	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, fmt.Errorf("caddyfile parse error: %w", err)
	}

	logger.Info("Successfully parsed Caddyfile", zap.String("file", h.Dispenser.File()))
	return &m, nil
}

// ==================== Middleware Lifecycle Methods ====================

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}

	logFilePath := m.LogFilePath
	if logFilePath == "" {
		logFilePath = "log.json"
	}

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

	consoleCfg := zap.NewProductionConfig()
	consoleCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	consoleCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg.EncoderConfig)
	consoleSync := zapcore.AddSync(os.Stdout)

	fileCfg := zap.NewProductionConfig()
	fileCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	fileCfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	fileEncoder := zapcore.NewJSONEncoder(fileCfg.EncoderConfig)

	fileSync, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		m.logger.Warn("Failed to open log file, logging only to console", zap.String("path", logFilePath), zap.Error(err))
		m.logger = zap.New(zapcore.NewCore(consoleEncoder, consoleSync, logLevel))
		return nil
	}

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleSync, logLevel),
		zapcore.NewCore(fileEncoder, zapcore.AddSync(fileSync), zap.DebugLevel),
	)

	m.logger = zap.New(core)
	m.logger.Info("Provisioning WAF middleware",
		zap.String("log_level", m.LogSeverity),
		zap.String("log_path", logFilePath),
		zap.Bool("log_json", m.LogJSON),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	// Provision Tor blocking
	if err := m.Tor.Provision(ctx); err != nil {
		return err
	}

	m.ruleHits = sync.Map{}
	m.logVersion()
	m.startFileWatcher(m.RuleFiles)
	m.startFileWatcher([]string{m.IPBlacklistFile, m.DNSBlacklistFile})

	if m.RateLimit.Requests > 0 {
		if m.RateLimit.Window <= 0 || m.RateLimit.CleanupInterval <= 0 {
			return fmt.Errorf("invalid rate limit configuration: requests, window, and cleanup_interval must be greater than zero")
		}
		m.logger.Info("Rate limit configuration",
			zap.Int("requests", m.RateLimit.Requests),
			zap.Duration("window", m.RateLimit.Window),
			zap.Duration("cleanup_interval", m.RateLimit.CleanupInterval),
			zap.Strings("paths", m.RateLimit.Paths),
			zap.Bool("match_all_paths", m.RateLimit.MatchAllPaths),
		)
		m.rateLimiter = NewRateLimiter(m.RateLimit)
		m.rateLimiter.startCleanup()
	} else {
		m.logger.Info("Rate limiting is disabled")
	}

	m.geoIPStats = make(map[string]int64)

	if m.CountryBlock.Enabled || m.CountryWhitelist.Enabled {
		geoIPPath := m.CountryBlock.GeoIPDBPath
		if m.CountryWhitelist.Enabled && m.CountryWhitelist.GeoIPDBPath != "" {
			geoIPPath = m.CountryWhitelist.GeoIPDBPath
		}

		if !fileExists(geoIPPath) {
			m.logger.Warn("GeoIP database not found. Country blocking/whitelisting will be disabled", zap.String("path", geoIPPath))
		} else {
			reader, err := maxminddb.Open(geoIPPath)
			if err != nil {
				m.logger.Error("Failed to load GeoIP database", zap.String("path", geoIPPath), zap.Error(err))
			} else {
				m.logger.Info("GeoIP database loaded successfully", zap.String("path", geoIPPath))
				if m.CountryBlock.Enabled {
					m.CountryBlock.geoIP = reader
				}
				if m.CountryWhitelist.Enabled {
					m.CountryWhitelist.geoIP = reader
				}
			}
		}
	}

	m.configLoader = NewConfigLoader(m.logger)
	m.blacklistLoader = NewBlacklistLoader(m.logger)
	m.geoIPHandler = NewGeoIPHandler(m.logger)
	m.requestValueExtractor = NewRequestValueExtractor(m.logger, m.RedactSensitiveData)

	m.geoIPHandler.WithGeoIPCache(m.geoIPCacheTTL)
	m.geoIPHandler.WithGeoIPLookupFallbackBehavior(m.geoIPLookupFallbackBehavior)

	dispenser := caddyfile.NewDispenser([]caddyfile.Token{})
	err = m.configLoader.UnmarshalCaddyfile(dispenser, m)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	m.ipBlacklist = make(map[string]struct{}) // Changed to map[string]struct{}
	if m.IPBlacklistFile != "" {
		err = m.blacklistLoader.LoadIPBlacklistFromFile(m.IPBlacklistFile, m.ipBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load IP blacklist: %w", err)
		}
	}
	m.dnsBlacklist = make(map[string]struct{}) // Changed to map[string]struct{}
	if m.DNSBlacklistFile != "" {
		err = m.blacklistLoader.LoadDNSBlacklistFromFile(m.DNSBlacklistFile, m.dnsBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load DNS blacklist: %w", err)
		}
	}

	if err := m.loadRules(m.RuleFiles); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	m.logger.Info("WAF middleware provisioned successfully")
	return nil
}

func (m *Middleware) Shutdown(ctx context.Context) error {
	m.logger.Info("Starting WAF middleware shutdown procedures")
	m.isShuttingDown = true

	if m.rateLimiter != nil {
		m.logger.Debug("Signaling rate limiter cleanup to stop...")
		m.rateLimiter.signalStopCleanup()
		m.logger.Debug("Rate limiter cleanup signaled.")
	} else {
		m.logger.Debug("Rate limiter is nil, no cleanup signaling needed.")
	}

	var firstError error

	if m.CountryBlock.geoIP != nil {
		m.logger.Debug("Closing country block GeoIP database...")
		if err := m.CountryBlock.geoIP.Close(); err != nil {
			m.logger.Error("Error encountered while closing country block GeoIP database", zap.Error(err))
			if firstError == nil {
				firstError = fmt.Errorf("error closing country block GeoIP: %w", err)
			}
		} else {
			m.logger.Debug("Country block GeoIP database closed successfully.")
		}
		m.CountryBlock.geoIP = nil // Explicitly set to nil after closing
	} else {
		m.logger.Debug("Country block GeoIP database was not open, skipping close.")
	}

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
		m.CountryWhitelist.geoIP = nil
	} else {
		m.logger.Debug("Country whitelist GeoIP database was not open, skipping close.")
	}

	m.logger.Info("Rule Hit Statistics:")
	m.ruleHits.Range(func(key, value interface{}) bool {
		ruleID, ok := key.(RuleID)
		if !ok {
			m.logger.Error("Invalid type for rule ID in ruleHits map", zap.Any("key", key))
			return true // Continue iterating
		}

		hitCount, ok := value.(HitCount)
		if !ok {
			m.logger.Error("Invalid type for hit count in ruleHits map", zap.Any("value", value))
			return true // Continue iterating
		}

		m.logger.Info("Rule Hit",
			zap.String("rule_id", string(ruleID)),
			zap.Int("hits", int(hitCount)),
		)
		return true
	})

	m.logger.Info("WAF middleware shutdown procedures completed")
	return firstError
}

// ==================== Helper Functions ====================

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
	m.logger.Info("WAF middleware version", zap.String("version", moduleVersion))
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
						m.logger.Info("Detected configuration change. Reloading...", zap.String("file", file))
						if strings.Contains(file, "rule") {
							if err := m.ReloadRules(); err != nil {
								m.logger.Error("Failed to reload rules after change", zap.String("file", file), zap.Error(err))
							} else {
								m.logger.Info("Rules reloaded successfully", zap.String("file", file))
							}
						} else {
							err := m.ReloadConfig()
							if err != nil {
								m.logger.Error("Failed to reload config after change", zap.Error(err))
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

	newRules := make(map[int][]Rule)

	for _, file := range m.RuleFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			m.logger.Error("Failed to read rule file", zap.String("file", file), zap.Error(err))
			continue
		}

		var rules []Rule
		if err := json.Unmarshal(content, &rules); err != nil {
			m.logger.Error("Failed to unmarshal rules from file", zap.String("file", file), zap.Error(err))
			continue
		}

		for _, rule := range rules {
			if err := validateRule(&rule); err != nil {
				m.logger.Warn("Invalid rule encountered", zap.String("file", file), zap.String("rule_id", rule.ID), zap.Error(err))
				continue
			}

			rule.regex, err = regexp.Compile(rule.Pattern)
			if err != nil {
				m.logger.Error("Failed to compile regex for rule", zap.String("rule_id", rule.ID), zap.Error(err))
				continue
			}

			if _, exists := newRules[rule.Phase]; !exists {
				newRules[rule.Phase] = []Rule{}
			}
			newRules[rule.Phase] = append(newRules[rule.Phase], rule)
		}
	}

	m.Rules = newRules
	m.logger.Info("WAF rules reloaded successfully")

	return nil
}

func (m *Middleware) ReloadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Reloading WAF configuration")

	newRules := make(map[int][]Rule)
	if err := m.loadRulesIntoMap(newRules); err != nil {
		m.logger.Error("Failed to reload rules", zap.Error(err))
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	newIPBlacklist := make(map[string]struct{}) // Changed to map[string]struct{}
	if m.IPBlacklistFile != "" {
		if err := m.loadIPBlacklistIntoMap(m.IPBlacklistFile, newIPBlacklist); err != nil {
			m.logger.Error("Failed to reload IP blacklist", zap.String("file", m.IPBlacklistFile), zap.Error(err))
			return fmt.Errorf("failed to reload IP blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No IP blacklist file specified, skipping reload")
	}

	newDNSBlacklist := make(map[string]struct{}) // Changed to map[string]struct{}
	if m.DNSBlacklistFile != "" {
		if err := m.loadDNSBlacklistIntoMap(m.DNSBlacklistFile, newDNSBlacklist); err != nil {
			m.logger.Error("Failed to reload DNS blacklist", zap.String("file", m.DNSBlacklistFile), zap.Error(err))
			return fmt.Errorf("failed to reload DNS blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No DNS blacklist file specified, skipping reload")
	}

	m.Rules = newRules
	m.ipBlacklist = newIPBlacklist
	m.dnsBlacklist = newDNSBlacklist

	m.logger.Info("WAF configuration reloaded successfully")

	return nil
}

func (m *Middleware) loadRulesIntoMap(rulesMap map[int][]Rule) error {
	for _, file := range m.RuleFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			m.logger.Error("Failed to read rule file", zap.String("file", file), zap.Error(err))
			return fmt.Errorf("failed to read rule file: %s, error: %v", file, err)
		}

		var rules []Rule
		if err := json.Unmarshal(content, &rules); err != nil {
			m.logger.Error("Failed to unmarshal rules from file", zap.String("file", file), zap.Error(err))
			return fmt.Errorf("failed to unmarshal rules from file: %s, error: %v. Ensure valid JSON", file, err)
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

func (m *Middleware) loadIPBlacklistIntoMap(path string, blacklistMap map[string]struct{}) error {
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
		blacklistMap[line] = struct{}{} // Changed to struct{}{}
	}
	return nil
}

func (m *Middleware) loadDNSBlacklistIntoMap(path string, blacklistMap map[string]struct{}) error {
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
		blacklistMap[line] = struct{}{} // Changed to struct{}{}
	}
	return nil
}

// ==================== Metrics and Statistics ====================

func (m *Middleware) getRuleHitStats() map[string]int {
	stats := make(map[string]int)
	m.ruleHits.Range(func(key, value interface{}) bool {
		stats[key.(string)] = value.(int)
		return true
	})
	return stats
}

func (m *Middleware) handleMetricsRequest(w http.ResponseWriter, r *http.Request) error {
	m.logger.Debug("Handling metrics request", zap.String("path", r.URL.Path))
	w.Header().Set("Content-Type", "application/json")

	// Collect rule hits using getRuleHitStats
	ruleHits := m.getRuleHitStats()

	// Collect all metrics
	metrics := map[string]interface{}{
		"total_requests":     m.totalRequests,
		"blocked_requests":   m.blockedRequests,
		"allowed_requests":   m.allowedRequests,
		"rule_hits":          ruleHits,
		"rule_hits_by_phase": m.ruleHitsByPhase,
		"geoip_stats":        m.geoIPStats,
	}

	jsonMetrics, err := json.Marshal(metrics)
	if err != nil {
		m.logger.Error("Failed to marshal metrics to JSON", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("failed to marshal metrics to JSON: %v", err)
	}

	_, err = w.Write(jsonMetrics)
	if err != nil {
		m.logger.Error("Failed to write metrics response", zap.Error(err))
		return fmt.Errorf("failed to write metrics response: %v", err)
	}
	return nil
}

// ==================== Utility Functions ====================

func (m *Middleware) extractValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	return m.requestValueExtractor.ExtractValue(target, r, w)
}

// ==================== Unimplemented Functions ====================

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if m.configLoader == nil {
		m.configLoader = NewConfigLoader(m.logger)
	}
	return m.configLoader.UnmarshalCaddyfile(d, m)
}

func (m *Middleware) handlePhase(w http.ResponseWriter, r *http.Request, phase int, state *WAFState) {
	m.logger.Debug("Starting phase evaluation",
		zap.Int("phase", phase),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	if phase == 1 && m.CountryBlock.Enabled {
		m.logger.Debug("Starting country blocking phase")
		blocked, err := m.isCountryInList(r.RemoteAddr, m.CountryBlock.CountryList, m.CountryBlock.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check country block",
				r,
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

	if phase == 1 && m.rateLimiter != nil {
		m.logger.Debug("Starting rate limiting phase")
		ip := extractIP(r.RemoteAddr, m.logger) // Pass the logger here
		path := r.URL.Path                      // Get the request path
		if m.rateLimiter.isRateLimited(ip, path) {
			m.blockRequest(w, r, state, http.StatusTooManyRequests,
				zap.String("message", "Request blocked by rate limit"),
				zap.String("reason", "rate_limit"),
			)
			m.logger.Debug("Rate limiting phase completed - blocked by rate limit")
			return
		}
		m.logger.Debug("Rate limiting phase completed - not blocked")
	}

	if phase == 1 && m.isIPBlacklisted(r.RemoteAddr) {
		m.logger.Debug("Starting IP blacklist phase")
		m.blockRequest(w, r, state, http.StatusForbidden,
			zap.String("message", "Request blocked by IP blacklist"),
			zap.String("reason", "ip_blacklist"),
		)
		m.logger.Debug("IP blacklist phase completed - blocked")
		return
	}

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

	rules, ok := m.Rules[phase]
	if !ok {
		m.logger.Debug("No rules found for phase", zap.Int("phase", phase))
		return
	}

	m.logger.Debug("Starting rule evaluation for phase", zap.Int("phase", phase), zap.Int("rule_count", len(rules)))
	for _, rule := range rules {
		m.logger.Debug("Processing rule", zap.String("rule_id", rule.ID), zap.Int("target_count", len(rule.Targets)))

		// Use the custom type as the key
		ctx := context.WithValue(r.Context(), ContextKeyRule("rule_id"), rule.ID)
		r = r.WithContext(ctx)

		for _, target := range rule.Targets {
			m.logger.Debug("Extracting value for target", zap.String("target", target), zap.String("rule_id", rule.ID))
			var value string
			var err error

			if phase == 3 || phase == 4 {
				if recorder, ok := w.(*responseRecorder); ok {
					value, err = m.extractValue(target, r, recorder)
				} else {
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
