package caddywaf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

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

// ==================== Initialization and Setup ====================

func init() {
	caddy.RegisterModule(&Middleware{}) // Changed from Middleware{} to &Middleware{}
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

func (*Middleware) CaddyModule() caddy.ModuleInfo {
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
	m.ruleCache = NewRuleCache() // Initialize RuleCache

	// Set default log severity if not provided
	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}

	// Set default log file path if not provided
	logFilePath := m.LogFilePath
	if logFilePath == "" {
		logFilePath = "log.json"
	}

	// Parse log severity level
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

	// Configure console logging
	consoleCfg := zap.NewProductionConfig()
	consoleCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	consoleCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg.EncoderConfig)
	consoleSync := zapcore.AddSync(os.Stdout)

	// Configure file logging
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

	// Create a multi-core logger for both console and file
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

	// Start the asynchronous logging worker
	m.StartLogWorker()

	// Provision Tor blocking
	if err := m.Tor.Provision(ctx); err != nil {
		return err
	}

	// Initialize rule hits map
	m.ruleHits = sync.Map{}

	// Log the current version of the middleware
	m.logVersion()

	// Start file watchers for rule files and blacklist files
	m.startFileWatcher(m.RuleFiles)
	m.startFileWatcher([]string{m.IPBlacklistFile, m.DNSBlacklistFile})

	// Configure rate limiting
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
		var err error
		m.rateLimiter, err = NewRateLimiter(m.RateLimit)
		if err != nil {
			return fmt.Errorf("failed to create rate limiter: %w", err)
		}
		m.rateLimiter.startCleanup()
	} else {
		m.logger.Info("Rate limiting is disabled")
	}

	// Initialize GeoIP stats
	m.geoIPStats = make(map[string]int64)

	// Configure GeoIP-based country blocking/whitelisting
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

	// Initialize config and blacklist loaders
	m.configLoader = NewConfigLoader(m.logger)
	m.blacklistLoader = NewBlacklistLoader(m.logger)
	m.geoIPHandler = NewGeoIPHandler(m.logger)
	m.requestValueExtractor = NewRequestValueExtractor(m.logger, m.RedactSensitiveData)

	// Configure GeoIP handler
	m.geoIPHandler.WithGeoIPCache(m.geoIPCacheTTL)
	m.geoIPHandler.WithGeoIPLookupFallbackBehavior(m.geoIPLookupFallbackBehavior)

	// Load configuration from Caddyfile
	dispenser := caddyfile.NewDispenser([]caddyfile.Token{})
	err = m.configLoader.UnmarshalCaddyfile(dispenser, m)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Load IP blacklist
	m.ipBlacklist = NewCIDRTrie()                                                                   // Initialize as CIDRTrie
	m.logger.Debug("ipBlacklist initialized in Provision", zap.Bool("isNil", m.ipBlacklist == nil)) // ADDED LOGGING - Check if nil right after initialization
	if m.IPBlacklistFile != "" {
		err = m.loadIPBlacklistIntoMap(m.IPBlacklistFile, m.ipBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load IP blacklist: %w", err)
		}
	}

	// Load DNS blacklist
	m.dnsBlacklist = make(map[string]struct{}) // Changed to map[string]struct{}
	if m.DNSBlacklistFile != "" {
		err = m.blacklistLoader.LoadDNSBlacklistFromFile(m.DNSBlacklistFile, m.dnsBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load DNS blacklist: %w", err)
		}
	}

	// Load WAF rules - calling the new external loadRules function
	if len(m.RuleFiles) > 0 { // Modified condition to check for rule files before loading
		if err := m.loadRules(m.RuleFiles); err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
	} else {
		m.logger.Warn("No rule files specified, WAF will run without rules.") // Log a warning instead of error
	}

	m.logger.Info("WAF middleware provisioned successfully")
	return nil
}

func (m *Middleware) Shutdown(ctx context.Context) error {
	m.logger.Info("Starting WAF middleware shutdown procedures")
	m.isShuttingDown = true

	// Stop the rate limiter cleanup
	if m.rateLimiter != nil {
		m.logger.Debug("Signaling rate limiter cleanup to stop...")
		m.rateLimiter.signalStopCleanup()
		m.logger.Debug("Rate limiter cleanup signaled.")
	} else {
		m.logger.Debug("Rate limiter is nil, no cleanup signaling needed.")
	}

	// Stop the asynchronous logging worker
	m.logger.Debug("Stopping logging worker...")
	m.StopLogWorker()
	m.logger.Debug("Logging worker stopped.")

	var firstError error
	var errorOccurred bool

	// Close GeoIP databases
	if m.CountryBlock.geoIP != nil {
		m.logger.Debug("Closing country block GeoIP database...")
		if err := m.CountryBlock.geoIP.Close(); err != nil {
			m.logger.Error("Error encountered while closing country block GeoIP database", zap.Error(err))
			if !errorOccurred {
				firstError = fmt.Errorf("error closing country block GeoIP: %w", err)
				errorOccurred = true
			}
		} else {
			m.logger.Debug("Country block GeoIP database closed successfully.")
		}
		m.CountryBlock.geoIP = nil
	} else {
		m.logger.Debug("Country block GeoIP database was not open, skipping close.")
	}

	if m.CountryWhitelist.geoIP != nil {
		m.logger.Debug("Closing country whitelist GeoIP database...")
		if err := m.CountryWhitelist.geoIP.Close(); err != nil {
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

	// Log rule hit statistics
	m.logger.Info("Rule Hit Statistics:")
	m.ruleHits.Range(func(key, value interface{}) bool {
		ruleID, ok := key.(RuleID)
		if !ok {
			m.logger.Error("Invalid type for rule ID in ruleHits map", zap.Any("key", key))
			return true
		}

		hitCount, ok := value.(HitCount)
		if !ok {
			m.logger.Error("Invalid type for hit count in ruleHits map", zap.Any("value", value))
			return true
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
		// Skip watching if the file doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			m.logger.Warn("Skipping file watch, file does not exist",
				zap.String("file", path),
			)
			continue
		}

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
	// Call the external loadRules function
	if err := m.loadRules(m.RuleFiles); err != nil {
		m.logger.Error("Failed to reload rules", zap.Error(err))
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	m.logger.Info("WAF rules reloaded successfully")
	return nil
}

func (m *Middleware) ReloadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Reloading WAF configuration")

	newIPBlacklist := NewCIDRTrie()
	if m.IPBlacklistFile != "" {
		if err := m.loadIPBlacklistIntoMap(m.IPBlacklistFile, newIPBlacklist); err != nil {
			m.logger.Error("Failed to reload IP blacklist", zap.String("file", m.IPBlacklistFile), zap.Error(err))
			return fmt.Errorf("failed to reload IP blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No IP blacklist file specified, skipping reload")
	}

	newDNSBlacklist := make(map[string]struct{})
	if m.DNSBlacklistFile != "" {
		if err := m.loadDNSBlacklistIntoMap(m.DNSBlacklistFile, newDNSBlacklist); err != nil {
			m.logger.Error("Failed to reload DNS blacklist", zap.String("file", m.DNSBlacklistFile), zap.Error(err))
			return fmt.Errorf("failed to reload DNS blacklist: %v", err)
		}
	} else {
		m.logger.Debug("No DNS blacklist file specified, skipping reload")
	}

	// Call the external loadRules function
	if err := m.loadRules(m.RuleFiles); err != nil {
		m.logger.Error("Failed to reload rules", zap.Error(err))
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	m.ipBlacklist = newIPBlacklist
	m.dnsBlacklist = newDNSBlacklist

	m.logger.Info("WAF configuration reloaded successfully")

	return nil
}

func (m *Middleware) loadIPBlacklistIntoMap(path string, blacklistMap *CIDRTrie) error {
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
		if err := blacklistMap.Insert(line); err != nil {
			m.logger.Warn("Failed to insert CIDR into trie", zap.String("cidr", line), zap.Error(err))
		}
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
		ruleID, ok := key.(RuleID)
		if !ok {
			m.logger.Error("Invalid type for rule ID in ruleHits map", zap.Any("key", key))
			return true // Continue iteration
		}
		hitCount, ok := value.(HitCount)
		if !ok {
			m.logger.Error("Invalid type for hit count in ruleHits map", zap.Any("value", value))
			return true // Continue iteration
		}
		stats[string(ruleID)] = int(hitCount)
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
		"rule_hits_by_phase": m.ruleHitsByPhase, // Include rule hits by phase
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
			m.blockRequest(w, r, state, http.StatusForbidden, "internal_error", "country_block_rule", r.RemoteAddr,
				zap.String("message", "Request blocked due to internal error"),
			)
			m.logger.Debug("Country blocking phase completed - blocked due to error")
			return
		} else if blocked {
			m.blockRequest(w, r, state, http.StatusForbidden, "country_block", "country_block_rule", r.RemoteAddr,
				zap.String("message", "Request blocked by country"),
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
			m.blockRequest(w, r, state, http.StatusTooManyRequests, "rate_limit", "rate_limit_rule", r.RemoteAddr,
				zap.String("message", "Request blocked by rate limit"),
			)
			m.logger.Debug("Rate limiting phase completed - blocked by rate limit")
			return
		}
		m.logger.Debug("Rate limiting phase completed - not blocked")
	}

	if phase == 1 && m.isIPBlacklisted(r.RemoteAddr) {
		m.logger.Debug("Starting IP blacklist phase")
		m.blockRequest(w, r, state, http.StatusForbidden, "ip_blacklist", "ip_blacklist_rule", r.RemoteAddr,
			zap.String("message", "Request blocked by IP blacklist"),
		)
		m.logger.Debug("IP blacklist phase completed - blocked")
		return
	}

	if phase == 1 && m.isDNSBlacklisted(r.Host) {
		m.logger.Debug("Starting DNS blacklist phase")
		m.blockRequest(w, r, state, http.StatusForbidden, "dns_blacklist", "dns_blacklist_rule", r.Host,
			zap.String("message", "Request blocked by DNS blacklist"),
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
		m.logger.Debug("Processing rule", zap.String("rule_id", string(rule.ID)), zap.Int("target_count", len(rule.Targets)))

		// Use the custom type as the key
		ctx := context.WithValue(r.Context(), ContextKeyRule("rule_id"), rule.ID)
		r = r.WithContext(ctx)

		for _, target := range rule.Targets {
			m.logger.Debug("Extracting value for target", zap.String("target", target), zap.String("rule_id", string(rule.ID)))
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
					zap.String("rule_id", string(rule.ID)),
					zap.Error(err),
				)
				continue
			}

			m.logger.Debug("Extracted value",
				zap.String("rule_id", string(rule.ID)),
				zap.String("target", target),
				zap.String("value", value),
			)

			if rule.regex.MatchString(value) {
				m.logger.Debug("Rule matched",
					zap.String("rule_id", string(rule.ID)),
					zap.String("target", target),
					zap.String("value", value),
				)
				if phase == 3 || phase == 4 {
					if recorder, ok := w.(*responseRecorder); ok {
						if !m.processRuleMatch(recorder, r, &rule, value, state) {
							return // Stop processing if the rule match indicates blocking
						}
					} else {
						if !m.processRuleMatch(w, r, &rule, value, state) {
							return // Stop processing if the rule match indicates blocking
						}
					}
				} else {
					if !m.processRuleMatch(w, r, &rule, value, state) {
						return // Stop processing if the rule match indicates blocking
					}
				}
				if state.Blocked || state.ResponseWritten {
					m.logger.Debug("Rule evaluation completed early due to blocking or response written", zap.Int("phase", phase), zap.String("rule_id", string(rule.ID)))
					return
				}
			} else {
				m.logger.Debug("Rule did not match",
					zap.String("rule_id", string(rule.ID)),
					zap.String("target", target),
					zap.String("value", value),
				)
			}
		}
	}
	m.logger.Debug("Rule evaluation completed for phase", zap.Int("phase", phase))

	if phase == 3 {
		m.logger.Debug("Starting response headers phase")
		if _, ok := w.(*responseRecorder); ok {
			m.logger.Debug("Response headers phase completed")
		}
	}

	if phase == 4 {
		m.logger.Debug("Starting response body phase")
		if _, ok := w.(*responseRecorder); ok {
			m.logger.Debug("Response body phase completed")
		}
	}

	m.logger.Debug("Completed phase evaluation",
		zap.Int("phase", phase),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)
}
