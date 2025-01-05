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
	fmt.Println("Registering WAF Middleware")
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
	fmt.Println("WAF Middleware Registered Successfully")
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

type RateLimit struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
}

type requestCounter struct {
	count  int
	window time.Time
}

type RateLimiter struct {
	sync.RWMutex
	requests map[string]*requestCounter
	config   RateLimit
}

type CountryAccessFilter struct {
	Enabled     bool     `json:"enabled"`
	CountryList []string `json:"country_list"`
	GeoIPDBPath string   `json:"geoip_db_path"`
	geoIP       *maxminddb.Reader
}

type GeoIPRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type Rule struct {
	ID          string   `json:"id"`
	Phase       int      `json:"phase"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Severity    string   `json:"severity"`
	Action      string   `json:"action"`
	Score       int      `json:"score"`
	Mode        string   `json:"mode"`
	Description string   `json:"description"`
	regex       *regexp.Regexp
}

type SeverityConfig struct {
	Critical string `json:"critical,omitempty"`
	High     string `json:"high,omitempty"`
	Medium   string `json:"medium,omitempty"`
	Low      string `json:"low,omitempty"`
}

type Middleware struct {
	RuleFiles        []string            `json:"rule_files"`
	IPBlacklistFile  string              `json:"ip_blacklist_file"`
	DNSBlacklistFile string              `json:"dns_blacklist_file"`
	LogAll           bool                `json:"log_all"`
	AnomalyThreshold int                 `json:"anomaly_threshold"`
	RateLimit        RateLimit           `json:"rate_limit"`
	CountryBlock     CountryAccessFilter `json:"country_block"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	Severity         SeverityConfig      `json:"severity,omitempty"`
	Rules            []Rule              `json:"-"`
	ipBlacklist      map[string]bool     `json:"-"`
	dnsBlacklist     []string            `json:"-"`
	rateLimiter      *RateLimiter        `json:"-"`
	logger           *zap.Logger
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
	fmt.Println("WAF UnmarshalCaddyfile Called")
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
			case "log_all":
				fmt.Println("WAF Log All Enabled")
				m.LogAll = true
			case "rule_file":
				fmt.Println("WAF Loading Rule File")
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RuleFiles = append(m.RuleFiles, d.Val())
			case "ip_blacklist_file":
				fmt.Println("WAF Loading IP Blacklist File")
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.IPBlacklistFile = d.Val()
			case "dns_blacklist_file":
				fmt.Println("WAF Loading DNS Blacklist File")
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.DNSBlacklistFile = d.Val()
			case "severity":
				if !d.NextArg() {
					return d.ArgErr()
				}
				severityLevel := strings.ToLower(d.Val())
				if !d.NextArg() {
					return d.ArgErr()
				}
				action := strings.ToLower(d.Val())
				switch severityLevel {
				case "critical":
					m.Severity.Critical = action
				case "high":
					m.Severity.High = action
				case "medium":
					m.Severity.Medium = action
				case "low":
					m.Severity.Low = action
				default:
					return d.Errf("invalid severity level: %s", severityLevel)
				}
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
				fmt.Println("WAF Unrecognized SubDirective: ", d.Val())
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func (rl *RateLimiter) isRateLimited(ip string) bool {
	rl.Lock()
	defer rl.Unlock()

	now := time.Now()
	if counter, exists := rl.requests[ip]; exists {
		if now.Sub(counter.window) > rl.config.Window {
			counter.count = 1
			counter.window = now
			return false
		}
		counter.count++
		return counter.count > rl.config.Requests
	}

	rl.requests[ip] = &requestCounter{
		count:  1,
		window: now,
	}
	return false
}

func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if geoIP == nil {
		return false, fmt.Errorf("GeoIP database not loaded")
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	var record GeoIPRecord
	err = geoIP.Lookup(parsedIP, &record)
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

type responseWriterWrapper struct {
	http.ResponseWriter
	headerSent  bool
	bodyAllowed bool
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	if !w.headerSent {
		w.ResponseWriter.WriteHeader(statusCode)
		w.headerSent = true
		// Disallow body writes for 403 status
		if statusCode == http.StatusForbidden {
			w.bodyAllowed = false
		} else {
			w.bodyAllowed = true
		}
	}
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	if w.headerSent && w.bodyAllowed {
		return w.ResponseWriter.Write(b)
	}
	// Discard the body if not allowed
	return len(b), nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	wrappedW := &responseWriterWrapper{ResponseWriter: w}

	// Handle Phase 1 and get the total score
	phase1Score := m.handlePhase1(wrappedW, r)
	if phase1Score < 0 {
		// Request was blocked in Phase 1 (e.g., IP blacklist, rate limit)
		return nil
	}

	// Handle Phase 2 with the accumulated score
	totalScore := m.handlePhase2(wrappedW, r, phase1Score)

	if totalScore >= m.AnomalyThreshold {
		m.handlePhase3(wrappedW, r, totalScore)
		return nil
	}

	// Proceed to the next handler
	return next.ServeHTTP(wrappedW, r)
}

func (m *Middleware) handlePhase1(w http.ResponseWriter, r *http.Request) int {
	wrappedW, ok := w.(*responseWriterWrapper)
	if !ok {
		wrappedW = &responseWriterWrapper{ResponseWriter: w}
	}

	m.logger.Debug("Handling phase 1 rules")

	// Check country blocking
	if m.CountryBlock.Enabled {
		blocked, err := m.isCountryInList(r.RemoteAddr, m.CountryBlock.CountryList, m.CountryBlock.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check country block",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
		} else if blocked {
			m.logRequest(zapcore.InfoLevel, "Request blocked by country",
				zap.String("ip", r.RemoteAddr),
				zap.Int("status_code", http.StatusForbidden),
			)
			wrappedW.WriteHeader(http.StatusForbidden)
			return -1 // Return -1 to indicate the request is blocked
		}
	}

	// Check country whitelisting
	if m.CountryWhitelist.Enabled {
		whitelisted, err := m.isCountryInList(r.RemoteAddr, m.CountryWhitelist.CountryList, m.CountryWhitelist.geoIP)
		if err != nil {
			m.logRequest(zapcore.ErrorLevel, "Failed to check country whitelist",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err),
			)
		} else if !whitelisted {
			m.logRequest(zapcore.InfoLevel, "Request blocked by country whitelist",
				zap.String("ip", r.RemoteAddr),
				zap.Int("status_code", http.StatusForbidden),
			)
			wrappedW.WriteHeader(http.StatusForbidden)
			return -1 // Return -1 to indicate the request is blocked
		}
	}

	// Check rate limiting
	if m.rateLimiter != nil {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil && m.rateLimiter.isRateLimited(ip) {
			m.logRequest(zapcore.InfoLevel, "Request blocked by rate limit",
				zap.String("ip", ip),
				zap.Int("status_code", http.StatusTooManyRequests),
			)
			wrappedW.WriteHeader(http.StatusTooManyRequests)
			return -1 // Return -1 to indicate the request is blocked
		}
	}

	// Check IP blacklist
	if m.isIPBlacklisted(r.RemoteAddr) {
		m.logRequest(zapcore.InfoLevel, "Request blocked by IP blacklist",
			zap.String("ip", r.RemoteAddr),
			zap.Int("status_code", http.StatusForbidden),
		)
		wrappedW.WriteHeader(http.StatusForbidden)
		return -1 // Return -1 to indicate the request is blocked
	}

	// Check DNS blacklist
	if m.isDNSBlacklisted(r.Host) {
		m.logRequest(zapcore.InfoLevel, "Request blocked by DNS blacklist",
			zap.String("domain", r.Host),
			zap.Int("status_code", http.StatusForbidden),
		)
		wrappedW.WriteHeader(http.StatusForbidden)
		return -1 // Return -1 to indicate the request is blocked
	}

	// Evaluate phase 1 rules and accumulate scores
	totalScore := 0
	for _, rule := range m.Rules {
		if rule.Phase != 1 {
			continue
		}
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
				totalScore += rule.Score
				m.logRequest(zapcore.InfoLevel, "Rule Matched",
					zap.String("rule_id", rule.ID),
					zap.String("target", target),
					zap.String("value", value),
					zap.String("description", rule.Description),
					zap.Int("score", rule.Score),
					zap.Int("total_score", totalScore),
					zap.Int("anomaly_threshold", m.AnomalyThreshold),
				)
			}
		}
	}

	// Log the final score after evaluating all rules
	m.logRequest(zapcore.InfoLevel, "Phase 1 Completed",
		zap.Int("total_score", totalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	return totalScore
}

func (m *Middleware) handlePhase2(w http.ResponseWriter, r *http.Request, phase1Score int) int {
	wrappedW, ok := w.(*responseWriterWrapper)
	if !ok {
		wrappedW = &responseWriterWrapper{ResponseWriter: w}
	}

	totalScore := phase1Score
	for _, rule := range m.Rules {
		if rule.Phase != 2 {
			continue
		}
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
				totalScore += rule.Score
				m.logRequest(zapcore.InfoLevel, "Rule Matched - Score Updated",
					zap.String("rule_id", rule.ID),
					zap.String("target", target),
					zap.String("value", value),
					zap.String("description", rule.Description),
					zap.Int("score", rule.Score),
					zap.Int("total_score", totalScore),
					zap.Int("anomaly_threshold", m.AnomalyThreshold),
				)

				// Check if the total score exceeds the anomaly threshold
				if totalScore >= m.AnomalyThreshold {
					m.logRequest(zapcore.WarnLevel, "Anomaly Threshold Reached - Request Blocked",
						zap.Int("total_score", totalScore),
						zap.Int("anomaly_threshold", m.AnomalyThreshold),
						zap.Int("status_code", http.StatusForbidden),
					)
					wrappedW.WriteHeader(http.StatusForbidden)
					return totalScore
				}
			}
		}
	}

	// Log the final score after evaluating all rules
	m.logRequest(zapcore.InfoLevel, "Phase 2 Completed",
		zap.Int("total_score", totalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	return totalScore
}

func (m *Middleware) handlePhase3(w http.ResponseWriter, r *http.Request, totalScore int) {
	wrappedW, ok := w.(*responseWriterWrapper)
	if !ok {
		wrappedW = &responseWriterWrapper{ResponseWriter: w}
	}

	// Log the blocking event with additional details
	m.logRequest(zapcore.WarnLevel, "Request blocked by Anomaly Threshold",
		zap.Int("total_score", totalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
		zap.Int("status_code", http.StatusForbidden),
	)

	// Block the request with a 403 Forbidden response
	wrappedW.WriteHeader(http.StatusForbidden)
}

func (m *Middleware) logRequest(level zapcore.Level, msg string, fields ...zap.Field) {
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

func (m *Middleware) getSeverityAction(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return m.Severity.Critical
	case "high":
		return m.Severity.High
	case "medium":
		return m.Severity.Medium
	case "low":
		return m.Severity.Low
	default:
		return "log"
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	// Initialize the logger
	m.logger = ctx.Logger(m)
	m.logger.Info("Provisioning WAF middleware")

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
	}

	// Load GeoIP database for country blocking
	if m.CountryBlock.Enabled {
		m.logger.Debug("Loading GeoIP database for country blocking",
			zap.String("path", m.CountryBlock.GeoIPDBPath),
		)
		reader, err := maxminddb.Open(m.CountryBlock.GeoIPDBPath)
		if err != nil {
			return fmt.Errorf("failed to load GeoIP database for country blocking: %v", err)
		}
		m.CountryBlock.geoIP = reader
		m.logger.Info("GeoIP database loaded for country blocking",
			zap.String("path", m.CountryBlock.GeoIPDBPath),
		)
	}

	// Load GeoIP database for country whitelisting
	if m.CountryWhitelist.Enabled {
		m.logger.Debug("Loading GeoIP database for country whitelisting",
			zap.String("path", m.CountryWhitelist.GeoIPDBPath),
		)
		reader, err := maxminddb.Open(m.CountryWhitelist.GeoIPDBPath)
		if err != nil {
			return fmt.Errorf("failed to load GeoIP database for country whitelisting: %v", err)
		}
		m.CountryWhitelist.geoIP = reader
		m.logger.Info("GeoIP database loaded for country whitelisting",
			zap.String("path", m.CountryWhitelist.GeoIPDBPath),
		)
	}

	// Load rules from rule files
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
	for _, rule := range m.Rules {
		m.logger.Debug("Validating rule",
			zap.String("rule_id", rule.ID),
			zap.Int("phase", rule.Phase),
			zap.String("pattern", rule.Pattern),
			zap.Strings("targets", rule.Targets),
			zap.String("severity", rule.Severity),
			zap.String("action", rule.Action),
			zap.Int("score", rule.Score),
			zap.String("description", rule.Description),
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
		if rule.regex == nil {
			invalidRules = append(invalidRules, fmt.Sprintf("Rule '%s' has an invalid regex pattern", rule.ID))
			continue
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
		m.logger.Info("IP blacklist loaded successfully",
			zap.Int("count", len(m.ipBlacklist)),
		)
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
		m.logger.Info("DNS blacklist loaded successfully",
			zap.Int("count", len(m.dnsBlacklist)),
		)
	} else {
		m.dnsBlacklist = []string{}
		m.logger.Debug("No DNS blacklist file specified, initializing empty blacklist")
	}

	m.logger.Info("WAF middleware provisioned successfully")
	return nil
}

func (m *Middleware) isIPBlacklisted(remoteAddr string) bool {
	if len(m.ipBlacklist) == 0 {
		return false
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	if m.ipBlacklist[ip] {
		return true
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for blacklistIP := range m.ipBlacklist {
		_, ipNet, err := net.ParseCIDR(blacklistIP)
		if err != nil {
			if blacklistIP == ip {
				return true
			}
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func (m *Middleware) isDNSBlacklisted(host string) bool {
	if m.dnsBlacklist == nil || len(m.dnsBlacklist) == 0 {
		return false
	}
	for _, blacklistedDomain := range m.dnsBlacklist {
		if strings.EqualFold(host, blacklistedDomain) {
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
		if r.Body == nil {
			return "", nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		return string(body), nil
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
		if r.Body == nil {
			return "", nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var jsonData map[string]interface{}
		if err := json.Unmarshal(body, &jsonData); err != nil {
			return "", err
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
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rules []Rule
	if err := json.Unmarshal(content, &rules); err != nil {
		return err
	}
	for i, rule := range rules {
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid pattern in rule %s: %v", rule.ID, err)
		}
		rules[i].regex = regex
		if rule.Mode == "" {
			rules[i].Mode = rule.Action
		}
	}
	m.Rules = append(m.Rules, rules...)
	return nil
}

func (m *Middleware) loadIPBlacklistFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ips := strings.Split(string(content), "\n")
	m.ipBlacklist = make(map[string]bool)
	for _, ip := range ips {
		if ip != "" {
			m.ipBlacklist[ip] = true
		}
	}
	return nil
}

func (m *Middleware) loadDNSBlacklistFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m.dnsBlacklist = strings.Split(string(content), "\n")
	return nil
}

func (m *Middleware) ReloadConfig() error {
	if err := m.loadRulesFromFiles(); err != nil {
		return err
	}
	if err := m.loadIPBlacklistFromFile(m.IPBlacklistFile); err != nil {
		return err
	}
	if err := m.loadDNSBlacklistFromFile(m.DNSBlacklistFile); err != nil {
		return err
	}
	return nil
}

func (m *Middleware) loadRulesFromFiles() error {
	m.Rules = []Rule{}
	for _, file := range m.RuleFiles {
		if err := m.loadRulesFromFile(file); err != nil {
			return err
		}
	}
	return nil
}
