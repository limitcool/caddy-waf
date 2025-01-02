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

type CountryBlocking struct {
	Enabled     bool     `json:"enabled"`
	BlockList   []string `json:"block_list"`
	GeoIPDBPath string   `json:"geoip_db_path"`
	geoIP       *maxminddb.Reader
}

type GeoIPRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type Rule struct {
	ID       string   `json:"id"`
	Phase    int      `json:"phase"`
	Pattern  string   `json:"pattern"`
	Targets  []string `json:"targets"`
	Severity string   `json:"severity"`
	Action   string   `json:"action"`
	Score    int      `json:"score"`
	Mode     string   `json:"mode"`
	regex    *regexp.Regexp
}

type Middleware struct {
	RuleFiles        []string        `json:"rule_files"`
	IPBlacklistFile  string          `json:"ip_blacklist_file"`
	DNSBlacklistFile string          `json:"dns_blacklist_file"`
	LogAll           bool            `json:"log_all"`
	AnomalyThreshold int             `json:"anomaly_threshold"`
	RateLimit        RateLimit       `json:"rate_limit"`
	CountryBlock     CountryBlocking `json:"country_block"`
	Rules            []Rule          `json:"-"`
	logger           *zap.Logger
	ipBlacklist      map[string]bool `json:"-"`
	dnsBlacklist     []string        `json:"-"`
	rateLimiter      *RateLimiter    `json:"-"`
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
					m.CountryBlock.BlockList = append(m.CountryBlock.BlockList, strings.ToUpper(d.Val()))
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

func (m *Middleware) isCountryBlocked(remoteAddr string) bool {
	if !m.CountryBlock.Enabled || m.CountryBlock.geoIP == nil {
		return false
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	var record GeoIPRecord
	err = m.CountryBlock.geoIP.Lookup(parsedIP, &record)
	if err != nil {
		return false
	}

	for _, blockedCountry := range m.CountryBlock.BlockList {
		if strings.EqualFold(record.Country.ISOCode, blockedCountry) {
			return true
		}
	}

	return false
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	statusCode := http.StatusOK

	// Check country blocking first
	if m.isCountryBlocked(r.RemoteAddr) {
		m.logger.Info("Request blocked by country",
			zap.String("ip", r.RemoteAddr),
			zap.Int("status_code", http.StatusForbidden),
		)
		w.WriteHeader(http.StatusForbidden)
		return nil
	}

	if m.rateLimiter != nil {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil && m.rateLimiter.isRateLimited(ip) {
			m.logger.Info("Request blocked by rate limit",
				zap.String("ip", ip),
				zap.Int("status_code", http.StatusTooManyRequests),
			)
			w.WriteHeader(http.StatusTooManyRequests)
			return nil
		}
	}

	if m.isIPBlacklisted(r.RemoteAddr) {
		statusCode = http.StatusForbidden
		m.logger.Info("Request blocked by IP blacklist",
			zap.String("ip", r.RemoteAddr),
			zap.Int("status_code", statusCode),
		)
		w.WriteHeader(statusCode)
		return nil
	}

	if m.isDNSBlacklisted(r.Host) {
		statusCode = http.StatusForbidden
		m.logger.Info("Request blocked by DNS blacklist",
			zap.String("domain", r.Host),
			zap.Int("status_code", statusCode),
		)
		w.WriteHeader(statusCode)
		return nil
	}

	totalScore := 0
	for _, rule := range m.Rules {
		for _, target := range rule.Targets {
			value, _ := m.extractValue(target, r)
			if rule.regex.MatchString(value) {
				totalScore += rule.Score
				mode := rule.Mode
				if mode == "" {
					mode = rule.Action
				}
				switch mode {
				case "block":
					statusCode = http.StatusForbidden
					m.logger.Info("Rule Matched",
						zap.String("rule_id", rule.ID),
						zap.String("target", target),
						zap.String("value", value),
						zap.Int("status_code", statusCode),
					)
					w.WriteHeader(statusCode)
					return nil
				case "log":
					m.logger.Info("Rule Matched",
						zap.String("rule_id", rule.ID),
						zap.String("target", target),
						zap.String("value", value),
						zap.Int("status_code", statusCode),
					)
				}
			}
		}
	}

	if totalScore >= m.AnomalyThreshold {
		statusCode = http.StatusForbidden
		m.logger.Info("Request blocked by Anomaly Threshold",
			zap.Int("status_code", statusCode),
		)
		w.WriteHeader(statusCode)
		return nil
	}

	return next.ServeHTTP(w, r)
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.RateLimit.Requests > 0 {
		m.rateLimiter = &RateLimiter{
			requests: make(map[string]*requestCounter),
			config:   m.RateLimit,
		}
	}

	// Initialize GeoIP if enabled
	if m.CountryBlock.Enabled {
		reader, err := maxminddb.Open(m.CountryBlock.GeoIPDBPath)
		if err != nil {
			return fmt.Errorf("failed to load GeoIP database: %v", err)
		}
		m.CountryBlock.geoIP = reader
	}

	for _, file := range m.RuleFiles {
		if err := m.loadRulesFromFile(file); err != nil {
			return fmt.Errorf("failed to load rules from %s: %v", file, err)
		}
	}
	if m.AnomalyThreshold == 0 {
		m.AnomalyThreshold = 5
	}
	if m.IPBlacklistFile != "" {
		if err := m.loadIPBlacklistFromFile(m.IPBlacklistFile); err != nil {
			return fmt.Errorf("failed to load IP blacklist from %s: %v", m.IPBlacklistFile, err)
		}
	} else {
		m.ipBlacklist = make(map[string]bool)
	}
	if m.DNSBlacklistFile != "" {
		if err := m.loadDNSBlacklistFromFile(m.DNSBlacklistFile); err != nil {
			return fmt.Errorf("failed to load DNS blacklist from %s: %v", m.DNSBlacklistFile, err)
		}
	} else {
		m.dnsBlacklist = []string{}
	}
	return nil
}

func (m *Middleware) isIPBlacklisted(remoteAddr string) bool {
	if m.ipBlacklist == nil || len(m.ipBlacklist) == 0 {
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
	switch target {
	case "ARGS":
		return r.URL.RawQuery, nil
	case "BODY":
		if r.Body == nil {
			return "", nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		return string(body), nil
	case "HEADERS":
		return fmt.Sprintf("%v", r.Header), nil
	case "URL":
		return r.URL.Path, nil
	case "USER_AGENT":
		return r.UserAgent(), nil
	case "COOKIES":
		return fmt.Sprintf("%v", r.Cookies()), nil
	case "PATH":
		return r.URL.Path, nil
	case "URI":
		return r.RequestURI, nil
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
