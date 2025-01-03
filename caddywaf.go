package caddywaf

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net"
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
    caddy.RegisterModule(Middleware{})
    httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

type RateLimit struct {
    Requests int           `json:"requests"`
    Window   time.Duration `json:"window"`
}

type requestCounter struct {
    count  int
    window time.Time
}

type RateLimiter struct {
    requests sync.Map
    config   RateLimit
}

type CountryBlocking struct {
    Enabled     bool     `json:"enabled"`
    BlockList   []string `json:"block_list"`
    GeoIPDBPath string   `json:"geoip_db_path"`
}

type GeoIPCache struct {
    cache sync.Map
    geoIP *maxminddb.Reader
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
    RuleFiles        []string        `json:"rule_files"`
    IPBlacklistFile  string          `json:"ip_blacklist_file"`
    DNSBlacklistFile string          `json:"dns_blacklist_file"`
    LogAll           bool            `json:"log_all"`
    AnomalyThreshold int             `json:"anomaly_threshold"`
    RateLimit        RateLimit       `json:"rate_limit"`
    CountryBlock     CountryBlocking `json:"country_block"`
    Severity         SeverityConfig  `json:"severity,omitempty"`
    Rules            []Rule          `json:"-"`
    logger           *zap.Logger
    logChan          chan *zapcore.Entry
    ipBlacklistCIDRs []IPNet
    ipBlacklist      map[string]bool
    dnsBlacklist     map[string]bool
    geoIPCache       *GeoIPCache
}

type IPNet struct {
    IP    net.IP
    Mask  net.IPMask
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
    for d.Next() {
        for d.NextBlock(0) {
            switch d.Val() {
            // Existing directives handling
            }
        }
    }
    return nil
}

func (rl *RateLimiter) isRateLimited(ip string) bool {
    now := time.Now()
    counterIface, _ := rl.requests.LoadOrStore(ip, &requestCounter{count: 1, window: now})
    counter := counterIface.(*requestCounter)

    if now.Sub(counter.window) > rl.config.Window {
        counter.count = 1
        counter.window = now
    } else {
        counter.count++
        if counter.count > rl.config.Requests {
            return true
        }
    }
    return false
}

func (g *GeoIPCache) getCountry(ip net.IP) (string, error) {
    if country, ok := g.cache.Load(ip); ok {
        return country.(string), nil
    }
    var record GeoIPRecord
    err := g.geoIP.Lookup(ip, &record)
    if err != nil {
        return "", err
    }
    g.cache.Store(ip, record.Country.ISOCode)
    return record.Country.ISOCode, nil
}

func (m *Middleware) isCountryBlocked(remoteAddr string) bool {
    if !m.CountryBlock.Enabled || m.geoIPCache == nil {
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

    country, err := m.geoIPCache.getCountry(parsedIP)
    if err != nil {
        return false
    }

    for _, blockedCountry := range m.CountryBlock.BlockList {
        if strings.EqualFold(country, blockedCountry) {
            return true
        }
    }

    return false
}

func (m *Middleware) isIPBlacklisted(remoteAddr string) bool {
    ip := net.ParseIP(remoteAddr)
    if ip == nil {
        return false
    }
    for _, ipNet := range m.ipBlacklistCIDRs {
        if ipNet.Mask.Contains(ip) {
            return true
        }
    }
    return m.ipBlacklist[remoteAddr]
}

func (m *Middleware) loadIPBlacklistFromFile(path string) error {
    content, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    lines := strings.Split(string(content), "\n")
    ipNets := make([]IPNet, 0, len(lines))
    m.ipBlacklist = make(map[string]bool)
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        ip, ipNet, err := net.ParseCIDR(line)
        if err != nil {
            m.ipBlacklist[ip.String()] = true
            continue
        }
        ipNets = append(ipNets, IPNet{IP: ip, Mask: ipNet.Mask})
    }
    m.ipBlacklistCIDRs = ipNets
    return nil
}

func (m *Middleware) loadDNSBlacklistFromFile(path string) error {
    content, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    domains := strings.Split(string(content), "\n")
    m.dnsBlacklist = make(map[string]bool)
    for _, domain := range domains {
        domain = strings.TrimSpace(domain)
        if domain != "" {
            m.dnsBlacklist[strings.ToLower(domain)] = true
        }
    }
    return nil
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
        var regex *regexp.Regexp
        var compileErr error
        if rule.Mode == "re" {
            regex, compileErr = regexp.Compile(rule.Pattern)
        } else {
            // Preprocess the pattern for exact or substring matching
            // ...
        }
        if compileErr != nil {
            return fmt.Errorf("invalid pattern in rule %s: %v", rule.ID, compileErr)
        }
        rules[i].regex = regex
    }
    m.Rules = append(m.Rules, rules...)
    return nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    if m.handlePhase1(w, r) {
        return nil
    }

    totalScore := m.handlePhase2(w, r)
    if totalScore >= m.AnomalyThreshold {
        m.handlePhase3(w, r)
        return nil
    }

    return next.ServeHTTP(w, r)
}

func (m *Middleware) handlePhase1(w http.ResponseWriter, r *http.Request) bool {
    // Existing Phase 1 handling with optimized checks
    return false
}

func (m *Middleware) handlePhase2(w http.ResponseWriter, r *http.Request) int {
    // Existing Phase 2 handling with optimized rule processing
    return 0
}

func (m *Middleware) handlePhase3(w http.ResponseWriter, r *http.Request) {
    // Existing Phase 3 handling
}

func (m *Middleware) logRequest(level zapcore.Level, msg string, fields ...zap.Field) {
    entry := &zapcore.Entry{
        Level:   level,
        Message: msg,
        Time:    time.Now(),
        Fields:  fields,
    }
    select {
    case m.logChan <- entry:
    default:
        // Optionally handle the case where the channel is full
    }
}

func (m *Middleware) logWorker() {
    for entry := range m.logChan {
        m.logger.Write(entry)
    }
}

func (m *Middleware) Provision(ctx caddy.Context) error {
    m.logger = ctx.Logger()
    m.logChan = make(chan *zapcore.Entry, 1000)
    go m.logWorker()

    if m.RateLimit.Requests > 0 {
        m.rateLimiter = &RateLimiter{
            config: m.RateLimit,
        }
    }

    if m.CountryBlock.Enabled {
        geoIP, err := maxminddb.Open(m.CountryBlock.GeoIPDBPath)
        if err != nil {
            return fmt.Errorf("failed to load GeoIP database: %v", err)
        }
        m.geoIPCache = &GeoIPCache{
            geoIP: geoIP,
        }
    }

    if err := m.loadRulesFromFiles(); err != nil {
        return err
    }

    if m.IPBlacklistFile != "" {
        if err := m.loadIPBlacklistFromFile(m.IPBlacklistFile); err != nil {
            return fmt.Errorf("failed to load IP blacklist from %s: %v", m.IPBlacklistFile, err)
        }
    }

    if m.DNSBlacklistFile != "" {
        if err := m.loadDNSBlacklistFromFile(m.DNSBlacklistFile); err != nil {
            return fmt.Errorf("failed to load DNS blacklist from %s: %v", m.DNSBlacklistFile, err)
        }
    }

    return nil
}
