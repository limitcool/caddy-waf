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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	fmt.Println("Registering WAF Middleware")
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
	fmt.Println("WAF Middleware Registered Successfully")
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

// Rule represents a WAF rule
type Rule struct {
	ID       string   `json:"id"`
	Phase    int      `json:"phase"`
	Pattern  string   `json:"pattern"`
	Targets  []string `json:"targets"`
	Severity string   `json:"severity"`
	Action   string   `json:"action"`
	Score    int      `json:"score"`
	regex    *regexp.Regexp
}

// Middleware handles WAF rules and blocklists
type Middleware struct {
	RuleFiles      []string `json:"rule_files"`
	IPBlacklistFile    string    `json:"ip_blacklist_file"`
	DNSBlacklistFile  string    `json:"dns_blacklist_file"`
	LogAll         bool     `json:"log_all"`
	AnomalyThreshold int    `json:"anomaly_threshold"`
	Rules          []Rule   `json:"-"`
	logger         *zap.Logger
	ipBlacklist     map[string]bool `json:"-"`
	dnsBlacklist    []string        `json:"-"`
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return &Middleware{} }, // Return pointer here
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return &m, nil // Return &m, a pointer to m

}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

        totalScore := 0

	// Check IP Blacklist
	if m.isIPBlacklisted(r.RemoteAddr) {
                m.logger.Info("Request blocked by IP blacklist", zap.String("ip", r.RemoteAddr))
		w.WriteHeader(http.StatusForbidden)
		return nil
	}

	// Check DNS Blacklist
    if m.isDNSBlacklisted(r.Host){
                m.logger.Info("Request blocked by DNS blacklist", zap.String("domain", r.Host))
            w.WriteHeader(http.StatusForbidden)
		return nil
    }


    for _, rule := range m.Rules {
        for _, target := range rule.Targets {
            value, _ := m.extractValue(target, r)

            if rule.regex.MatchString(value) {
                    totalScore += rule.Score
                    m.logger.Info("Rule Matched",
                         zap.String("rule_id", rule.ID),
                         zap.String("target", target),
                         zap.String("value", value))
                    if rule.Action == "block" {
                        w.WriteHeader(http.StatusForbidden)
                        return nil
                    }
            }
        }
    }

        if totalScore >= m.AnomalyThreshold {
            w.WriteHeader(http.StatusForbidden)
            return nil
        }
        return next.ServeHTTP(w, r)
}


func (m *Middleware) isIPBlacklisted(remoteAddr string) bool {
	if m.ipBlacklist == nil || len(m.ipBlacklist) == 0 {
		return false
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
        if m.ipBlacklist[ip]{
                return true
        }
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false // if it is an invalid IP address we skip the check
	}

        for blacklistIP := range m.ipBlacklist {
        	_, ipNet, err := net.ParseCIDR(blacklistIP)

                if err != nil {
                        // if is not a subnet, check as a single ip
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
	default:
		return "", fmt.Errorf("unknown target: %s", target)
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
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
                if ip != "" { // skip empty lines
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

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    fmt.Println("WAF UnmarshalCaddyfile Called")
    for d.Next() {
        // Skip the directive name itself
        for d.NextBlock(0) {
            switch d.Val() {
            case "log_all":
                                fmt.Println("WAF Log All Enabled")
                m.LogAll = true
            case "rule_file":
                                fmt.Println("WAF Loading Rule File")
                if !d.NextArg() {
                                        fmt.Println("WAF Missing Argument for rule file")
                    return d.ArgErr()
                }
                                fmt.Println("WAF Loading Rule File at path: ", d.Val())
                m.RuleFiles = append(m.RuleFiles, d.Val())
            case "ip_blacklist_file":
                                fmt.Println("WAF Loading IP Blacklist File")
                                if !d.NextArg() {
                                        fmt.Println("WAF Missing Argument for IP Blacklist file")
                                        return d.ArgErr()
                                }
                                fmt.Println("WAF Loading IP Blacklist File at path: ", d.Val())
                                m.IPBlacklistFile = d.Val()
                        case "dns_blacklist_file":
                                fmt.Println("WAF Loading DNS Blacklist File")
                                if !d.NextArg() {
                                        fmt.Println("WAF Missing Argument for DNS Blacklist File")
                                        return d.ArgErr()
                                }
                                fmt.Println("WAF Loading DNS Blacklist File at path: ", d.Val())
                                m.DNSBlacklistFile = d.Val()
            default:
                                fmt.Println("WAF Unrecognized SubDirective: ", d.Val())
                return d.Errf("unrecognized subdirective: %s", d.Val())
            }
         }
    }
        fmt.Println("WAF UnmarshalCaddyfile Completed")
    return nil
}