package caddywaf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

// ConfigLoader structure to encapsulate loading and parsing logic
type ConfigLoader struct {
	logger *zap.Logger
}

func NewConfigLoader(logger *zap.Logger) *ConfigLoader {
	return &ConfigLoader{logger: logger}
}

func (cl *ConfigLoader) UnmarshalCaddyfile(d *caddyfile.Dispenser, m *Middleware) error {
	if cl.logger == nil {
		cl.logger = zap.NewNop()
	}

	cl.logger.Debug("WAF UnmarshalCaddyfile Called", zap.String("file", d.File()), zap.Int("line", d.Line()))

	// Explicitly set default values
	m.LogSeverity = "info"
	m.LogJSON = false
	m.AnomalyThreshold = 5
	m.CountryBlock.Enabled = false
	m.CountryWhitelist.Enabled = false
	m.LogFilePath = "debug.json"
	m.RedactSensitiveData = false // Initialize with default value
	for d.Next() {
		for d.NextBlock(0) {
			directive := d.Val()
			cl.logger.Debug("Processing directive", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))

			switch directive {
			case "metrics_endpoint":
				if !d.NextArg() {
					return fmt.Errorf("file: %s, line: %d: missing value for metrics_endpoint", d.File(), d.Line())
				}
				m.MetricsEndpoint = d.Val()
				cl.logger.Debug("Metrics endpoint set from Caddyfile",
					zap.String("metrics_endpoint", m.MetricsEndpoint),
					zap.String("file", d.File()),
					zap.Int("line", d.Line()),
				)
			case "log_path":
				if !d.NextArg() {
					return fmt.Errorf("file: %s, line: %d: missing value for log_path", d.File(), d.Line())
				}
				m.LogFilePath = d.Val()
				cl.logger.Debug("Log path set from Caddyfile",
					zap.String("log_path", m.LogFilePath),
					zap.String("file", d.File()),
					zap.Int("line", d.Line()),
				)
			case "rate_limit":
				if m.RateLimit.Requests > 0 {
					return d.Err("rate_limit specified multiple times")
				}

				rl := RateLimit{}
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "requests":
						if !d.NextArg() {
							return d.Err("requests requires an argument")
						}
						reqs, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid requests value: %v", err)
						}
						rl.Requests = reqs
					case "window":
						if !d.NextArg() {
							return d.Err("window requires an argument")
						}
						window, err := time.ParseDuration(d.Val())
						if err != nil {
							return d.Errf("invalid window value: %v", err)
						}
						rl.Window = window
					case "cleanup_interval":
						if !d.NextArg() {
							return d.Err("cleanup_interval requires an argument")
						}
						interval, err := time.ParseDuration(d.Val())
						if err != nil {
							return d.Errf("invalid cleanup_interval value: %v", err)
						}
						rl.CleanupInterval = interval
					case "paths":
						rl.Paths = d.RemainingArgs()
					case "match_all_paths":
						rl.MatchAllPaths = true
					default:
						return d.Errf("invalid rate_limit option: %s", d.Val())
					}
				}
				if rl.Requests <= 0 || rl.Window <= 0 {
					return d.Err("requests and window must be greater than zero")
				}
				// Create temporary RateLimit struct with basic fields only
				m.RateLimit = RateLimit{
					Requests:        rl.Requests,
					Window:          rl.Window,
					CleanupInterval: rl.CleanupInterval,
					Paths:           rl.Paths,
					MatchAllPaths:   rl.MatchAllPaths,
				}
				cl.logger.Debug("Rate limit parsed", zap.Any("rate_limit", m.RateLimit))
			case "block_countries":
				if err := cl.parseCountryBlock(d, m, true); err != nil {
					return err
				}
			case "whitelist_countries":
				if err := cl.parseCountryBlock(d, m, false); err != nil {
					return err
				}
			case "log_severity":
				if err := cl.parseLogSeverity(d, m); err != nil {
					return err
				}
			case "log_json":
				m.LogJSON = true
				cl.logger.Debug("Log JSON enabled", zap.String("file", d.File()), zap.Int("line", d.Line()))
			case "rule_file":
				if err := cl.parseRuleFile(d, m); err != nil {
					return err
				}
			case "ip_blacklist_file":
				if err := cl.parseBlacklistFile(d, m, true); err != nil {
					return err
				}
			case "dns_blacklist_file":
				if err := cl.parseBlacklistFile(d, m, false); err != nil {
					return err
				}
			case "anomaly_threshold":
				if err := cl.parseAnomalyThreshold(d, m); err != nil {
					return err
				}
			case "custom_response":
				if err := cl.parseCustomResponse(d, m); err != nil {
					return err
				}
			case "redact_sensitive_data":
				m.RedactSensitiveData = true
				cl.logger.Debug("Redact sensitive data enabled", zap.String("file", d.File()), zap.Int("line", d.Line()))
			default:
				cl.logger.Warn("WAF Unrecognized SubDirective", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))
				return fmt.Errorf("file: %s, line: %d: unrecognized subdirective: %s", d.File(), d.Line(), d.Val())
			}
		}
	}
	if len(m.RuleFiles) == 0 {
		return fmt.Errorf("no rule files specified")
	}
	return nil
}
func (cl *ConfigLoader) parseRuleFile(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing path for rule_file", d.File(), d.Line())
	}
	ruleFile := d.Val()
	m.RuleFiles = append(m.RuleFiles, ruleFile)

	if m.MetricsEndpoint != "" && !strings.HasPrefix(m.MetricsEndpoint, "/") {
		return fmt.Errorf("metrics_endpoint must start with '/'")
	}
	cl.logger.Info("WAF Loading Rule File",
		zap.String("file", ruleFile),
		zap.String("caddyfile", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

func (cl *ConfigLoader) parseCustomResponse(d *caddyfile.Dispenser, m *Middleware) error {
	if m.CustomResponses == nil {
		m.CustomResponses = make(map[int]CustomBlockResponse)
	}

	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing status code for custom_response", d.File(), d.Line())
	}
	statusCode, err := strconv.Atoi(d.Val())
	if err != nil {
		return fmt.Errorf("file: %s, line: %d: invalid status code for custom_response: %v", d.File(), d.Line(), err)
	}

	if m.CustomResponses[statusCode].Headers == nil {
		m.CustomResponses[statusCode] = CustomBlockResponse{
			StatusCode: statusCode,
			Headers:    make(map[string]string),
		}
	}

	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing content_type or file path for custom_response", d.File(), d.Line())
	}
	contentTypeOrFile := d.Val()

	if d.NextArg() {
		filePath := d.Val()
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("file: %s, line: %d: could not read custom response file '%s': %v", d.File(), d.Line(), filePath, err)
		}
		m.CustomResponses[statusCode] = CustomBlockResponse{
			StatusCode: statusCode,
			Headers: map[string]string{
				"Content-Type": contentTypeOrFile,
			},
			Body: string(content),
		}
		cl.logger.Debug("Loaded custom response from file",
			zap.Int("status_code", statusCode),
			zap.String("file", filePath),
			zap.String("content_type", contentTypeOrFile),
			zap.String("caddyfile", d.File()),
			zap.Int("line", d.Line()),
		)
	} else {
		remaining := d.RemainingArgs()
		if len(remaining) == 0 {
			return fmt.Errorf("file: %s, line: %d: missing custom response body", d.File(), d.Line())
		}
		body := strings.Join(remaining, " ")
		m.CustomResponses[statusCode] = CustomBlockResponse{
			StatusCode: statusCode,
			Headers: map[string]string{
				"Content-Type": contentTypeOrFile,
			},
			Body: body,
		}
		cl.logger.Debug("Loaded inline custom response",
			zap.Int("status_code", statusCode),
			zap.String("content_type", contentTypeOrFile),
			zap.String("body", body),
			zap.String("caddyfile", d.File()),
			zap.Int("line", d.Line()),
		)
	}
	return nil
}

func (cl *ConfigLoader) parseCountryBlock(d *caddyfile.Dispenser, m *Middleware, isBlock bool) error {
	target := &m.CountryBlock
	if !isBlock {
		target = &m.CountryWhitelist
	}
	target.Enabled = true

	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing GeoIP DB path", d.File(), d.Line())
	}
	target.GeoIPDBPath = d.Val()
	target.CountryList = []string{}

	for d.NextArg() {
		country := strings.ToUpper(d.Val())
		target.CountryList = append(target.CountryList, country)
	}

	cl.logger.Debug("Country list configured",
		zap.Bool("block_mode", isBlock),
		zap.Strings("countries", target.CountryList),
		zap.String("geoip_db_path", target.GeoIPDBPath),
		zap.String("file", d.File()), zap.Int("line", d.Line()),
	)
	return nil
}

func (cl *ConfigLoader) parseLogSeverity(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing value for log_severity", d.File(), d.Line())
	}
	m.LogSeverity = d.Val()
	cl.logger.Debug("Log severity set",
		zap.String("severity", m.LogSeverity),
		zap.String("file", d.File()), zap.Int("line", d.Line()),
	)
	return nil
}

func (cl *ConfigLoader) parseBlacklistFile(d *caddyfile.Dispenser, m *Middleware, isIP bool) error {
	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing blacklist file path", d.File(), d.Line())
	}
	if isIP {
		m.IPBlacklistFile = d.Val()
	} else {
		m.DNSBlacklistFile = d.Val()
	}
	cl.logger.Info("Blacklist file loaded", zap.String("file", d.Val()), zap.Bool("is_ip", isIP))
	return nil
}

func (cl *ConfigLoader) parseAnomalyThreshold(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing threshold value", d.File(), d.Line())
	}
	threshold, err := strconv.Atoi(d.Val())
	if err != nil {
		return fmt.Errorf("file: %s, line: %d: invalid threshold: %v", d.File(), d.Line(), err)
	}
	m.AnomalyThreshold = threshold
	cl.logger.Debug("Anomaly threshold set", zap.Int("threshold", threshold))
	return nil
}
