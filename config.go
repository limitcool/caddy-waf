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

// parseMetricsEndpoint parses the metrics_endpoint directive.
func (cl *ConfigLoader) parseMetricsEndpoint(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing value for metrics_endpoint", d.File(), d.Line())
	}
	m.MetricsEndpoint = d.Val()
	cl.logger.Debug("Metrics endpoint set from Caddyfile",
		zap.String("metrics_endpoint", m.MetricsEndpoint),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

// parseLogPath parses the log_path directive.
func (cl *ConfigLoader) parseLogPath(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return fmt.Errorf("file: %s, line: %d: missing value for log_path", d.File(), d.Line())
	}
	m.LogFilePath = d.Val()
	cl.logger.Debug("Log path set from Caddyfile",
		zap.String("log_path", m.LogFilePath),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

// parseRateLimit parses the rate_limit directive.
func (cl *ConfigLoader) parseRateLimit(d *caddyfile.Dispenser, m *Middleware) error {
	if m.RateLimit.Requests > 0 {
		return d.Err("rate_limit specified multiple times")
	}

	rl := RateLimit{
		Requests:        100,               // Default requests
		Window:          10 * time.Second,  // Default window
		CleanupInterval: 300 * time.Second, // Default cleanup interval
		MatchAllPaths:   false,             // Default to false
	}

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
			cl.logger.Debug("Rate limit requests set", zap.Int("requests", rl.Requests))

		case "window":
			if !d.NextArg() {
				return d.Err("window requires an argument")
			}
			window, err := time.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid window value: %v", err)
			}
			rl.Window = window
			cl.logger.Debug("Rate limit window set", zap.Duration("window", rl.Window))

		case "cleanup_interval":
			if !d.NextArg() {
				return d.Err("cleanup_interval requires an argument")
			}
			interval, err := time.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid cleanup_interval value: %v", err)
			}
			rl.CleanupInterval = interval
			cl.logger.Debug("Rate limit cleanup interval set", zap.Duration("cleanup_interval", rl.CleanupInterval))

		case "paths":
			paths := d.RemainingArgs()
			if len(paths) == 0 {
				return d.Err("paths requires at least one argument")
			}
			rl.Paths = paths
			cl.logger.Debug("Rate limit paths set", zap.Strings("paths", rl.Paths))

		case "match_all_paths":
			if !d.NextArg() {
				return d.Err("match_all_paths requires an argument")
			}
			matchAllPaths, err := strconv.ParseBool(d.Val())
			if err != nil {
				return d.Errf("invalid match_all_paths value: %v", err)
			}
			rl.MatchAllPaths = matchAllPaths
			cl.logger.Debug("Rate limit match_all_paths set", zap.Bool("match_all_paths", rl.MatchAllPaths))

		default:
			return d.Errf("invalid rate_limit option: %s", d.Val())
		}
	}

	if rl.Requests <= 0 || rl.Window <= 0 {
		return d.Err("requests and window must be greater than zero")
	}

	m.RateLimit = rl
	cl.logger.Debug("Rate limit configuration applied", zap.Any("rate_limit", m.RateLimit))
	return nil
}

func (cl *ConfigLoader) UnmarshalCaddyfile(d *caddyfile.Dispenser, m *Middleware) error {
	if cl.logger == nil {
		cl.logger = zap.NewNop()
	}

	// Initialize TorConfig with default values
	m.Tor = TorConfig{
		Enabled:            false,               // Default to disabled
		TORIPBlacklistFile: "tor_blacklist.txt", // Default file
		UpdateInterval:     "24h",               // Default interval
		RetryOnFailure:     false,               // Default to disabled
		RetryInterval:      "5m",                // Default retry interval
	}

	cl.logger.Debug("WAF UnmarshalCaddyfile Called", zap.String("file", d.File()), zap.Int("line", d.Line()))

	// Set default values
	m.LogSeverity = "info"
	m.LogJSON = false
	m.AnomalyThreshold = 5
	m.CountryBlock.Enabled = false
	m.CountryWhitelist.Enabled = false
	m.LogFilePath = "debug.json"
	m.RedactSensitiveData = false

	for d.Next() {
		for d.NextBlock(0) {
			directive := d.Val()
			cl.logger.Debug("Processing directive", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))

			switch directive {
			case "metrics_endpoint":
				if err := cl.parseMetricsEndpoint(d, m); err != nil {
					return err
				}

			case "log_path":
				if err := cl.parseLogPath(d, m); err != nil {
					return err
				}

			case "rate_limit":
				if err := cl.parseRateLimit(d, m); err != nil {
					return err
				}

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

			case "tor":
				// Handle the tor block as a nested directive
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "enabled":
						if !d.NextArg() {
							return d.ArgErr()
						}
						enabled, err := strconv.ParseBool(d.Val())
						if err != nil {
							return d.Errf("invalid enabled value: %v", err)
						}
						m.Tor.Enabled = enabled
						cl.logger.Debug("Tor blocking enabled", zap.Bool("enabled", m.Tor.Enabled))

					case "tor_ip_blacklist_file": // Updated field name
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Tor.TORIPBlacklistFile = d.Val() // Updated field name
						cl.logger.Debug("Tor IP blacklist file set", zap.String("tor_ip_blacklist_file", m.Tor.TORIPBlacklistFile))

					case "update_interval":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Tor.UpdateInterval = d.Val()
						cl.logger.Debug("Tor update interval set", zap.String("update_interval", m.Tor.UpdateInterval))

					case "retry_on_failure":
						if !d.NextArg() {
							return d.ArgErr()
						}
						retryOnFailure, err := strconv.ParseBool(d.Val())
						if err != nil {
							return d.Errf("invalid retry_on_failure value: %v", err)
						}
						m.Tor.RetryOnFailure = retryOnFailure
						cl.logger.Debug("Tor retry on failure set", zap.Bool("retry_on_failure", m.Tor.RetryOnFailure))

					case "retry_interval":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Tor.RetryInterval = d.Val()
						cl.logger.Debug("Tor retry interval set", zap.String("retry_interval", m.Tor.RetryInterval))

					default:
						return d.Errf("unrecognized tor subdirective: %s", d.Val())
					}
				}

			default:
				cl.logger.Warn("WAF Unrecognized SubDirective", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))
				return fmt.Errorf("file: %s, line: %d: unrecognized subdirective: %s", d.File(), d.Line(), d.Val())
			}
		} // Closing brace for the outer for loop
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
