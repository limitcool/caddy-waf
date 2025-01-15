// rules.go
package caddywaf

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// processRuleMatch handles the logic when a rule is matched.
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

func (m *Middleware) loadRules(paths []string, ipBlacklistPath string, dnsBlacklistPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Loading rules and blacklists from files", zap.Strings("rule_files", paths), zap.String("ip_blacklist", ipBlacklistPath), zap.String("dns_blacklist", dnsBlacklistPath))

	m.Rules = make(map[int][]Rule)
	totalRules := 0
	var invalidFiles []string
	var allInvalidRules []string
	ruleIDs := make(map[string]bool)

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
			if err := validateRule(&rule); err != nil {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule at index %d: %v", i, err))
				continue
			}

			if _, exists := ruleIDs[rule.ID]; exists {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Duplicate rule ID '%s' at index %d", rule.ID, i))
				continue
			}
			ruleIDs[rule.ID] = true

			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				m.logger.Error("Failed to compile regex for rule", zap.String("rule_id", rule.ID), zap.String("pattern", rule.Pattern), zap.Error(err))
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule '%s': invalid regex pattern: %v", rule.ID, err))
				continue
			}
			rule.regex = regex

			if _, ok := m.Rules[rule.Phase]; !ok {
				m.Rules[rule.Phase] = []Rule{}
			}

			m.Rules[rule.Phase] = append(m.Rules[rule.Phase], rule)
			totalRules++
		}
		if len(invalidRulesInFile) > 0 {
			m.logger.Warn("Some rules failed validation", zap.String("file", path), zap.Strings("invalid_rules", invalidRulesInFile))
			allInvalidRules = append(allInvalidRules, invalidRulesInFile...)
		}

		m.logger.Info("Rules loaded", zap.String("file", path), zap.Int("total_rules", len(rules)), zap.Int("invalid_rules", len(invalidRulesInFile)))
	}

	m.ipBlacklist = make(map[string]struct{}) // Changed to map[string]struct{}
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
					continue
				}

				if _, _, err := net.ParseCIDR(line); err == nil {
					m.ipBlacklist[line] = struct{}{} // Changed to struct{}{}
					validEntries++
					m.logger.Debug("Added CIDR range to blacklist", zap.String("cidr", line))
					continue
				}

				if ip := net.ParseIP(line); ip != nil {
					m.ipBlacklist[line] = struct{}{} // Changed to struct{}{}
					validEntries++
					m.logger.Debug("Added IP to blacklist", zap.String("ip", line))
					continue
				}

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

	m.dnsBlacklist = make(map[string]struct{}) // Changed to map[string]struct{}
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
					continue
				}
				m.dnsBlacklist[line] = struct{}{} // Changed to struct{}{}
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
