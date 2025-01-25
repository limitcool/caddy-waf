// rules.go
package caddywaf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (m *Middleware) processRuleMatch(w http.ResponseWriter, r *http.Request, rule *Rule, value string, state *WAFState) bool {
	logID := r.Context().Value(ContextKeyLogId("logID")).(string)

	m.logRequest(zapcore.DebugLevel, "Rule Matched", r, // More concise log message
		zap.String("rule_id", string(rule.ID)),
		zap.String("target", strings.Join(rule.Targets, ",")),
		zap.String("value", value),
		zap.String("description", rule.Description),
		zap.Int("score", rule.Score),
		zap.Int("anomaly_threshold_config", m.AnomalyThreshold), // ADDED: Log configured anomaly threshold
		zap.Int("current_anomaly_score", state.TotalScore),      // ADDED: Log current anomaly score before increment
	)

	// Rule Hit Counter - Refactored for clarity
	m.incrementRuleHitCount(RuleID(rule.ID))

	// Metrics for Rule Hits by Phase - Refactored for clarity
	m.incrementRuleHitsByPhaseMetric(rule.Phase)

	oldScore := state.TotalScore
	state.TotalScore += rule.Score
	m.logRequest(zapcore.DebugLevel, "Anomaly score increased", r, // Corrected argument order - 'r' is now the third argument
		zap.String("log_id", logID),
		zap.String("rule_id", string(rule.ID)),
		zap.Int("score_increase", rule.Score),
		zap.Int("old_score", oldScore),
		zap.Int("new_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	shouldBlock := !state.ResponseWritten && (state.TotalScore >= m.AnomalyThreshold || rule.Action == "block")
	blockReason := ""

	if shouldBlock {
		blockReason = "Anomaly threshold exceeded"
		if rule.Action == "block" {
			blockReason = "Rule action is 'block'"
		}
	}

	m.logRequest(zapcore.DebugLevel, "Determining Block Action", r, // More descriptive log message
		zap.String("action", rule.Action),
		zap.Bool("should_block", shouldBlock),
		zap.String("block_reason", blockReason),
		zap.Int("total_score", state.TotalScore),         // ADDED: Log total score in block decision log
		zap.Int("anomaly_threshold", m.AnomalyThreshold), // ADDED: Log anomaly threshold in block decision log
	)

	if shouldBlock {
		m.blockRequest(w, r, state, http.StatusForbidden, blockReason, string(rule.ID), value,
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
			zap.String("final_block_reason", blockReason), // ADDED: Clarify block reason in blockRequest log
		)
		return false
	}

	if rule.Action == "log" {
		m.logRequest(zapcore.InfoLevel, "Rule action: Log", r,
			zap.String("log_id", logID),
			zap.String("rule_id", string(rule.ID)),
			zap.Int("total_score", state.TotalScore),         // ADDED: Log total score for log action
			zap.Int("anomaly_threshold", m.AnomalyThreshold), // ADDED: Log anomaly threshold for log action
		)
	} else if !shouldBlock && !state.ResponseWritten {
		m.logRequest(zapcore.DebugLevel, "Rule action: No Block", r,
			zap.String("log_id", logID),
			zap.String("rule_id", string(rule.ID)),
			zap.String("action", rule.Action),
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
		)
	}

	return true
}

// incrementRuleHitCount increments the hit counter for a given rule ID.
func (m *Middleware) incrementRuleHitCount(ruleID RuleID) {
	hitCount := HitCount(1) // Default increment
	if currentCount, loaded := m.ruleHits.Load(ruleID); loaded {
		hitCount = currentCount.(HitCount) + 1
	}
	m.ruleHits.Store(ruleID, hitCount)
	m.logger.Debug("Rule hit count updated",
		zap.String("rule_id", string(ruleID)),
		zap.Int("hit_count", int(hitCount)), // More descriptive log field
	)
}

// incrementRuleHitsByPhaseMetric increments the rule hits by phase metric.
func (m *Middleware) incrementRuleHitsByPhaseMetric(phase int) {
	m.muMetrics.Lock()
	if m.ruleHitsByPhase == nil {
		m.ruleHitsByPhase = make(map[int]int64)
	}
	m.ruleHitsByPhase[phase]++
	m.muMetrics.Unlock()
}

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

// loadRules updates the RuleCache and Rules map when rules are loaded and sorts rules by priority.
func (m *Middleware) loadRules(paths []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Loading rules", zap.Strings("rule_files", paths))

	loadedRules := make(map[int][]Rule) // Temporary map to hold loaded rules
	totalRules := 0
	invalidFiles := []string{}
	allInvalidRules := []string{}
	ruleIDs := make(map[string]bool)

	for _, path := range paths {
		fileRules, fileInvalidRules, err := m.loadRulesFromFile(path, ruleIDs) // Load rules from a single file
		if err != nil {
			m.logger.Error("Failed to load rule file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue // Skip to the next file if loading fails
		}

		if len(fileInvalidRules) > 0 {
			m.logger.Warn("Invalid rules in file", zap.String("file", path), zap.Strings("errors", fileInvalidRules))
			allInvalidRules = append(allInvalidRules, fileInvalidRules...)
		}
		fileTotalRules := 0
		for phase := 1; phase <= 4; phase++ { // Correctly calculate fileTotalRules
			fileTotalRules += len(fileRules[phase])
		}
		m.logger.Info("Rules loaded from file", zap.String("file", path), zap.Int("valid_rules", fileTotalRules), zap.Int("invalid_rules", len(fileInvalidRules)))

		// Merge valid rules from the file into the temporary loadedRules map
		for phase, rules := range fileRules {
			loadedRules[phase] = append(loadedRules[phase], rules...)
		}
		totalRules += fileTotalRules // Update total rule count with fileTotalRules
	}

	m.Rules = loadedRules // Atomically update m.Rules after loading all files

	if len(invalidFiles) > 0 {
		m.logger.Error("Failed to load rule files", zap.Strings("files", invalidFiles)) // Error level for file loading failures
	}
	if len(allInvalidRules) > 0 {
		m.logger.Warn("Validation errors in rules", zap.Strings("errors", allInvalidRules)) // More specific log message - "errors" field
	}

	if totalRules == 0 && len(paths) > 0 { // Only return error if paths were provided
		return fmt.Errorf("no valid rules were loaded from any file")
	} else if totalRules == 0 && len(paths) == 0 {
		m.logger.Warn("No rule files specified, WAF will run without rules.") // Warn if no rule files and no rules loaded
	}

	m.logger.Info("WAF rules loaded successfully", zap.Int("total_rules", totalRules))
	return nil
}

// loadRulesFromFile loads and validates rules from a single file.
func (m *Middleware) loadRulesFromFile(path string, ruleIDs map[string]bool) (validRules map[int][]Rule, invalidRules []string, err error) {
	m.logger.Debug("Loading rules from file", zap.String("file", path)) // Log file being loaded
	validRules = make(map[int][]Rule)
	var fileInvalidRules []string

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read rule file: %w", err)
	}

	var rules []Rule
	if err := json.Unmarshal(content, &rules); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	// Sort rules by priority (higher priority first)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	for i, rule := range rules {
		if err := validateRule(&rule); err != nil {
			fileInvalidRules = append(fileInvalidRules, fmt.Sprintf("Rule at index %d: %v", i, err))
			continue
		}

		if _, exists := ruleIDs[string(rule.ID)]; exists {
			fileInvalidRules = append(fileInvalidRules, fmt.Sprintf("Duplicate rule ID '%s' at index %d", rule.ID, i))
			continue
		}
		ruleIDs[string(rule.ID)] = true // Track rule IDs to prevent duplicates

		// RuleCache handling (compile and cache regex)
		if cachedRegex, exists := m.ruleCache.Get(rule.ID); exists {
			rule.regex = cachedRegex
		} else {
			compiledRegex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				fileInvalidRules = append(fileInvalidRules, fmt.Sprintf("Rule '%s': invalid regex pattern: %v", rule.ID, err))
				continue
			}
			rule.regex = compiledRegex
			m.ruleCache.Set(rule.ID, compiledRegex) // Cache regex
		}

		if _, ok := validRules[rule.Phase]; !ok {
			validRules[rule.Phase] = []Rule{}
		}
		validRules[rule.Phase] = append(validRules[rule.Phase], rule)
	}

	ruleCounts := ""
	for phase := 1; phase <= 4; phase++ {
		ruleCounts += fmt.Sprintf("Phase %d: %d rules, ", phase, len(validRules[phase]))
	}
	m.logger.Debug("Rules loaded from file by phase", zap.String("file", path), zap.String("counts", ruleCounts)) // Log rules count per phase

	return validRules, fileInvalidRules, nil
}
