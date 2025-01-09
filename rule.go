package caddywaf

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"

	"go.uber.org/zap"
)

// Rule struct
type Rule struct {
	ID          string         `json:"id"`
	Phase       int            `json:"phase"`
	Pattern     string         `json:"pattern"`
	Targets     []string       `json:"targets"`
	Severity    string         `json:"severity"` // Used for logging only
	Score       int            `json:"score"`
	Action      string         `json:"mode"` // Determines the action (block/log)
	Description string         `json:"description"`
	regex       *regexp.Regexp `json:"-"`
}

// loadRules loads rules from files
func LoadRules(paths []string, logger *zap.Logger) (map[int][]Rule, error) {
	rules := make(map[int][]Rule)
	totalRules := 0
	var invalidFiles []string
	var allInvalidRules []string
	ruleIDs := make(map[string]bool) // Track rule IDs across all files

	// Load Rules
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			logger.Error("Failed to read rule file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue
		}

		var fileRules []Rule
		if err := json.Unmarshal(content, &fileRules); err != nil {
			logger.Error("Failed to unmarshal rules from file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue
		}

		var invalidRulesInFile []string
		for i, rule := range fileRules {
			// Validate rule structure
			if err := validateRule(&rule); err != nil {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule at index %d: %v", i, err))
				continue
			}

			// Check for duplicate IDs across all files
			if _, exists := ruleIDs[rule.ID]; exists {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Duplicate rule ID '%s' at index %d", rule.ID, i))
				continue
			}
			ruleIDs[rule.ID] = true

			// Compile regex pattern
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				logger.Error("Failed to compile regex for rule", zap.String("rule_id", rule.ID), zap.String("pattern", rule.Pattern), zap.Error(err))
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule '%s': invalid regex pattern: %v", rule.ID, err))
				continue
			}
			rule.regex = regex

			// Initialize phase if missing
			if _, ok := rules[rule.Phase]; !ok {
				rules[rule.Phase] = []Rule{}
			}

			// Add rule to appropriate phase
			rules[rule.Phase] = append(rules[rule.Phase], rule)
			totalRules++
		}
		if len(invalidRulesInFile) > 0 {
			logger.Warn("Some rules failed validation", zap.String("file", path), zap.Strings("invalid_rules", invalidRulesInFile))
			allInvalidRules = append(allInvalidRules, invalidRulesInFile...)
		}

		logger.Info("Rules loaded", zap.String("file", path), zap.Int("total_rules", len(fileRules)), zap.Int("invalid_rules", len(invalidRulesInFile)))
	}

	if len(invalidFiles) > 0 {
		logger.Warn("Some rule files could not be loaded", zap.Strings("invalid_files", invalidFiles))
	}
	if len(allInvalidRules) > 0 {
		logger.Warn("Some rules across files failed validation", zap.Strings("invalid_rules", allInvalidRules))
	}

	if totalRules == 0 && len(invalidFiles) > 0 {
		return nil, fmt.Errorf("no valid rules were loaded from any file")
	}
	logger.Debug("Rules loaded successfully", zap.Int("total_rules", totalRules))
	return rules, nil
}

// ReloadRules reloads rules from files into a provided map.
func ReloadRules(paths []string, logger *zap.Logger, rulesMap map[int][]Rule, mu *sync.RWMutex) error {
	mu.Lock()
	defer mu.Unlock()

	newRules, err := LoadRules(paths, logger)

	if err != nil {
		return err
	}

	// Swap the old configuration with the new one atomically
	for k := range rulesMap {
		delete(rulesMap, k)
	}
	for k, v := range newRules {
		rulesMap[k] = v
	}

	logger.Info("Rules reloaded successfully")

	return nil
}
