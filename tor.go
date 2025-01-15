// tor.go
package caddywaf

import (
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

const (
	torExitNodeURL = "https://check.torproject.org/torbulkexitlist"
)

type TorConfig struct {
	Enabled            bool   `json:"enabled,omitempty"`
	TORIPBlacklistFile string `json:"tor_ip_blacklist_file,omitempty"`
	UpdateInterval     string `json:"update_interval,omitempty"`
	RetryOnFailure     bool   `json:"retry_on_failure,omitempty"` // Enable/disable retries
	RetryInterval      string `json:"retry_interval,omitempty"`   // Retry interval (e.g., "5m")
	lastUpdated        time.Time
	logger             *zap.Logger
}

// Provision sets up the Tor blocking configuration.
func (t *TorConfig) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()
	if t.Enabled {
		if err := t.updateTorExitNodes(); err != nil {
			return err
		}
		go t.scheduleUpdates()
	}
	return nil
}

// updateTorExitNodes fetches the latest Tor exit nodes and updates the IP blacklist.
func (t *TorConfig) updateTorExitNodes() error {
	resp, err := http.Get(torExitNodeURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	torIPs := strings.Split(string(data), "\n")
	existingIPs, err := t.readExistingBlacklist()
	if err != nil {
		return err
	}

	// Merge and deduplicate IPs
	allIPs := append(existingIPs, torIPs...)
	sort.Strings(allIPs)
	uniqueIPs := unique(allIPs)

	// Write updated blacklist to file
	if err := t.writeBlacklist(uniqueIPs); err != nil {
		return err
	}

	t.lastUpdated = time.Now()
	t.logger.Info("Updated Tor exit nodes in IP blacklist", zap.Int("count", len(uniqueIPs)))
	return nil
}

// scheduleUpdates periodically updates the Tor exit node list.
// scheduleUpdates periodically updates the Tor exit node list.
func (t *TorConfig) scheduleUpdates() {
	interval, err := time.ParseDuration(t.UpdateInterval)
	if err != nil {
		t.logger.Error("Invalid update interval", zap.String("interval", t.UpdateInterval), zap.Error(err))
		return
	}

	var retryInterval time.Duration
	if t.RetryOnFailure {
		retryInterval, err = time.ParseDuration(t.RetryInterval)
		if err != nil {
			t.logger.Error("Invalid retry interval, disabling retries", zap.String("retry_interval", t.RetryInterval), zap.Error(err))
			t.RetryOnFailure = false // Disable retries if the interval is invalid
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Use for range to iterate over the ticker channel
	for range ticker.C {
		if err := t.updateTorExitNodes(); err != nil {
			if t.RetryOnFailure {
				t.logger.Error("Failed to update Tor exit nodes, retrying shortly", zap.Error(err))
				time.Sleep(retryInterval)
				continue
			} else {
				t.logger.Error("Failed to update Tor exit nodes, will retry at next scheduled interval", zap.Error(err))
			}
		}
	}
}

// readExistingBlacklist reads the current IP blacklist file.
func (t *TorConfig) readExistingBlacklist() ([]string, error) {
	data, err := os.ReadFile(t.TORIPBlacklistFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

// writeBlacklist writes the updated IP blacklist to the file.
func (t *TorConfig) writeBlacklist(ips []string) error {
	data := strings.Join(ips, "\n")
	return os.WriteFile(t.TORIPBlacklistFile, []byte(data), 0644)
}

// unique removes duplicate entries from a slice of strings.
func unique(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result
}
