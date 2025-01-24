package caddywaf

import (
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	tests := []struct {
		name    string
		config  RateLimit
		wantErr bool
	}{
		{
			name: "valid config without paths",
			config: RateLimit{
				Requests:        100,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid config with paths",
			config: RateLimit{
				Requests:        100,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
				Paths:           []string{`^/api/.*$`},
			},
			wantErr: false,
		},
		{
			name: "invalid path regex",
			config: RateLimit{
				Requests:        100,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
				Paths:           []string{`[invalid`},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl, err := NewRateLimiter(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRateLimiter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && rl == nil {
				t.Error("NewRateLimiter() returned nil but wanted valid RateLimiter")
			}
		})
	}
}

func TestRateLimiter_isRateLimited(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Second,
		Paths:           []string{`^/api/.*$`},
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create RateLimiter: %v", err)
	}

	tests := []struct {
		name     string
		ip       string
		path     string
		calls    int
		expected bool
	}{
		{
			name:     "under limit",
			ip:       "1.1.1.1",
			path:     "/api/test",
			calls:    1,
			expected: false,
		},
		{
			name:     "at limit",
			ip:       "2.2.2.2",
			path:     "/api/test",
			calls:    2,
			expected: false,
		},
		{
			name:     "over limit",
			ip:       "3.3.3.3",
			path:     "/api/test",
			calls:    3,
			expected: true,
		},
		{
			name:     "non-matching path",
			ip:       "4.4.4.4",
			path:     "/other",
			calls:    3,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var limited bool
			for i := 0; i < tt.calls; i++ {
				limited = rl.isRateLimited(tt.ip, tt.path)
			}
			if limited != tt.expected {
				t.Errorf("isRateLimited() = %v, want %v", limited, tt.expected)
			}
		})
	}
}

func TestRateLimiter_cleanupExpiredEntries(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create RateLimiter: %v", err)
	}

	// Add some entries
	rl.isRateLimited("1.1.1.1", "/test")
	rl.isRateLimited("2.2.2.2", "/test")

	// Wait for window to expire
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup
	rl.cleanupExpiredEntries()

	rl.RLock()
	count := len(rl.requests)
	rl.RUnlock()

	if count != 0 {
		t.Errorf("cleanupExpiredEntries() failed, got %d entries, want 0", count)
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create RateLimiter: %v", err)
	}

	rl.startCleanup()
	rl.isRateLimited("1.1.1.1", "/test")

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	rl.signalStopCleanup()

	// Verify entries were cleaned up
	rl.RLock()
	count := len(rl.requests)
	rl.RUnlock()

	if count != 0 {
		t.Errorf("Cleanup failed, got %d entries, want 0", count)
	}
}
