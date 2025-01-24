package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
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

func TestIsRateLimited_PathMatching(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		Paths:           []string{"/api/.*"},
		MatchAllPaths:   false,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Test path matching
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Path matches
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // second request
	assert.True(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // Third request, rate limited

	// Test path not matching
	assert.False(t, rl.isRateLimited("192.168.1.1", "/other/test")) // Path does not match
}

func TestIsRateLimited_MatchAllPaths(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Test rate limiting for all paths
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // First request
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // Second request
	assert.True(t, rl.isRateLimited("192.168.1.1", "/api/test"))   // Third request, rate limited
	assert.True(t, rl.isRateLimited("192.168.1.1", "/other/test")) // first request to the other path is rate limited
}

func TestIsRateLimited_WindowExpiry(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Test rate limiting within the window
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // First request
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Second request
	assert.True(t, rl.isRateLimited("192.168.1.1", "/api/test"))  // Third request, rate limited

	// Wait for the window to expire
	time.Sleep(time.Second)

	// Test rate limiting after the window expires
	assert.False(t, rl.isRateLimited("192.168.1.1", "/api/test")) // Window expired, counter reset
}

func TestCleanupExpiredEntries(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Add some entries
	rl.isRateLimited("192.168.1.1", "/api/test")
	rl.isRateLimited("192.168.1.2", "/api/test")

	// Wait for the window to expire
	time.Sleep(time.Second)

	// Clean up expired entries
	rl.cleanupExpiredEntries()

	// Verify that entries are cleaned up
	rl.Lock()
	assert.Equal(t, 0, len(rl.requests))
	rl.Unlock()
}

func TestStartCleanup(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Second,
		MatchAllPaths:   true,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Start the cleanup goroutine
	rl.startCleanup()

	// Add some entries
	rl.isRateLimited("192.168.1.1", "/api/test")
	rl.isRateLimited("192.168.1.2", "/api/test")

	// Wait for cleanup to run
	time.Sleep(2 * time.Second)

	// Verify that entries are cleaned up
	rl.Lock()
	assert.Equal(t, 0, len(rl.requests))
	rl.Unlock()

	// Stop the cleanup goroutine
	rl.signalStopCleanup()
}

func TestSignalStopCleanup(t *testing.T) {
	config := RateLimit{
		Requests:        2,
		Window:          time.Second,
		CleanupInterval: time.Second,
		MatchAllPaths:   true,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Start the cleanup goroutine
	rl.startCleanup()

	// Stop the cleanup goroutine
	rl.signalStopCleanup()

	// Verify that the stopCleanup channel is closed
	select {
	case <-rl.stopCleanup:
		// channel was closed correctly
	default:
		t.Error("Expected channel to be closed")

	}
}

func TestConcurrentAccess(t *testing.T) {
	config := RateLimit{
		Requests:        100,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
	}

	rl, err := NewRateLimiter(config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			rl.isRateLimited(ip, "/api/test")
		}("192.168.1." + string(rune(i)))
	}

	wg.Wait()

	// Verify that all requests were processed
	rl.Lock()
	assert.Equal(t, 100, len(rl.requests))
	rl.Unlock()
}

func TestBlockedRequestPhase1_RateLimiting(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: func() *RateLimiter {
			rl, err := NewRateLimiter(RateLimit{
				Requests:        1, // Allow only 1 request
				Window:          time.Minute,
				CleanupInterval: time.Minute,
				Paths:           []string{"/api/.*"}, // Match paths starting with /api
				MatchAllPaths:   false,               // Only match specified paths
			})
			if err != nil {
				t.Fatalf("Failed to create rate limiter: %v", err)
			}
			return rl
		}(),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  NewCIDRTrie(),             // Initialize ipBlacklist
		dnsBlacklist: make(map[string]struct{}), // Initialize dnsBlacklist
	}

	// Simulate two requests from the same IP
	req := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	w2 := httptest.NewRecorder()
	state1 := &WAFState{}
	state2 := &WAFState{}

	// First request (allowed)
	middleware.handlePhase(w1, req, 1, state1)
	assert.False(t, state1.Blocked, "First request should not be blocked")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	// Second request (blocked due to rate limiting)
	middleware.handlePhase(w2, req, 1, state2)
	assert.True(t, state2.Blocked, "Second request should be blocked")
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Expected status code 429")
	assert.Contains(t, w2.Body.String(), "Rate limit exceeded", "Response body should contain 'Rate limit exceeded'")
}
