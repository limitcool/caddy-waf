package caddywaf

import (
	"log"
	"regexp"
	"sync"
	"time"
)

// requestCounter struct
type requestCounter struct {
	count  int
	window time.Time
}

// RateLimit struct
type RateLimit struct {
	Requests        int              `json:"requests"`
	Window          time.Duration    `json:"window"`
	CleanupInterval time.Duration    `json:"cleanup_interval"`
	Paths           []string         `json:"paths,omitempty"` // New: optional paths to apply rate limit
	PathRegexes     []*regexp.Regexp `json:"-"`               // New: compiled regexes for the given paths
	MatchAllPaths   bool             `json:"match_all_paths,omitempty"`
}

// RateLimiter struct
type RateLimiter struct {
	sync.RWMutex
	requests    map[string]*requestCounter
	config      RateLimit
	stopCleanup chan struct{} // Channel to signal cleanup goroutine to stop
}

// NewRateLimiter creates a new RateLimiter
func NewRateLimiter(config RateLimit) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string]*requestCounter),
		config:   config,
	}
}

// isRateLimited checks if a given IP is rate limited.
func (rl *RateLimiter) isRateLimited(ip string) bool {
	now := time.Now()

	rl.Lock()
	defer rl.Unlock()

	counter, exists := rl.requests[ip]
	if exists {
		if now.Sub(counter.window) > rl.config.Window {
			// Window expired, reset the counter
			rl.requests[ip] = &requestCounter{count: 1, window: now}
			return false
		}

		// Window not expired, increment the counter
		counter.count++
		return counter.count > rl.config.Requests
	}

	// IP doesn't exist, add it
	rl.requests[ip] = &requestCounter{count: 1, window: now}
	return false
}

// cleanupExpiredEntries removes expired entries from the rate limiter.
func (rl *RateLimiter) cleanupExpiredEntries() {
	now := time.Now()
	var expiredIPs []string

	// Collect expired IPs to delete (read lock)
	rl.RLock()
	for ip, counter := range rl.requests {
		if now.Sub(counter.window) > rl.config.Window {
			expiredIPs = append(expiredIPs, ip)
		}
	}
	rl.RUnlock()

	// Delete expired IPs (write lock)
	if len(expiredIPs) > 0 {
		rl.Lock()
		for _, ip := range expiredIPs {
			delete(rl.requests, ip)
		}
		rl.Unlock()
	}
}

// startCleanup starts the goroutine to periodically clean up expired entries.
func (rl *RateLimiter) startCleanup() {
	// Ensure stopCleanup channel is created only once
	if rl.stopCleanup == nil {
		rl.stopCleanup = make(chan struct{})
	}

	go func() {
		log.Println("[INFO] Starting rate limiter cleanup goroutine") // Added logging
		ticker := time.NewTicker(rl.config.CleanupInterval)           // Use the specified cleanup interval
		defer func() {
			ticker.Stop()
			log.Println("[INFO] Rate limiter cleanup goroutine stopped") // Added logging on exit
		}()
		for {
			select {
			case <-ticker.C:
				rl.cleanupExpiredEntries()
			case <-rl.stopCleanup:
				return
			}
		}
	}()
}

// signalStopCleanup signals the cleanup goroutine to stop.
func (rl *RateLimiter) signalStopCleanup() {
	if rl.stopCleanup != nil {
		log.Println("[INFO] Signaling rate limiter cleanup goroutine to stop") // Added logging
		close(rl.stopCleanup)
		// We avoid setting rl.stopCleanup to nil here for maximum safety.
		// Subsequent calls to signalStopCleanup will still be protected by the nil check.
	}
}
