package caddywaf

import (
	"log"
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
	Requests        int           `json:"requests"`
	Window          time.Duration `json:"window"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// RateLimiter struct
type RateLimiter struct {
	sync.RWMutex
	requests    map[string]*requestCounter
	config      RateLimit
	stopCleanup chan struct{} // Channel to signal cleanup goroutine to stop
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(config RateLimit) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*requestCounter),
		config:   config,
	}
	rl.startCleanup()
	return rl
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

// Stop signals the cleanup goroutine to stop and waits for it to finish.
func (rl *RateLimiter) Stop() {
	if rl.stopCleanup != nil {
		rl.signalStopCleanup()
		// Wait for the cleanup goroutine to exit
		// To be safe, we should wait for the cleanup goroutine to exit,
		// though in our current implementation, the goroutine exits immediately after the close call.
		// However, if more logic was to be added, this approach would protect from closing channels
		// when the goroutine has not exited
		select {
		case <-rl.stopCleanup:
			log.Println("[INFO] Rate limiter cleanup goroutine has exited.")
			return
		case <-time.After(time.Second): // Optional timeout, in case something hangs.
			log.Println("[WARN] Rate limiter cleanup goroutine has not exited in time, continuing anyway.")
			return
		}
	} else {
		log.Println("[INFO] Rate limiter has not started cleanup goroutine, nothing to stop.")
	}
}
