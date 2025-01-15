package caddywaf

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// extractIP extracts the IP address from a remote address string.
func extractIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	// Remove brackets from IPv6 addresses
	if strings.HasPrefix(remoteAddr, "[") && strings.HasSuffix(remoteAddr, "]") {
		remoteAddr = strings.TrimPrefix(remoteAddr, "[")
		remoteAddr = strings.TrimSuffix(remoteAddr, "]")
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}

	ip := net.ParseIP(remoteAddr)
	if ip != nil {
		return ip.String()
	}

	return ""
}

// extractPath extracts the path from a http.Request
func extractPath(r *http.Request) string {
	return r.URL.Path
}

// fileExists checks if a file exists and is readable.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
