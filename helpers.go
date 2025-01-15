package caddywaf

import (
	"os"
)

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
