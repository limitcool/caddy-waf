package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestExtractValue(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, true)

	tests := []struct {
		name          string
		target        string
		setupRequest  func() (*http.Request, http.ResponseWriter)
		expectedValue string
		expectedError bool
	}{
		{
			name:   "Extract METHOD",
			target: "METHOD",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("POST", "http://example.com", nil)
				return req, httptest.NewRecorder()
			},
			expectedValue: "POST",
			expectedError: false,
		},
		{
			name:   "Extract PATH",
			target: "PATH",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com/test/path", nil)
				return req, httptest.NewRecorder()
			},
			expectedValue: "/test/path",
			expectedError: false,
		},
		{
			name:   "Extract USER_AGENT",
			target: "USER_AGENT",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("User-Agent", "test-agent")
				return req, httptest.NewRecorder()
			},
			expectedValue: "test-agent",
			expectedError: false,
		},
		{
			name:   "Extract HEADERS prefix",
			target: "HEADERS:Content-Type",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Content-Type", "application/json")
				return req, httptest.NewRecorder()
			},
			expectedValue: "application/json",
			expectedError: false,
		},
		{
			name:   "Extract multiple targets",
			target: "METHOD,PATH",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				return req, httptest.NewRecorder()
			},
			expectedValue: "GET,/test",
			expectedError: false,
		},
		{
			name:   "Empty target",
			target: "",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				return httptest.NewRequest("GET", "http://example.com", nil), httptest.NewRecorder()
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, w := tt.setupRequest()
			value, err := rve.ExtractValue(tt.target, req, w)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectedError && value != tt.expectedValue {
				t.Errorf("Expected value %q but got %q", tt.expectedValue, value)
			}
		})
	}
}

func TestRedactValueIfSensitive(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name             string
		redactSensitive  bool
		target           string
		value            string
		expectedRedacted bool
	}{
		{
			name:             "Sensitive target with redaction enabled",
			redactSensitive:  true,
			target:           "password",
			value:            "secret123",
			expectedRedacted: true,
		},
		{
			name:             "Sensitive target with redaction disabled",
			redactSensitive:  false,
			target:           "password",
			value:            "secret123",
			expectedRedacted: false,
		},
		{
			name:             "Non-sensitive target",
			redactSensitive:  true,
			target:           "username",
			value:            "user123",
			expectedRedacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rve := NewRequestValueExtractor(logger, tt.redactSensitive)
			result := rve.redactValueIfSensitive(tt.target, tt.value)

			if tt.expectedRedacted && result != "REDACTED" {
				t.Errorf("Expected REDACTED but got %q", result)
			}
			if !tt.expectedRedacted && result != tt.value {
				t.Errorf("Expected %q but got %q", tt.value, result)
			}
		})
	}
}
