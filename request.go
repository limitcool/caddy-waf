package caddywaf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RequestValueExtractor struct
type RequestValueExtractor struct {
	logger              *zap.Logger
	redactSensitiveData bool // Add this field
}

// NewRequestValueExtractor creates a new RequestValueExtractor with a given logger
func NewRequestValueExtractor(logger *zap.Logger, redactSensitiveData bool) *RequestValueExtractor {
	return &RequestValueExtractor{logger: logger, redactSensitiveData: redactSensitiveData}
}

func (rve *RequestValueExtractor) ExtractValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty extraction target")
	}

	// If target is a comma separated list, extract values and return them separated by commas.
	if strings.Contains(target, ",") {
		var values []string
		targets := strings.Split(target, ",")
		for _, t := range targets {
			t = strings.TrimSpace(t)
			v, err := rve.extractSingleValue(t, r, w)
			if err == nil {
				values = append(values, v)
			} else {
				rve.logger.Debug("Failed to extract single value from multiple targets.", zap.String("target", t), zap.Error(err))
				// if one extraction fails we continue and don't return an error.
			}
		}
		return strings.Join(values, ","), nil // Returning concatenated values
	}
	return rve.extractSingleValue(target, r, w)
}

func (rve *RequestValueExtractor) extractSingleValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	target = strings.ToUpper(strings.TrimSpace(target))
	var unredactedValue string
	var err error

	// Basic Cases (Keep as Before)
	switch {
	case target == "METHOD":
		unredactedValue = r.Method
	case target == "REMOTE_IP":
		unredactedValue = r.RemoteAddr
	case target == "PROTOCOL":
		unredactedValue = r.Proto
	case target == "HOST":
		unredactedValue = r.Host
	case target == "ARGS":
		if r.URL.RawQuery == "" {
			rve.logger.Debug("Query string is empty", zap.String("target", target))
			return "", fmt.Errorf("query string is empty for target: %s", target)
		}
		unredactedValue = r.URL.RawQuery
	case target == "USER_AGENT":
		unredactedValue = r.UserAgent()
		if unredactedValue == "" {
			rve.logger.Debug("User-Agent is empty", zap.String("target", target))
		}
	case target == "PATH":
		unredactedValue = r.URL.Path
		if unredactedValue == "" {
			rve.logger.Debug("Request path is empty", zap.String("target", target))
		}
	case target == "URI":
		unredactedValue = r.URL.RequestURI()
		if unredactedValue == "" {
			rve.logger.Debug("Request URI is empty", zap.String("target", target))
		}
	case target == "BODY":
		if r.Body == nil {
			rve.logger.Warn("Request body is nil", zap.String("target", target))
			return "", fmt.Errorf("request body is nil for target: %s", target)
		}
		if r.ContentLength == 0 {
			rve.logger.Debug("Request body is empty", zap.String("target", target))
			return "", fmt.Errorf("request body is empty for target: %s", target)
		}
		var bodyBytes []byte
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			rve.logger.Error("Failed to read request body", zap.Error(err))
			return "", fmt.Errorf("failed to read request body for target %s: %w", target, err)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for next read
		unredactedValue = string(bodyBytes)

	// Full Header Dump (Request)
	case target == "HEADERS", target == "REQUEST_HEADERS":
		if len(r.Header) == 0 {
			rve.logger.Debug("Request headers are empty", zap.String("target", target))
			return "", fmt.Errorf("request headers are empty for target: %s", target)
		}
		headers := make([]string, 0)
		for name, values := range r.Header {
			headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
		}
		unredactedValue = strings.Join(headers, "; ")

	// Response Headers (Phase 3)
	case target == "RESPONSE_HEADERS":
		if w == nil {
			return "", fmt.Errorf("response headers not accessible outside Phase 3 for target: %s", target)
		}
		headers := make([]string, 0)
		for name, values := range w.Header() {
			headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
		}
		unredactedValue = strings.Join(headers, "; ")

	// Response Body (Phase 4)
	case target == "RESPONSE_BODY":
		if w == nil {
			return "", fmt.Errorf("response body not accessible outside Phase 4 for target: %s", target)
		}
		if recorder, ok := w.(*responseRecorder); ok {
			if recorder == nil {
				return "", fmt.Errorf("response recorder is nil for target: %s", target)
			}
			if recorder.body.Len() == 0 {
				rve.logger.Debug("Response body is empty", zap.String("target", target))
				return "", fmt.Errorf("response body is empty for target: %s", target)
			}
			unredactedValue = recorder.BodyString()
		} else {
			return "", fmt.Errorf("response recorder not available for target: %s", target)
		}

	// Dynamic Header Extraction (Request)
	case strings.HasPrefix(target, "HEADERS:"), strings.HasPrefix(target, "REQUEST_HEADERS:"):
		headerName := strings.TrimPrefix(strings.TrimPrefix(target, "HEADERS:"), "REQUEST_HEADERS:") // Trim both prefixes
		headerValue := r.Header.Get(headerName)
		if headerValue == "" {
			rve.logger.Debug("Header not found", zap.String("header", headerName))
			return "", fmt.Errorf("header '%s' not found for target: %s", headerName, target)
		}
		unredactedValue = headerValue
	// Dynamic Response Header Extraction (Phase 3)
	case strings.HasPrefix(target, "RESPONSE_HEADERS:"):
		if w == nil {
			return "", fmt.Errorf("response headers not available during this phase for target: %s", target)
		}
		headerName := strings.TrimPrefix(target, "RESPONSE_HEADERS:")
		headerValue := w.Header().Get(headerName)
		if headerValue == "" {
			rve.logger.Debug("Response header not found", zap.String("header", headerName))
			return "", fmt.Errorf("response header '%s' not found for target: %s", headerName, target)
		}
		unredactedValue = headerValue

	// Cookies Extraction
	case target == "COOKIES":
		cookies := make([]string, 0)
		for _, c := range r.Cookies() {
			cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		if len(cookies) == 0 {
			rve.logger.Debug("No cookies found", zap.String("target", target))
			return "", fmt.Errorf("no cookies found for target: %s", target)
		}
		unredactedValue = strings.Join(cookies, "; ")

	case strings.HasPrefix(target, "COOKIES:"):
		cookieName := strings.TrimPrefix(target, "COOKIES:")
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			rve.logger.Debug("Cookie not found", zap.String("cookie", cookieName))
			return "", fmt.Errorf("cookie '%s' not found for target: %s", cookieName, target)
		}
		unredactedValue = cookie.Value

	// URL Parameter Extraction
	case strings.HasPrefix(target, "URL_PARAM:"):
		paramName := strings.TrimPrefix(target, "URL_PARAM:")
		if paramName == "" {
			return "", fmt.Errorf("URL parameter name is empty for target: %s", target)
		}
		if r.URL.Query().Get(paramName) == "" {
			rve.logger.Debug("URL parameter not found", zap.String("parameter", paramName))
			return "", fmt.Errorf("url parameter '%s' not found for target: %s", paramName, target)
		}
		unredactedValue = r.URL.Query().Get(paramName)

	// JSON Path Extraction from Body
	case strings.HasPrefix(target, "JSON_PATH:"):
		jsonPath := strings.TrimPrefix(target, "JSON_PATH:")
		if r.Body == nil {
			rve.logger.Warn("Request body is nil", zap.String("target", target))
			return "", fmt.Errorf("request body is nil for target: %s", target)
		}
		if r.ContentLength == 0 {
			rve.logger.Debug("Request body is empty", zap.String("target", target))
			return "", fmt.Errorf("request body is empty for target: %s", target)
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			rve.logger.Error("Failed to read request body", zap.Error(err))
			return "", fmt.Errorf("failed to read request body for JSON_PATH target %s: %w", target, err)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for next read

		// Use helper method to dynamically extract value based on JSON path (e.g., 'data.items.0.name').
		unredactedValue, err = rve.extractJSONPath(string(bodyBytes), jsonPath)
		if err != nil {
			rve.logger.Debug("Failed to extract value from JSON path", zap.String("target", target), zap.String("path", jsonPath), zap.Error(err))
			return "", fmt.Errorf("failed to extract from JSON path '%s': %w", jsonPath, err)
		}
	// New cases start here:
	case target == "CONTENT_TYPE":
		unredactedValue = r.Header.Get("Content-Type")
		if unredactedValue == "" {
			rve.logger.Debug("Content-Type header not found", zap.String("target", target))
			return "", fmt.Errorf("content-type header not found for target: %s", target)
		}
	case target == "URL":
		unredactedValue = r.URL.String()
		if unredactedValue == "" {
			rve.logger.Debug("URL could not be extracted", zap.String("target", target))
			return "", fmt.Errorf("url could not be extracted for target: %s", target)
		}

	case target == "REQUEST_COOKIES":
		cookies := make([]string, 0)
		for _, c := range r.Cookies() {
			cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		unredactedValue = strings.Join(cookies, "; ")
		if len(cookies) == 0 {
			rve.logger.Debug("No cookies found", zap.String("target", target))
			return "", fmt.Errorf("no cookies found for target: %s", target)
		}

	default:
		rve.logger.Warn("Unknown extraction target", zap.String("target", target))
		return "", fmt.Errorf("unknown extraction target: %s", target)
	}

	// Redact sensitive fields (unchanged)
	value := unredactedValue
	if rve.redactSensitiveData {
		sensitiveTargets := []string{"password", "token", "apikey", "authorization", "secret"}
		for _, sensitive := range sensitiveTargets {
			if strings.Contains(strings.ToLower(target), sensitive) {
				value = "REDACTED"
				break
			}
		}
	}
	rve.logger.Debug("Extracted value",
		zap.String("target", target),
		zap.String("value", value), // Now logging the potentially redacted value
	)
	return unredactedValue, nil // Return the unredacted value for rule matching
}

// Helper function for JSON path extraction.
func (rve *RequestValueExtractor) extractJSONPath(jsonStr string, jsonPath string) (string, error) {
	if jsonStr == "" {
		return "", fmt.Errorf("json string is empty")
	}

	var jsonData interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonData); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// If jsonData is nil or not a valid JSON, return empty string or error.
	if jsonData == nil {
		return "", fmt.Errorf("invalid json data")
	}

	pathParts := strings.Split(jsonPath, ".")
	current := jsonData

	for _, part := range pathParts {
		if current == nil {
			return "", fmt.Errorf("invalid json path, not found '%s'", part)
		}

		switch value := current.(type) {
		case map[string]interface{}:
			if next, ok := value[part]; ok {
				current = next
			} else {
				return "", fmt.Errorf("invalid json path, not found '%s'", part)
			}
		case []interface{}:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				return "", fmt.Errorf("invalid json path, not found '%s'", part)
			}
			current = value[index]
		default:
			return "", fmt.Errorf("invalid path '%s'", part)
		}
	}
	if current == nil {
		return "", fmt.Errorf("invalid path, value is nil '%s'", jsonPath)
	}
	return fmt.Sprintf("%v", current), nil // Convert value to string (if possible)
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logID := uuid.New().String()
	ctx := context.WithValue(r.Context(), "logID", logID)
	r = r.WithContext(ctx)

	// Increment total requests
	m.muMetrics.Lock()
	m.totalRequests++
	m.muMetrics.Unlock()

	state := &WAFState{
		TotalScore:      0,
		Blocked:         false,
		StatusCode:      http.StatusOK,
		ResponseWritten: false,
	}

	// Log the request
	m.logger.Info("WAF evaluation started",
		zap.String("log_id", logID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
		zap.String("query_params", r.URL.RawQuery),
	)

	// Handle phases and blocking logic
	m.handlePhase(w, r, 1, state)
	if state.Blocked {
		m.muMetrics.Lock()
		m.blockedRequests++
		m.muMetrics.Unlock()
		w.WriteHeader(state.StatusCode)
		return nil
	}

	m.handlePhase(w, r, 2, state)
	if state.Blocked {
		m.muMetrics.Lock()
		m.blockedRequests++
		m.muMetrics.Unlock()
		w.WriteHeader(state.StatusCode)
		return nil
	}

	recorder := &responseRecorder{ResponseWriter: w, body: new(bytes.Buffer)}
	err := next.ServeHTTP(recorder, r)

	m.handlePhase(recorder, r, 3, state)
	if state.Blocked {
		m.muMetrics.Lock()
		m.blockedRequests++
		m.muMetrics.Unlock()
		recorder.WriteHeader(state.StatusCode)
		return nil
	}

	if recorder.body != nil {
		body := recorder.body.String()
		m.logger.Debug("Response body captured", zap.String("body", body))

		for _, rule := range m.Rules[4] {
			if rule.regex.MatchString(body) {
				m.processRuleMatch(recorder, r, &rule, body, state)
				if state.Blocked {
					m.muMetrics.Lock()
					m.blockedRequests++
					m.muMetrics.Unlock()
					recorder.WriteHeader(state.StatusCode)
					return nil
				}
			}
		}

		if !state.ResponseWritten {
			_, writeErr := w.Write(recorder.body.Bytes())
			if writeErr != nil {
				m.logger.Error("Failed to write response body", zap.Error(writeErr))
			}
		}
	}

	// Increment allowed requests if not blocked
	if !state.Blocked {
		m.muMetrics.Lock()
		m.allowedRequests++
		m.muMetrics.Unlock()
	}

	if m.MetricsEndpoint != "" && r.URL.Path == m.MetricsEndpoint {
		return m.handleMetricsRequest(w, r)
	}

	m.logger.Info("WAF evaluation complete",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
	)

	return err
}
