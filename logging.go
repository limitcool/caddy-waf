package caddywaf

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const unknownValue = "unknown" // Define a constant for "unknown" values

var sensitiveKeys = []string{"password", "token", "apikey", "authorization", "secret"} // Define sensitive keys for redaction as package variable

func (m *Middleware) logRequest(level zapcore.Level, msg string, r *http.Request, fields ...zap.Field) {
	if m.logger == nil || level < m.logLevel {
		return // Early return if logger is nil or level is below threshold
	}

	allFields := m.prepareLogFields(r, fields) // Prepare all fields in one function - Corrected call: Removed 'level'

	// Send the log entry to the buffered channel
	select {
	case m.logChan <- LogEntry{Level: level, Message: msg, Fields: allFields}:
		// Log entry successfully queued
	default:
		// If the channel is full, fall back to synchronous logging
		m.logger.Warn("Log buffer full, falling back to synchronous logging",
			zap.String("message", msg),
			zap.Any("fields", allFields),
		)
		m.logger.Log(level, msg, allFields...)
	}
}

// prepareLogFields consolidates the logic for preparing log fields, including common fields and log_id.
func (m *Middleware) prepareLogFields(r *http.Request, fields []zap.Field) []zap.Field { // Corrected signature: Removed 'level zapcore.Level'
	var logID string
	var customFields []zap.Field

	// Extract log_id if present, otherwise generate a new one
	logID, customFields = m.extractLogIDField(fields)
	if logID == "" {
		logID = uuid.New().String()
	}

	// Get common log fields and merge with custom fields, prioritizing custom fields in case of duplicates
	commonFields := m.getCommonLogFields(r)
	allFields := m.mergeFields(customFields, commonFields, zap.String("log_id", logID)) // Ensure log_id is always present

	return allFields
}

// extractLogIDField extracts the log_id from the given fields and returns it along with the remaining fields.
func (m *Middleware) extractLogIDField(fields []zap.Field) (logID string, remainingFields []zap.Field) {
	for _, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
		} else {
			remainingFields = append(remainingFields, field)
		}
	}
	return logID, remainingFields
}

// mergeFields merges custom fields and common fields, with custom fields taking precedence and ensuring log_id is present.
func (m *Middleware) mergeFields(customFields []zap.Field, commonFields []zap.Field, logIDField zap.Field) []zap.Field {
	mergedFields := make([]zap.Field, 0, len(customFields)+len(commonFields)+1) //预分配容量
	mergedFields = append(mergedFields, customFields...)

	// Add common fields, skip if key already exists in custom fields
	for _, commonField := range commonFields {
		exists := false
		for _, customField := range customFields {
			if commonField.Key == customField.Key {
				exists = true
				break
			}
		}
		if !exists {
			mergedFields = append(mergedFields, commonField)
		}
	}

	mergedFields = append(mergedFields, logIDField) // Ensure log_id is always last or at least present
	return mergedFields
}

func (m *Middleware) getCommonLogFields(r *http.Request) []zap.Field {
	sourceIP := unknownValue
	userAgent := unknownValue
	requestMethod := unknownValue
	requestPath := unknownValue
	queryParams := "" // Initialize to empty string, not "unknown" - More accurate for query params
	statusCode := 0   // Default status code is 0 if not explicitly set

	if r != nil {
		sourceIP = r.RemoteAddr
		userAgent = r.UserAgent()
		requestMethod = r.Method
		requestPath = r.URL.Path
		queryParams = r.URL.RawQuery
	}

	if m.RedactSensitiveData {
		queryParams = m.redactQueryParams(queryParams)
	}

	return []zap.Field{
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
		zap.Time("timestamp", time.Now()),
	}
}

func (m *Middleware) redactQueryParams(queryParams string) string {
	if queryParams == "" {
		return ""
	}

	parts := strings.Split(queryParams, "&")
	for i, part := range parts {
		if strings.Contains(part, "=") {
			keyValue := strings.SplitN(part, "=", 2)
			if len(keyValue) == 2 {
				key := strings.ToLower(keyValue[0])
				if m.isSensitiveQueryParamKey(key) { // Use helper function for sensitive key check
					parts[i] = keyValue[0] + "=REDACTED"
				}
			}
		}
	}
	return strings.Join(parts, "&")
}

func (m *Middleware) isSensitiveQueryParamKey(key string) bool {
	for _, sensitiveKey := range sensitiveKeys { // Use package level sensitiveKeys variable
		if strings.Contains(key, sensitiveKey) {
			return true
		}
	}
	return false
}

func caddyTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006/01/02 15:04:05.000"))
}

// LogEntry represents a single log entry to be processed asynchronously.
type LogEntry struct {
	Level   zapcore.Level
	Message string
	Fields  []zap.Field
}

// StartLogWorker initializes the background logging worker.
func (m *Middleware) StartLogWorker() {
	m.logChan = make(chan LogEntry, 1000) // Buffer size can be adjusted
	m.logDone = make(chan struct{})

	go func() {
		for entry := range m.logChan {
			m.logger.Log(entry.Level, entry.Message, entry.Fields...)
		}
		close(m.logDone) // Signal that the worker has finished
	}()
}

// StopLogWorker stops the background logging worker.
func (m *Middleware) StopLogWorker() {
	close(m.logChan) // Close the channel to stop the worker
	<-m.logDone      // Wait for the worker to finish processing
}
