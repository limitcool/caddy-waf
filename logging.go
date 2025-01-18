// logging.go
package caddywaf

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (m *Middleware) logRequest(level zapcore.Level, msg string, r *http.Request, fields ...zap.Field) {
	if m.logger == nil {
		return
	}

	// Skip logging if the level is below the threshold
	if level < m.logLevel {
		return
	}

	// Extract log ID or generate a new one
	var logID string
	var newFields []zap.Field
	foundLogID := false

	for _, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
			foundLogID = true
		} else {
			newFields = append(newFields, field)
		}
	}

	if !foundLogID {
		logID = uuid.New().String()
	}

	// Append log_id explicitly to newFields
	newFields = append(newFields, zap.String("log_id", logID))

	// Attach common request metadata only if not already set
	commonFields := m.getCommonLogFields(r, newFields)
	for _, commonField := range commonFields {
		fieldExists := false
		for _, existingField := range newFields {
			if existingField.Key == commonField.Key {
				fieldExists = true
				break
			}
		}
		if !fieldExists {
			newFields = append(newFields, commonField)
		}
	}

	// Send the log entry to the buffered channel
	select {
	case m.logChan <- LogEntry{Level: level, Message: msg, Fields: newFields}:
		// Log entry successfully queued
	default:
		// If the channel is full, fall back to synchronous logging
		m.logger.Warn("Log buffer full, falling back to synchronous logging",
			zap.String("message", msg),
			zap.Any("fields", newFields),
		)
		m.logger.Log(level, msg, newFields...)
	}
}

func (m *Middleware) getCommonLogFields(r *http.Request, fields []zap.Field) []zap.Field {
	// Debug: Print the incoming fields
	m.logger.Debug("Incoming fields to getCommonLogFields",
		zap.Any("fields", fields),
	)

	// Extract or assign default values for metadata fields
	var sourceIP string
	var userAgent string
	var requestMethod string
	var requestPath string
	var queryParams string
	var statusCode int

	// Extract values from the incoming fields
	for _, field := range fields {
		switch field.Key {
		case "source_ip":
			sourceIP = field.String
		case "user_agent":
			userAgent = field.String
		case "request_method":
			requestMethod = field.String
		case "request_path":
			requestPath = field.String
		case "query_params":
			queryParams = field.String
		case "status_code":
			statusCode = int(field.Integer)
		}
	}

	// If values are not provided in the fields, extract them from the request
	if sourceIP == "" && r != nil {
		sourceIP = r.RemoteAddr
	}
	if userAgent == "" && r != nil {
		userAgent = r.UserAgent()
	}
	if requestMethod == "" && r != nil {
		requestMethod = r.Method
	}
	if requestPath == "" && r != nil {
		requestPath = r.URL.Path
	}
	if queryParams == "" && r != nil {
		queryParams = r.URL.RawQuery
	}

	// Debug: Print the extracted values
	m.logger.Debug("Extracted values in getCommonLogFields",
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
	)

	// Default values for missing fields
	if sourceIP == "" {
		sourceIP = "unknown"
	}
	if userAgent == "" {
		userAgent = "unknown"
	}
	if requestMethod == "" {
		requestMethod = "unknown"
	}
	if requestPath == "" {
		requestPath = "unknown"
	}

	// Debug: Print the final values after applying defaults
	m.logger.Debug("Final values after applying defaults",
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
	)

	// Redact query parameters if required
	if m.RedactSensitiveData {
		queryParams = m.redactQueryParams(queryParams)
	}

	// Construct and return common fields
	return []zap.Field{
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
		zap.Time("timestamp", time.Now()), // Include a timestamp
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
				if strings.Contains(key, "password") || strings.Contains(key, "token") || strings.Contains(key, "apikey") || strings.Contains(key, "authorization") || strings.Contains(key, "secret") {
					parts[i] = keyValue[0] + "=REDACTED"
				}
			}
		}
	}
	return strings.Join(parts, "&")
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
