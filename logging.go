// logging.go
package caddywaf

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (m *Middleware) logRequest(level zapcore.Level, msg string, fields ...zap.Field) {
	if m.logger == nil {
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

	// Attach common request metadata
	commonFields := m.getCommonLogFields(newFields)
	newFields = append(newFields, commonFields...)

	// Determine the log level if unset
	if m.logLevel == 0 {
		switch strings.ToLower(m.LogSeverity) {
		case "debug":
			m.logLevel = zapcore.DebugLevel
		case "warn":
			m.logLevel = zapcore.WarnLevel
		case "error":
			m.logLevel = zapcore.ErrorLevel
		default:
			m.logLevel = zapcore.InfoLevel
		}
	}

	// Skip logging if level is below the threshold
	if level < m.logLevel {
		return
	}

	// Log the message with the appropriate format
	if m.LogJSON {
		newFields = append(newFields, zap.String("message", msg))
		m.logger.Log(level, "", newFields...)
	} else {
		m.logger.Log(level, msg, newFields...)
	}
}

func (m *Middleware) getCommonLogFields(fields []zap.Field) []zap.Field {
	// Extract or assign default values for metadata fields
	var sourceIP, userAgent, requestMethod, requestPath, queryParams string
	var statusCode int

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
