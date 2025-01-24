package caddywaf

import (
	"bytes"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// blockRequest handles blocking a request and logging the details.
func (m *Middleware) blockRequest(w http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, reason, ruleID, matchedValue string, fields ...zap.Field) {
	if !state.ResponseWritten {
		state.Blocked = true
		state.StatusCode = statusCode
		state.ResponseWritten = true

		// Custom response handling
		if resp, ok := m.CustomResponses[statusCode]; ok {
			m.logger.Debug("Custom response found for status code",
				zap.Int("status_code", statusCode),
				zap.String("body", resp.Body),
			)
			for key, value := range resp.Headers {
				w.Header().Set(key, value)
			}
			w.WriteHeader(resp.StatusCode)
			_, err := w.Write([]byte(resp.Body))
			if err != nil {
				m.logger.Error("Failed to write custom block response body", zap.Error(err), zap.Int("status_code", resp.StatusCode), zap.String("log_id", r.Context().Value("logID").(string)))
			}
			return
		}

		// Default blocking behavior
		logID := uuid.New().String()
		if logIDCtx, ok := r.Context().Value("logID").(string); ok {
			logID = logIDCtx
		}

		// Prepare standard fields for logging
		blockFields := []zap.Field{
			zap.String("log_id", logID),
			zap.String("source_ip", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_method", r.Method),
			zap.String("request_path", r.URL.Path),
			zap.String("query_params", r.URL.RawQuery),
			zap.Int("status_code", statusCode),
			zap.Time("timestamp", time.Now()),
			zap.String("reason", reason),              // Include the reason for blocking
			zap.String("rule_id", ruleID),             // Include the rule ID
			zap.String("matched_value", matchedValue), // Include the matched value
		}

		// Debug: Print the blockFields to verify they are correct
		m.logger.Debug("Block fields being passed to logRequest",
			zap.Any("blockFields", blockFields),
		)

		// Append additional fields if any
		blockFields = append(blockFields, fields...)

		// Log the blocked request at WARN level
		m.logRequest(zapcore.WarnLevel, "Request blocked", r, blockFields...)

		// Respond with the status code
		w.WriteHeader(statusCode)
	} else {
		// Debug log when response is already written, including log_id
		logID, _ := r.Context().Value("logID").(string)

		m.logger.Debug("blockRequest called but response already written",
			zap.Int("intended_status_code", statusCode),
			zap.String("path", r.URL.Path),
			zap.String("log_id", logID),
			zap.Int("current_status_code", state.StatusCode),
		)
	}
}

// responseRecorder captures the response status code, headers, and body.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool // To track if a write to the original writer has been done.
}

// NewResponseRecorder creates a new responseRecorder.
func NewResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		body:           new(bytes.Buffer),
		statusCode:     0, // Zero means not explicitly set
		written:        false,
	}
}

// WriteHeader captures the response status code.
func (r *responseRecorder) WriteHeader(statusCode int) {
	if !r.written {
		r.statusCode = statusCode
		r.ResponseWriter.WriteHeader(statusCode)
	}

}

// Header returns the response headers.
func (r *responseRecorder) Header() http.Header {
	return r.ResponseWriter.Header()
}

// BodyString returns the captured response body as a string.
func (r *responseRecorder) BodyString() string {
	return r.body.String()
}

// StatusCode returns the captured status code.
func (r *responseRecorder) StatusCode() int {
	if r.statusCode == 0 {
		return http.StatusOK
	}
	return r.statusCode
}

// Write captures the response body and writes to the buffer only.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 && !r.written {
		r.WriteHeader(http.StatusOK) // Default to 200 if not set
	}
	n, err := r.body.Write(b)
	r.written = true
	return n, err
}
