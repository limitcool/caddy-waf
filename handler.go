package caddywaf

import (
	"bytes"
	"context"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ==================== Request Handling and Logic ====================

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Generate a unique log ID for the request
	logID := uuid.New().String()

	// Log the request with common fields
	m.logRequest(zapcore.InfoLevel, "WAF evaluation started", r, zap.String("log_id", logID))

	// Use the custom type as the key
	ctx := context.WithValue(r.Context(), ContextKeyLogId("logID"), logID)
	r = r.WithContext(ctx)

	// Increment total requests
	m.muMetrics.Lock()
	m.totalRequests++
	m.muMetrics.Unlock()

	// Initialize WAF state for the request
	state := &WAFState{
		TotalScore:      0,
		Blocked:         false,
		StatusCode:      http.StatusOK,
		ResponseWritten: false,
	}

	// Log the request details
	m.logger.Info("WAF evaluation started",
		zap.String("log_id", logID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
		zap.String("query_params", r.URL.RawQuery),
	)

	// Handle Phase 1: Pre-request evaluation
	m.handlePhase(w, r, 1, state)
	if state.Blocked {
		m.muMetrics.Lock()
		m.blockedRequests++
		m.muMetrics.Unlock()
		w.WriteHeader(state.StatusCode)
		return nil
	}

	// Handle Phase 2: Request evaluation
	m.handlePhase(w, r, 2, state)
	if state.Blocked {
		m.muMetrics.Lock()
		m.blockedRequests++
		m.muMetrics.Unlock()
		w.WriteHeader(state.StatusCode)
		return nil
	}

	// Capture the response using a response recorder
	recorder := &responseRecorder{ResponseWriter: w, body: new(bytes.Buffer)}
	err := next.ServeHTTP(recorder, r)

	// Handle Phase 3: Response headers evaluation
	m.handlePhase(recorder, r, 3, state)
	if state.Blocked {
		m.muMetrics.Lock()
		m.blockedRequests++
		m.muMetrics.Unlock()
		recorder.WriteHeader(state.StatusCode)
		return nil
	}

	// Handle Phase 4: Response body evaluation
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

		// Write the response body if no blocking occurred
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

	// Handle metrics endpoint requests
	if m.MetricsEndpoint != "" && r.URL.Path == m.MetricsEndpoint {
		return m.handleMetricsRequest(w, r)
	}

	// Log the completion of WAF evaluation
	m.logger.Info("WAF evaluation complete",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
	)

	return err
}

// ==================== Utility Functions ====================
