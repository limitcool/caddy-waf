package caddywaf

import (
	"context"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ServeHTTP implements caddyhttp.Handler.
// ServeHTTP implements caddyhttp.Handler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logID := uuid.New().String()

	m.logRequestStart(r, logID)

	ctx := context.WithValue(r.Context(), ContextKeyLogId("logID"), logID)
	r = r.WithContext(ctx)

	m.incrementTotalRequestsMetric()

	state := m.initializeWAFState()

	if m.isPhaseBlocked(w, r, 1, state) { // Phase 1: Pre-request checks
		return nil // Request blocked in Phase 1, short-circuit
	}

	if m.isPhaseBlocked(w, r, 2, state) { // Phase 2: Request analysis
		return nil // Request blocked in Phase 2, short-circuit
	}

	recorder := NewResponseRecorder(w)
	err := next.ServeHTTP(recorder, r)

	if m.isResponseHeaderPhaseBlocked(recorder, r, 3, state) { // Phase 3: Response Header analysis
		return nil // Request blocked in Phase 3, short-circuit
	}

	m.handleResponseBodyPhase(recorder, r, state) // Phase 4: Response Body analysis (if not blocked yet)

	if state.Blocked {
		m.incrementBlockedRequestsMetric() // Potential overcounting here
		m.writeCustomResponse(recorder, state.StatusCode)
		return nil // Short circuit if blocked in any phase after headers
	}

	m.incrementAllowedRequestsMetric()

	if m.isMetricsRequest(r) {
		return m.handleMetricsRequest(w, r) // Handle metrics requests separately
	}

	// If not blocked, copy recorded response back to original writer
	if !state.Blocked {
		// Copy headers from recorder to original writer
		header := w.Header()
		for key, values := range recorder.Header() {
			for _, value := range values {
				header.Add(key, value)
			}
		}
		w.WriteHeader(recorder.StatusCode()) // Set status code from recorder

		// Write body from recorder to original writer
		_, writeErr := w.Write(recorder.body.Bytes())
		if writeErr != nil {
			m.logger.Error("Failed to write recorded response body to client", zap.Error(writeErr), zap.String("log_id", logID))
			// We should still return the original error from next.ServeHTTP if available, or a new error if writing body failed and next didn't return error.
			if err == nil {
				return writeErr // If original handler didn't error, return body write error.
			}
		}
	}

	m.logRequestCompletion(logID, state)

	return err // Return any error from the next handler
}

// isPhaseBlocked encapsulates the phase handling and blocking check logic.
func (m *Middleware) isPhaseBlocked(w http.ResponseWriter, r *http.Request, phase int, state *WAFState) bool {
	m.handlePhase(w, r, phase, state)
	if state.Blocked {
		m.incrementBlockedRequestsMetric()
		w.WriteHeader(state.StatusCode)
		return true
	}
	return false
}

// isResponseHeaderPhaseBlocked encapsulates the response header phase handling and blocking check logic.
func (m *Middleware) isResponseHeaderPhaseBlocked(recorder *responseRecorder, r *http.Request, phase int, state *WAFState) bool {
	m.handlePhase(recorder, r, phase, state)
	if state.Blocked {
		m.incrementBlockedRequestsMetric()
		recorder.WriteHeader(state.StatusCode)
		return true
	}
	return false
}

// logRequestStart logs the start of WAF evaluation.
func (m *Middleware) logRequestStart(r *http.Request, logID string) {
	m.logger.Info("WAF request evaluation started",
		zap.String("log_id", logID),
		zap.String("method", r.Method),
		zap.String("uri", r.RequestURI),
		zap.String("remote_address", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)
}

// incrementTotalRequestsMetric increments the total requests metric.
func (m *Middleware) incrementTotalRequestsMetric() {
	m.muMetrics.Lock()
	m.totalRequests++
	m.muMetrics.Unlock()
}

// initializeWAFState initializes the WAF state.
func (m *Middleware) initializeWAFState() *WAFState {
	return &WAFState{
		TotalScore:      0,
		Blocked:         false,
		StatusCode:      http.StatusOK,
		ResponseWritten: false,
	}
}

// handleResponseBodyPhase processes Phase 4 (response body).
func (m *Middleware) handleResponseBodyPhase(recorder *responseRecorder, r *http.Request, state *WAFState) {
	// No need to check if recorder.body is nil here, it's always initialized in NewResponseRecorder
	body := recorder.BodyString()
	m.logger.Debug("Response body captured for Phase 4 analysis", zap.String("log_id", r.Context().Value(ContextKeyLogId("logID")).(string)))

	for _, rule := range m.Rules[4] {
		if rule.regex.MatchString(body) {
			m.processRuleMatch(recorder, r, &rule, body, state)
			if state.Blocked {
				m.incrementBlockedRequestsMetric()
				return
			}
		}
	}
}

// incrementBlockedRequestsMetric increments the blocked requests metric.
func (m *Middleware) incrementBlockedRequestsMetric() {
	m.muMetrics.Lock()
	m.blockedRequests++
	m.muMetrics.Unlock()
}

// incrementAllowedRequestsMetric increments the allowed requests metric.
func (m *Middleware) incrementAllowedRequestsMetric() {
	m.muMetrics.Lock()
	m.allowedRequests++
	m.muMetrics.Unlock()
}

// isMetricsRequest checks if it's a metrics request.
func (m *Middleware) isMetricsRequest(r *http.Request) bool {
	return m.MetricsEndpoint != "" && r.URL.Path == m.MetricsEndpoint
}

// writeCustomResponse writes a custom response.
func (m *Middleware) writeCustomResponse(w http.ResponseWriter, statusCode int) {
	if customResponse, ok := m.CustomResponses[statusCode]; ok {
		for key, value := range customResponse.Headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(customResponse.StatusCode)
		if _, err := w.Write([]byte(customResponse.Body)); err != nil {
			m.logger.Error("Failed to write custom response body", zap.Error(err))
		}
	}
}

// logRequestCompletion logs the completion of WAF evaluation.
func (m *Middleware) logRequestCompletion(logID string, state *WAFState) {
	m.logger.Info("WAF request evaluation completed",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
		zap.Int("status_code", state.StatusCode),
	)
}
