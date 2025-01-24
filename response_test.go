package caddywaf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

type contextKey string

type CustomResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
}

func TestBlockRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("handles custom response", func(t *testing.T) {
		m := &Middleware{
			logger: logger,
			CustomResponses: map[int]CustomBlockResponse{
				http.StatusForbidden: {
					StatusCode: http.StatusForbidden,
					Body:       "Blocked",
					Headers:    map[string]string{"X-Test": "true"},
				},
			},
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test", nil)
		state := &WAFState{}

		m.blockRequest(w, r, state, http.StatusForbidden, "test reason", "rule1", "match1")

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, "Blocked", w.Body.String())
		assert.Equal(t, "true", w.Header().Get("X-Test"))
		assert.True(t, state.Blocked)
	})

	t.Run("handles default blocking", func(t *testing.T) {
		m := &Middleware{
			logger: logger,
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test", nil)
		const logIDKey contextKey = "logID"
		ctx := context.WithValue(r.Context(), logIDKey, "test-id")
		r = r.WithContext(ctx)
		state := &WAFState{}

		m.blockRequest(w, r, state, http.StatusForbidden, "test reason", "rule1", "match1")

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.True(t, state.Blocked)
	})

	t.Run("skips if response already written", func(t *testing.T) {
		m := &Middleware{
			logger: logger,
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test", nil)
		state := &WAFState{
			ResponseWritten: true,
			StatusCode:      http.StatusOK,
		}

		m.blockRequest(w, r, state, http.StatusForbidden, "test reason", "rule1", "match1")

		assert.Equal(t, http.StatusOK, state.StatusCode)
	})
}
