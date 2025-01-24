package caddywaf

import (
	"context"

	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/stretchr/testify/assert"
)

func TestMiddleware_Provision(t *testing.T) {
	// Ensure testdata files exist
	if _, err := os.Stat("testdata/rules.json"); os.IsNotExist(err) {
		t.Skip("testdata/rules.json does not exist, skipping test")
	}
	if _, err := os.Stat("testdata/ip_blacklist.txt"); os.IsNotExist(err) {
		t.Skip("testdata/ip_blacklist.txt does not exist, skipping test")
	}
	if _, err := os.Stat("testdata/dns_blacklist.txt"); os.IsNotExist(err) {
		t.Skip("testdata/dns_blacklist.txt does not exist, skipping test")
	}
	if _, err := os.Stat("testdata/GeoIP2-Country-Test.mmdb"); os.IsNotExist(err) {
		t.Skip("testdata/GeoIP2-Country-Test.mmdb does not exist, skipping test")
	}

	m := &Middleware{
		RuleFiles:        []string{"testdata/rules.json"},
		IPBlacklistFile:  "testdata/ip_blacklist.txt",
		DNSBlacklistFile: "testdata/dns_blacklist.txt",
		AnomalyThreshold: 10,
		CountryBlock: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"US"},
			GeoIPDBPath: "testdata/GeoIP2-Country-Test.mmdb",
		},
	}

	ctx := caddy.Context{Context: context.Background()}
	err := m.Provision(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, m.logger)
	assert.NotNil(t, m.ruleCache)
	assert.NotNil(t, m.ipBlacklist)
	assert.NotNil(t, m.dnsBlacklist)
	assert.NotNil(t, m.Rules)
}

// MockGeoIPReader is a mock implementation of GeoIP reader for testing
type MockGeoIPReader struct{}

func TestNewResponseRecorder(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Assert that the responseRecorder is initialized correctly
	assert.NotNil(t, rr)
	assert.NotNil(t, rr.body)
	assert.Equal(t, 0, rr.statusCode)
}

func TestResponseRecorder_WriteHeader(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Set a custom status code
	rr.WriteHeader(http.StatusNotFound)

	// Assert that the status code is set correctly
	assert.Equal(t, http.StatusNotFound, rr.statusCode)
}

func TestResponseRecorder_Header(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Set a custom header
	rr.Header().Set("Content-Type", "application/json")

	// Assert that the header is set correctly
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestResponseRecorder_BodyString(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Write some data to the response body
	_, err := rr.Write([]byte("Hello, World!"))
	assert.NoError(t, err)

	// Assert that the body is captured correctly
	assert.Equal(t, "Hello, World!", rr.BodyString())
}

func TestResponseRecorder_StatusCode(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Default status code should be 200
	assert.Equal(t, http.StatusOK, rr.StatusCode())

	// Set a custom status code
	rr.WriteHeader(http.StatusInternalServerError)

	// Assert that the status code is updated correctly
	assert.Equal(t, http.StatusInternalServerError, rr.StatusCode())
}

func TestResponseRecorder_Write(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Write some data to the response body
	n, err := rr.Write([]byte("Hello, World!"))
	assert.NoError(t, err)

	// Assert that the correct number of bytes were written
	assert.Equal(t, 13, n)

	// Assert that the body is captured correctly
	assert.Equal(t, "Hello, World!", rr.BodyString())

	// Assert that the status code is set to 200 by default
	assert.Equal(t, http.StatusOK, rr.StatusCode())
}

func TestResponseRecorder_Write_WithCustomStatusCode(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Set a custom status code
	rr.WriteHeader(http.StatusForbidden)

	// Write some data to the response body
	_, err := rr.Write([]byte("Access Denied"))
	assert.NoError(t, err)

	// Assert that the status code is set correctly
	assert.Equal(t, http.StatusForbidden, rr.StatusCode())

	// Assert that the body is captured correctly
	assert.Equal(t, "Access Denied", rr.BodyString())
}

func TestResponseRecorder_Write_EmptyBody(t *testing.T) {
	// Create a new ResponseRecorder
	rr := NewResponseRecorder(httptest.NewRecorder())

	// Write an empty body
	_, err := rr.Write([]byte{})
	assert.NoError(t, err)

	// Assert that the body is empty
	assert.Equal(t, "", rr.BodyString())

	// Assert that the status code is set to 200 by default
	assert.Equal(t, http.StatusOK, rr.StatusCode())
}
