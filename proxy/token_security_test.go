package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewTokenLookupRejectsInvalidPlatformAddress(t *testing.T) {
	for _, address := range []string{"", "user:password@example.test", "example.test/path"} {
		if _, err := newTokenLookup(address); err == nil {
			t.Fatalf("unsafe platform address was accepted: %q", address)
		}
	}
}

func TestTokenLookupDoesNotFollowRedirectWithCredentials(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v1/serviceproxies" {
			http.Redirect(w, req, "/redirected", http.StatusFound)
			return
		}
		redirected.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"should-not-be-returned"}`))
	}))
	defer server.Close()

	lookup, err := newTokenLookup(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://client.test/service", nil)
	req.Header.Set(authHeader, "Bearer credential")
	if _, err := lookup.callPlatform(req); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected.Load() {
		t.Fatal("credential-bearing request followed a redirect")
	}
}

func TestTokenLookupBoundsPlatformResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxServiceProxyResponseBytes+1)))
	}))
	defer server.Close()

	lookup, err := newTokenLookup(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = lookup.callPlatform(httptest.NewRequest(http.MethodGet, "http://client.test/service", nil))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized service-proxy response was accepted: %v", err)
	}
}
