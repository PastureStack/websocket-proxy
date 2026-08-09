package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/model"
)

func TestExactTokenCookieDoesNotMatchCookieNameSubstrings(t *testing.T) {
	headers := http.Header{}
	headers.Add("Cookie", "not_token=wrong; token=expected; token_hint=also-wrong")
	got, err := exactTokenCookie(headers)
	if err != nil {
		t.Fatal(err)
	}
	if got != "expected" {
		t.Fatalf("wrong cookie selected: %q", got)
	}
}

func TestValidatedPlatformURLRejectsInjectedComponents(t *testing.T) {
	for _, addr := range []string{"user:pass@example.test", "example.test/path", "example.test?token=secret", ""} {
		if _, err := validatedPlatformURL(addr); err == nil {
			t.Fatalf("unsafe platform address was accepted: %q", addr)
		}
	}
}

func TestPerformPlatformAuthRequestBoundsBodyAndRejectsRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/redirect" {
			http.Redirect(w, req, "/oversized", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", maxPlatformAuthResponseBytes+1)))
	}))
	defer server.Close()

	redirectRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/redirect", nil)
	_, _, status, err := performPlatformAuthRequest(redirectRequest)
	if err != nil || status != http.StatusFound {
		t.Fatalf("redirect was followed or mishandled: status=%d err=%v", status, err)
	}

	oversizedRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/oversized", nil)
	if _, _, _, err := performPlatformAuthRequest(oversizedRequest); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response was accepted: %v", err)
	}
}

func TestTokenValidationFilterPreservesUnauthorizedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer server.Close()

	filter := &TokenValidationFilter{platformURL: server.URL}
	output, err := filter.ProcessFilter(model.FilterData{}, model.APIRequestData{
		Headers: map[string][]string{"Cookie": {"token=credential"}},
	})
	if err == nil || output.Status != http.StatusUnauthorized {
		t.Fatalf("unauthorized response was not preserved: status=%d err=%v", output.Status, err)
	}
}
