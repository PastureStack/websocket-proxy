package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStripProxyAuthenticationQueryPreservesApplicationParameters(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.test/service?token=secret&access_token=other&view=all", nil)
	stripProxyAuthenticationQuery(req)
	if got := req.URL.Query().Get("view"); got != "all" {
		t.Fatalf("application query parameter was lost: %q", got)
	}
	if raw := req.URL.RawQuery; strings.Contains(raw, "token") || strings.Contains(raw, "secret") || strings.Contains(raw, "other") {
		t.Fatalf("authentication credential remained in forwarded query: %q", raw)
	}
}

func TestCopyAuthHeadersDoesNotForwardAuthenticationCookie(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.test/service", nil)
	req.Header.Add("Cookie", "token=secret; preference=compact")
	req.Header.Set("Proxy-Authorization", "Basic secret")
	(&FrontendHTTPHandler{}).copyAuthHeaders(req)
	if _, err := req.Cookie("token"); err == nil {
		t.Fatal("authentication cookie remained in proxied request")
	}
	preference, err := req.Cookie("preference")
	if err != nil || preference.Value != "compact" {
		t.Fatalf("application cookie was not preserved: cookie=%v err=%v", preference, err)
	}
	if req.Header.Get("Authorization") == "" {
		t.Fatal("backend authorization wrapper was not created")
	}
	if req.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("proxy authorization credential remained in proxied request")
	}
}
