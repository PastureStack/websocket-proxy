package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSafeAccessPathNeverIncludesQueryCredentials(t *testing.T) {
	secret := "query-secret"
	req := httptest.NewRequest("GET", "https://example.test/v1/exec?token="+secret+"&view=all", nil)
	got := safeAccessPath(req)
	if got != "/v1/exec" || strings.Contains(got, secret) || strings.Contains(got, "token") {
		t.Fatalf("unsafe access path: %q", got)
	}
}
