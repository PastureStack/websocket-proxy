package http

import (
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/model"
)

func TestValidFilterEndpointRejectsCredentialAndNonHTTPDestinations(t *testing.T) {
	for _, endpoint := range []string{
		"file:///etc/passwd",
		"https://user:password@example.test/filter",
		"https://example.test/filter#secret",
		"//example.test/filter",
	} {
		if _, err := validFilterEndpoint(endpoint); err == nil {
			t.Fatalf("unsafe endpoint was accepted: %q", endpoint)
		}
	}
}

func TestGenericHTTPFilterBoundsResponse(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxFilterResponseBodyBytes+1)))
	}))
	defer server.Close()

	filterValue, err := NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	_, err = filterValue.ProcessFilter(model.FilterData{Endpoint: server.URL}, model.APIRequestData{})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized filter response was accepted: %v", err)
	}
}
