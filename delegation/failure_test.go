package delegation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFailureReporterRejectsRedirectAndUnconfirmedOrOversizedResponse(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{{"redirect", 302, ""}, {"notAccepted", 200, `{"accepted":false}`}, {"oversized", 200, strings.Repeat("x", 4097)}, {"accepted", 200, `{"accepted":true}`}} {
		t.Run(test.name, func(t *testing.T) {
			calls := &atomic.Int32{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirect-target")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			accepted := NewFailureReporter(server.URL).Report("grant", "backend-proof")
			if accepted != (test.name == "accepted") || calls.Load() != 1 {
				t.Fatal("failure receipt escaped its bounded fixed call")
			}
		})
	}
	if NewFailureReporter("https://user:secret@example.test").Report("grant", "proof") || NewFailureReporter("http://engine").Report("grant", "") {
		t.Fatal("untrusted or missing proof accepted")
	}
}
