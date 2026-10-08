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

func TestRouteFailureReporterRequiresProxyAttemptUuidBeforeAnyNetworkCall(t *testing.T) {
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer server.Close()
	reporter := NewFailureReporter(server.URL)
	for _, attempt := range []string{"", "client-selected", "00000000-0000-0000-0000-000000000000", "00000000-0000-4000-8000-000000000000\n"} {
		if reporter.ReportRouteDenied("grant", "proof", attempt) || calls.Load() != 0 {
			t.Fatal("malformed route nonce reached the audit endpoint")
		}
	}
	if !reporter.ReportRouteDenied("grant", "proof", "00000000-0000-4000-8000-000000000000") || calls.Load() != 1 {
		t.Fatal("valid fixed route evidence was not bounded to one request")
	}
}
