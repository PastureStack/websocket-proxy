package proxy

import (
	"net/url"
	"strings"
	"testing"
)

func TestStatsTargetURLNormalizesAndReplacesToken(t *testing.T) {
	secret := "new-secret"
	got, err := statsTargetURL("wss://example.test/v1/hoststats/project?sample=1&token=old-secret", secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "example.test") || strings.Contains(got, "old-secret") {
		t.Fatalf("statistics target leaked an external host or old credential: %q", got)
	}
	parsed, err := url.ParseRequestURI(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("token") != secret || parsed.Query().Get("sample") != "1" {
		t.Fatalf("statistics target query was not preserved safely: %q", got)
	}
}

func TestStatsTargetURLRejectsUnexpectedRoute(t *testing.T) {
	if _, err := statsTargetURL("wss://example.test/v1/exec", "secret"); err == nil {
		t.Fatal("non-statistics route was accepted as a statistics target")
	}
}
