package proxyprotocol

import (
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxyProtocolRejectsOversizedHeader(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	conn := NewConn(server)
	go func() {
		_, _ = client.Write([]byte("PROXY " + strings.Repeat("x", maxProxyHeaderBytes) + "\r\n"))
	}()
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("oversized proxy protocol header was accepted")
	}
}

func TestForwardedHeadersReplaceUntrustedClientValues(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	req.RemoteAddr = "[2001:db8::10]:4321"
	req.Header.Set(xForwardedFor, "203.0.113.99")
	req.Header.Set(xForwardedProto, "https")
	req.Header.Set(xForwardedPort, "443")
	AddHeaders(req, nil, nil)
	if got := req.Header.Get(xForwardedFor); got != "2001:db8::10" {
		t.Fatalf("untrusted forwarded address survived: %q", got)
	}
	if got := req.Header.Get(xForwardedProto); got != "http" {
		t.Fatalf("untrusted forwarded protocol survived: %q", got)
	}
	if got := req.Header.Get(xForwardedPort); got != "" {
		t.Fatalf("untrusted forwarded port survived: %q", got)
	}
	if got := req.Header.Get(xForwardedHost); got != "example.test" {
		t.Fatalf("untrusted forwarded host survived: %q", got)
	}
}

func TestConfiguredPublicOriginCorrectsTLSAfterInternalHTTPProxying(t *testing.T) {
	origin, err := url.Parse("https://stack.example.test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://stack.example.test/v2-beta/schema", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set(xForwardedProto, "http")
	req.Header.Set(xForwardedPort, "8080")

	AddHeaders(req, nil, origin)

	if got := req.Header.Get(xForwardedProto); got != "https" {
		t.Fatalf("public protocol was not corrected: %q", got)
	}
	if got := req.Header.Get(xForwardedHost); got != "stack.example.test" {
		t.Fatalf("public host was not corrected: %q", got)
	}
	if got := req.Header.Get(xForwardedPort); got != "443" {
		t.Fatalf("public port was not corrected: %q", got)
	}
	if got := req.Header.Get(xForwardedFor); got != "127.0.0.1" {
		t.Fatalf("connection-derived client address was lost: %q", got)
	}
}

func TestConfiguredPublicOriginDoesNotApplyToAnotherHost(t *testing.T) {
	origin, err := url.Parse("https://stack.example.test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://attacker.example/v2-beta/schema", nil)
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set(xForwardedProto, "https")
	req.Header.Set(xForwardedHost, "stack.example.test")
	req.Header.Set(xForwardedPort, "443")

	AddHeaders(req, nil, origin)

	if got := req.Header.Get(xForwardedProto); got != "http" {
		t.Fatalf("foreign host inherited the public protocol: %q", got)
	}
	if got := req.Header.Get(xForwardedHost); got != "attacker.example" {
		t.Fatalf("foreign host inherited the configured public host: %q", got)
	}
	if got := req.Header.Get(xForwardedPort); got != "" {
		t.Fatalf("foreign host inherited the public port: %q", got)
	}
}

func TestProxyProtocolDefaultsToLoopbackSourcesOnly(t *testing.T) {
	if !trustedProxySource(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, nil) {
		t.Fatal("loopback proxy source was rejected")
	}
	if trustedProxySource(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}, nil) {
		t.Fatal("untrusted remote proxy source was accepted by default")
	}
}
