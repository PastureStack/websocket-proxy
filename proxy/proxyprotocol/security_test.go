package proxyprotocol

import (
	"net"
	"net/http/httptest"
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
	AddHeaders(req, nil)
	if got := req.Header.Get(xForwardedFor); got != "2001:db8::10" {
		t.Fatalf("untrusted forwarded address survived: %q", got)
	}
	if got := req.Header.Get(xForwardedProto); got != "http" {
		t.Fatalf("untrusted forwarded protocol survived: %q", got)
	}
	if got := req.Header.Get(xForwardedPort); got != "" {
		t.Fatalf("untrusted forwarded port survived: %q", got)
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
