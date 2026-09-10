package proxy

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadCertUsesAuthenticatedSameOriginResources(t *testing.T) {
	archive := certificateArchive(t, map[string]string{
		"ca.pem":   "test-ca",
		"cert.pem": "test-cert",
		"key.pem":  "test-key",
	})

	const accessKey = "test-access"
	const secretKey = "test-secret"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != accessKey || password != secretKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/schemas":
			writeJSON(t, w, map[string]interface{}{
				"data": []interface{}{map[string]interface{}{
					"id": "credential",
					"links": map[string]string{
						"collection": server.URL + "/v1/credentials",
					},
				}},
			})
		case "/v1/credentials":
			if got := r.URL.Query().Get("publicValue"); got != accessKey {
				t.Errorf("unexpected publicValue filter: %q", got)
			}
			if got := r.URL.Query().Get("kind"); got != "agentApiKey" {
				t.Errorf("unexpected kind filter: %q", got)
			}
			writeJSON(t, w, map[string]interface{}{
				"data": []interface{}{map[string]interface{}{
					"links": map[string]string{
						"certificate": server.URL + "/v1/credentials/1/certificate",
					},
				}},
			})
		case "/v1/credentials/1/certificate":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	certs, err := downloadCert(accessKey, secretKey, strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("downloadCert failed: %v", err)
	}
	if string(certs.CA) != "test-ca" || string(certs.Cert) != "test-cert" || string(certs.Key) != "test-key" {
		t.Fatalf("unexpected certificate bundle: %#v", certs)
	}
}

func TestDownloadCertRejectsCrossOriginCertificateURL(t *testing.T) {
	var crossOriginRequests int32
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&crossOriginRequests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer crossOrigin.Close()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/schemas":
			writeJSON(t, w, map[string]interface{}{
				"data": []interface{}{map[string]interface{}{
					"id":    "credential",
					"links": map[string]string{"collection": server.URL + "/v1/credentials"},
				}},
			})
		case "/v1/credentials":
			writeJSON(t, w, map[string]interface{}{
				"data": []interface{}{map[string]interface{}{
					"links": map[string]string{"certificate": crossOrigin.URL + "/certificate.zip"},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := downloadCert("access", "secret", strings.TrimPrefix(server.URL, "http://"))
	if err == nil || !strings.Contains(err.Error(), "same-origin") {
		t.Fatalf("expected same-origin error, got %v", err)
	}
	if got := atomic.LoadInt32(&crossOriginRequests); got != 0 {
		t.Fatalf("cross-origin server received %d requests", got)
	}
}

func TestDownloadKeyRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, maxPublicKeyBytes+1))
	}))
	defer server.Close()

	_, err := downloadKey(strings.TrimPrefix(server.URL, "http://"))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded-response error, got %v", err)
	}
}

func TestPublicKeyDecodeRejectsWeakRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	contents := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	if _, err := publicKeyDecode(contents); err == nil {
		t.Fatal("weak RSA JWT public key was accepted")
	}
}

func TestPublicKeyDecodeRejectsOversizedInput(t *testing.T) {
	if _, err := publicKeyDecode(make([]byte, maxPublicKeyBytes+1)); err == nil {
		t.Fatal("oversized JWT public key input was accepted")
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	networks, err := parseTrustedProxyCIDRs("127.0.0.0/8, 2001:db8::/32")
	if err != nil || len(networks) != 2 {
		t.Fatalf("valid trusted proxy networks were rejected: networks=%v err=%v", networks, err)
	}
	if _, err := parseTrustedProxyCIDRs("not-a-network"); err == nil {
		t.Fatal("invalid trusted proxy network was accepted")
	}
}

func TestParsePlatformPublicOrigin(t *testing.T) {
	origin, err := parsePlatformPublicOrigin("https://stack.example.test/")
	if err != nil || origin.String() != "https://stack.example.test" {
		t.Fatalf("valid public origin was rejected: origin=%v err=%v", origin, err)
	}
	for _, invalid := range []string{
		"ftp://stack.example.test",
		"https://user:secret@stack.example.test",
		"https://stack.example.test/a/path",
		"https://stack.example.test?query=value",
	} {
		if _, err := parsePlatformPublicOrigin(invalid); err == nil {
			t.Fatalf("invalid public origin was accepted: %q", invalid)
		}
	}
}

func TestExtractCertificateArchiveRejectsMissingAndDuplicateEntries(t *testing.T) {
	_, err := extractCertificateArchive(certificateArchive(t, map[string]string{
		"ca.pem":   "ca",
		"cert.pem": "cert",
	}))
	if err == nil || !strings.Contains(err.Error(), "key.pem") {
		t.Fatalf("expected missing key error, got %v", err)
	}

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for i := 0; i < 2; i++ {
		entry, createErr := writer.Create("ca.pem")
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, _ = entry.Write([]byte("ca"))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = extractCertificateArchive(archive.Bytes())
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate entry error, got %v", err)
	}
}

func TestNewServerTLSConfigRequiresTLS12(t *testing.T) {
	certPEM, keyPEM := selfSignedCertificate(t)
	config, err := newServerTLSConfig(&Certs{CA: certPEM, Cert: certPEM, Key: keyPEM})
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want TLS 1.2", config.MinVersion)
	}
	if config.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("unexpected client authentication mode: %v", config.ClientAuth)
	}
}

func TestApplyEnvironmentToUnsetFlagsPreservesCommandLinePrecedence(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	listenAddress := flags.String("listen-address", ":8080", "")
	parentPID := flags.Int("parent-pid", 0, "")
	if err := flags.Parse([]string{"--listen-address=:9000"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROXY_LISTEN_ADDRESS", ":1000")
	t.Setenv("PROXY_PARENT_PID", "42")
	if err := applyEnvironmentToUnsetFlags(flags, "PROXY_"); err != nil {
		t.Fatalf("applyEnvironmentToUnsetFlags failed: %v", err)
	}
	if *listenAddress != ":9000" {
		t.Fatalf("command-line value was overwritten: %q", *listenAddress)
	}
	if *parentPID != 42 {
		t.Fatalf("environment value was not applied: %d", *parentPID)
	}
}

func TestApplyEnvironmentToUnsetFlagsRejectsInvalidValue(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.Int("parent-pid", 0, "")
	t.Setenv("PROXY_PARENT_PID", "not-an-integer")
	if err := applyEnvironmentToUnsetFlags(flags, "PROXY_"); err == nil {
		t.Fatal("expected invalid environment value error")
	}
}

func certificateArchive(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, contents := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("write JSON: %v", err)
	}
}

func selfSignedCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "websocket-proxy-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if certificatePEM == nil || privatePEM == nil {
		t.Fatal(fmt.Errorf("failed to encode test certificate"))
	}
	return certificatePEM, privatePEM
}
