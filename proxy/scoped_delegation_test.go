package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/delegation"
	"github.com/PastureStack/websocket-proxy/testutils"
)

type scopedTestBackend struct{ closed atomic.Int32 }

func (*scopedTestBackend) initializeClient(string) (string, <-chan common.Message, error) {
	return "message", make(chan common.Message), nil
}
func (*scopedTestBackend) connect(string, string, string) error   { return nil }
func (*scopedTestBackend) send(string, string, string) error      { return nil }
func (b *scopedTestBackend) closeConnection(string, string) error { b.closed.Add(1); return nil }
func (*scopedTestBackend) releaseConnection(string, string) error { return nil }
func (*scopedTestBackend) hasBackend(host string) bool            { return host == "h1" }

func scopedProxyFixture(t *testing.T) (string, *delegation.Grant, *delegation.Verifier, *atomic.Bool) {
	t.Helper()
	expires := time.Now().Add(time.Hour).Unix()
	envelope := map[string]interface{}{"version": 1, "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "exec", "expiresAt": expires,
		"payload": map[string]interface{}{"hostUuid": "h1", "exec": map[string]interface{}{"Container": "docker9"}}}
	raw := testutils.CreateTokenWithPayload(map[string]interface{}{delegation.Claim: envelope, "exp": expires}, testutils.ParseTestPrivateKey())
	grant, err := delegation.Parse(map[string]interface{}{delegation.Claim: envelope, "exp": expires})
	if err != nil {
		t.Fatal(err)
	}
	denied := &atomic.Bool{}
	digest := sha256.Sum256([]byte(raw))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if denied.Load() {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true, "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "exec", "expiresAt": expires, "tokenDigest": hex.EncodeToString(digest[:])})
	}))
	t.Cleanup(server.Close)
	return raw, grant, delegation.New(server.URL), denied
}

func TestScopedFrontendHandshakeCannotChangeTargetPathOrSkipEngine(t *testing.T) {
	raw, _, verifier, denied := scopedProxyFixture(t)
	handler := &FrontendHandler{backend: &scopedTestBackend{}, parsedPublicKey: testutils.ParseTestPublicKey(), delegations: verifier}
	request := httptest.NewRequest(http.MethodGet, "http://proxy/v2-beta/exec/", nil)
	request.Header.Set("Authorization", "Bearer "+raw)
	if _, host, err := handler.auth(request); err != nil || host != "h1" {
		t.Fatalf("valid handshake denied: %v", err)
	}
	request.URL.Path = "/v2-beta/logs/"
	if _, _, err := handler.auth(request); err == nil {
		t.Fatal("exec grant became logs authority")
	}
	request.URL.Path = "/v2-beta/exec/"
	denied.Store(true)
	if _, _, err := handler.auth(request); err == nil {
		t.Fatal("revoked handshake accepted")
	}
}

func scopedSession(backend *scopedTestBackend) *persistentSession {
	return &persistentSession{secretHash: sha256.Sum256([]byte("test-secret")), backend: backend, hostKey: "h1", msgKey: "message", status: "connected", maxReplayBytes: 1024, clients: make(map[string]*workspaceClient)}
}

func TestScopedPersistentRevocationClosesBackendAndErasesReplay(t *testing.T) {
	raw, grant, verifier, denied := scopedProxyFixture(t)
	backend := &scopedTestBackend{}
	session := scopedSession(backend)
	session.delegationCheck = func() bool { return verifier.Check(context.Background(), raw, grant) == nil }
	session.appendOutput("before-revocation")
	if !session.matchesSecretHash(session.secretHash) {
		t.Fatal("live secret rejected")
	}
	ticks, expiry, done := make(chan time.Time), make(chan time.Time), make(chan struct{})
	go func() {
		verifier.Run(context.Background(), raw, grant, ticks, expiry, session.revokeDelegation)
		close(done)
	}()
	denied.Store(true)
	ticks <- time.Now()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revocation barrier did not terminate")
	}
	session.appendOutput("after-revocation")
	if session.matchesSecretHash(session.secretHash) || backend.closed.Load() != 1 || len(session.replay) != 0 || session.replayBytes != 0 {
		t.Fatal("session secret/replay survived revocation")
	}
}

func TestScopedPersistentExpiryRejectsResumeWithoutExtendingRetention(t *testing.T) {
	raw, grant, verifier, _ := scopedProxyFixture(t)
	backend := &scopedTestBackend{}
	session := scopedSession(backend)
	verifier.Now = func() time.Time { return time.Unix(grant.ExpiresAt, 0) }
	session.delegationCheck = func() bool { return verifier.Check(context.Background(), raw, grant) == nil }
	if session.matchesSecretHash(session.secretHash) || backend.closed.Load() != 1 {
		t.Fatal("72-hour session retention extended ticket authority")
	}
	legacy := scopedSession(&scopedTestBackend{})
	if !legacy.matchesSecretHash(legacy.secretHash) {
		t.Fatal("legacy retention changed")
	}
}
