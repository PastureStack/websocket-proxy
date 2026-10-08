package delegation

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
)

func fixture() (map[string]interface{}, *Grant) {
	envelope := map[string]interface{}{"version": 1, "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "exec", "expiresAt": 1000,
		"payload": map[string]interface{}{"hostUuid": "h1", "exec": map[string]interface{}{"Container": "docker9"}}}
	claims := map[string]interface{}{Claim: envelope, "exp": 1000}
	grant, _ := Parse(claims)
	return claims, grant
}

func answer(g *Grant, token string) map[string]interface{} {
	digest := sha256.Sum256([]byte(token))
	return map[string]interface{}{"allowed": true, "keyId": g.KeyID, "revision": g.Revision, "targetType": g.TargetType, "targetId": g.TargetID,
		"operation": g.Operation, "expiresAt": g.ExpiresAt, "tokenDigest": hex.EncodeToString(digest[:])}
}

func TestNewGrantCannotFallBackToLegacyOrAnotherPath(t *testing.T) {
	claims, g := fixture()
	if g == nil || !g.AllowsPath("/v2-beta/exec/") || g.AllowsPath("/v2-beta/logs/") || g.AllowsPath("/v1/exec/sessions/id") {
		t.Fatal("operation/path binding failed")
	}
	if legacy, err := Parse(map[string]interface{}{"hostUuid": "h1"}); err != nil || legacy != nil {
		t.Fatal("legacy changed")
	}
	for _, bad := range []interface{}{nil, "wrong", map[string]interface{}{"version": 2}} {
		if _, err := Parse(map[string]interface{}{Claim: bad}); err == nil {
			t.Fatal("malformed grant became legacy")
		}
	}
	claims["hostUuid"] = "h1"
	if _, err := Parse(claims); err == nil {
		t.Fatal("rollback-compatible grant was accepted")
	}
	delete(claims, "hostUuid")
	claims["exp"] = 1001
	if _, err := Parse(claims); err == nil {
		t.Fatal("JWT expiry mismatch accepted")
	}
}

func TestHandshakeBindsOriginalTokenAndAllTargets(t *testing.T) {
	_, g := fixture()
	const raw = "signed-ticket"
	result := answer(g, raw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2-beta/apiKeyDelegation/introspect" || r.Header.Get("Authorization") != "" || len(r.Cookies()) != 0 {
			t.Error("untrusted request authority")
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != raw {
			t.Error("original token not sent")
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	v := New(server.URL + "/v1")
	v.Now = func() time.Time { return time.Unix(900, 0) }
	if err := v.Check(context.Background(), raw, g); err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]interface{}{"keyId": 99, "revision": 4, "targetType": "host", "targetId": "1i10", "operation": "logs", "expiresAt": 1001, "tokenDigest": "wrong", "allowed": false} {
		prior := result[field]
		result[field] = value
		if v.Check(context.Background(), raw, g) == nil {
			t.Fatalf("mismatch %s accepted", field)
		}
		result[field] = prior
	}
	v.Now = func() time.Time { return time.Unix(1000, 0) }
	if v.Check(context.Background(), raw, g) == nil {
		t.Fatal("expired grant accepted")
	}
}

func TestLiveRevocationAndExpiryCloseAtControlledBarrier(t *testing.T) {
	_, g := fixture()
	var revoked atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(answer(g, "ticket"))
	}))
	defer server.Close()
	v := New(server.URL)
	v.Now = func() time.Time { return time.Unix(900, 0) }
	for _, kind := range []string{"revocation", "expiry"} {
		revoked.Store(false)
		ctx, cancel := context.WithCancel(context.Background())
		ticks, expiry := make(chan time.Time), make(chan time.Time)
		denied, finished := make(chan struct{}), make(chan struct{})
		go func() { defer close(finished); v.Run(ctx, "ticket", g, ticks, expiry, func() { close(denied) }) }()
		if kind == "revocation" {
			revoked.Store(true)
			ticks <- time.Unix(901, 0)
		} else {
			expiry <- time.Unix(1000, 0)
		}
		<-denied
		<-finished
		cancel()
	}
}

func TestMissingEngineRedirectAndOutageFailClosed(t *testing.T) {
	_, g := fixture()
	if New("").Check(context.Background(), "ticket", g) == nil {
		t.Fatal("missing Engine allowed")
	}
	var followed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			followed.Store(true)
			json.NewEncoder(w).Encode(answer(g, "ticket"))
			return
		}
		http.Redirect(w, r, "/redirect", http.StatusFound)
	}))
	defer server.Close()
	v := New(server.URL)
	v.Now = func() time.Time { return time.Unix(900, 0) }
	if v.Check(context.Background(), "ticket", g) == nil || followed.Load() {
		t.Fatal("redirected authorization accepted")
	}
	server.Close()
	if v.Check(context.Background(), "ticket", g) == nil {
		t.Fatal("Engine outage allowed")
	}
}
