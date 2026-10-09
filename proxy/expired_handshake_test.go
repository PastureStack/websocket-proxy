package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/websocket-proxy/delegation"
	"github.com/PastureStack/websocket-proxy/testutils"
)

func expiredScopedTicket() string {
	expires := time.Now().Add(-time.Minute).Unix()
	grant := map[string]interface{}{"version": 1, "keyId": 12, "principalId": 42, "accountId": 5, "revision": 3,
		"targetType": "container", "targetId": "9", "operation": "logs", "issuedAt": expires - 60, "expiresAt": expires,
		"requestId": "d3819b41-95fb-4351-b95a-0d82e94a477c", "requestMethod": "POST", "requestAction": "logs", "payload": map[string]interface{}{"hostUuid": "h1", "logs": map[string]interface{}{"Container": "docker9"}}}
	return testutils.CreateTokenWithPayload(map[string]interface{}{delegation.Claim: grant, "exp": expires}, testutils.ParseTestPrivateKey())
}

func fullExpiryTrace(targetType, targetID, operation string, issued int64) map[string]interface{} {
	return map[string]interface{}{"version": 1, "keyId": 12, "principalId": 42, "accountId": 5, "revision": 0,
		"targetType": targetType, "targetId": targetID, "operation": operation, "issuedAt": issued,
		"requestId": "d3819b41-95fb-4351-b95a-0d82e94a477c", "requestMethod": "GET", "requestLink": "containerstats"}
}

func TestExpiredFullTraceHasIndependentOwnedReceiptsWithoutChangingLegacyAuth(t *testing.T) {
	expires := time.Now().Add(-time.Minute).Unix()
	trace := fullExpiryTrace("container", "9", "logs", expires-60)
	trace["requestMethod"], trace["requestAction"] = "POST", "logs"
	delete(trace, "requestLink")
	raw := testutils.CreateTokenWithPayload(map[string]interface{}{"apiKeyAudit": trace, "hostUuid": "h1",
		"logs": map[string]interface{}{"Container": "docker9"}, "exp": expires}, testutils.ParseTestPrivateKey())
	backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
	calls, attempts := &atomic.Int32{}, []string{}
	handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), failures: expiredReporter(t, raw, true, calls, &attempts)}
	for attempt := 0; attempt < 2; attempt++ {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://proxy/v2-beta/logs/?token="+url.QueryEscape(raw), nil))
		if response.Code != 401 || response.Header().Get("X-Api-Error-Code") != "ApiKeyExpired" || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
			t.Fatal("signed expired full trace was not an owned denial before business")
		}
	}
	if calls.Load() != 2 || len(attempts) != 2 || attempts[0] == attempts[1] {
		t.Fatal("full trace cached attempts lost independent durable event identity")
	}
	if token, err := parseSignedJWT(raw, testutils.ParseTestPublicKey()); err == nil || (token != nil && token.Valid) {
		t.Fatal("audit-only full trace bypassed normal JWT expiry validation")
	}
}

func TestExpiredFullAggregateUsesSignedTraceAndHostProofWithExactSharedBindings(t *testing.T) {
	for _, variant := range []string{"valid", "principalId", "accountId", "requestId", "requestMethod", "requestAction", "requestLink", "keyId", "missingTrace", "unexpiredInner"} {
		t.Run(variant, func(t *testing.T) {
			expires := time.Now().Add(-time.Minute).Unix()
			entries, proofs := []interface{}{}, map[string]string{}
			for _, host := range []string{"h1", "h2"} {
				trace := fullExpiryTrace("service", "1s9", "read", expires-60)
				claims := map[string]interface{}{"apiKeyAudit": trace, "hostUuid": host, "exp": expires,
					"containerIds": map[string]interface{}{"docker9": "1i9"}}
				if host == "h2" && variant != "valid" {
					switch variant {
					case "missingTrace":
						delete(claims, "apiKeyAudit")
					case "unexpiredInner":
						claims["exp"] = time.Now().Add(time.Minute).Unix()
					default:
						trace[variant] = "foreign-signed-binding"
					}
				}
				raw := testutils.CreateTokenWithPayload(claims, testutils.ParseTestPrivateKey())
				entries = append(entries, map[string]interface{}{"token": raw, "url": "ws://untrusted.test/ignored"})
				proofs[raw] = "trusted-" + host
			}
			outer := testutils.CreateTokenWithPayload(map[string]interface{}{"apiKeyAudit": fullExpiryTrace("service", "1s9", "read", expires-60),
				"service": entries, "exp": expires}, testutils.ParseTestPrivateKey())
			backend := &routeMultiBackend{capabilityTestBackend: capabilityTestBackend{capable: true}}
			calls, attempts := &atomic.Int32{}, []string{}
			handler := &StatsHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), failures: expiredReporterWithProofs(t, proofs, true, calls, &attempts)}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "http://proxy/v2-beta/containerstats/service/?token="+url.QueryEscape(outer), nil))
			status, reports := 503, int32(0)
			if variant == "valid" {
				status, reports = 401, 2
			}
			if response.Code != status || calls.Load() != reports || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
				t.Fatal("expired full aggregate used unowned/foreign/live inner proof or initialized business")
			}
			if reports == 2 && (len(attempts) != 2 || attempts[0] != attempts[1]) {
				t.Fatal("full aggregate did not retain common server attempt nonce")
			}
		})
	}
}

func expiredReporter(t *testing.T, raw string, accept bool, calls *atomic.Int32, attempts *[]string) *delegation.FailureReporter {
	return expiredReporterWithProofs(t, map[string]string{raw: "trusted-backend"}, accept, calls, attempts)
}

func expiredReporterWithProofs(t *testing.T, tickets map[string]string, accept bool, calls *atomic.Int32, attempts *[]string) *delegation.FailureReporter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		var body map[string]string
		if req.Method != "POST" || req.URL.Path != "/v2-beta/apiKeyDelegationFailure/report" || req.URL.RawQuery != "" ||
			req.Header.Get("Authorization") != "" || json.NewDecoder(req.Body).Decode(&body) != nil || len(body) != 4 ||
			body["failureCode"] != "ApiKeyExpired" || body["backendToken"] == "" || tickets[body["token"]] != body["backendToken"] ||
			!regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`).MatchString(body["attemptId"]) ||
			body["attemptId"] == "caller-attempt" {
			t.Error("expiry report contains untrusted identity/outcome or lacks dual proof and server nonce")
			w.WriteHeader(400)
			return
		}
		*attempts = append(*attempts, body["attemptId"])
		if !accept {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(server.Close)
	return delegation.NewFailureReporter(server.URL)
}

func TestExpiredScopedHandshakeHasTwoIndependentReceiptsBefore401AndNeverOpensBackend(t *testing.T) {
	raw := expiredScopedTicket()
	backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
	calls, attempts := &atomic.Int32{}, []string{}
	handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(),
		failures: expiredReporter(t, raw, true, calls, &attempts)}
	for index := 0; index < 2; index++ {
		request := httptest.NewRequest("GET", "http://proxy/v2-beta/logs/?attemptId=caller-attempt&keyId=forged&failureCode=SUCCEEDED", nil)
		request.Header.Set("Authorization", "Bearer "+raw)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 401 || response.Header().Get("X-Api-Error-Code") != "ApiKeyExpired" || response.Header().Get("Cache-Control") != "no-store" ||
			strings.Contains(response.Body.String(), raw) || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
			t.Fatal("expired signed handshake was not audited before its real401 or initialized business")
		}
	}
	if calls.Load() != 2 || len(attempts) != 2 || attempts[0] == attempts[1] {
		t.Fatal("two attempts on one expired ticket lost an independent audit event")
	}
}

func TestExpiredScopedHandshakeMissingProofOrAuditOutageIs503WithoutBusiness(t *testing.T) {
	for _, proof := range []string{"", "trusted-backend"} {
		raw := expiredScopedTicket()
		backend := &capabilityTestBackend{capable: true, proof: proof}
		calls, attempts := &atomic.Int32{}, []string{}
		handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(),
			failures: expiredReporter(t, raw, false, calls, &attempts)}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://proxy/v2-beta/logs/?token="+url.QueryEscape(raw), nil))
		wantedCalls := int32(1)
		if proof == "" {
			wantedCalls = 0
		}
		if response.Code != 503 || response.Header().Get("X-Api-Error-Code") != "AuditUnavailable" || calls.Load() != wantedCalls ||
			backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
			t.Fatal("unrecorded expired handshake claimed ordinary401 or opened business")
		}
	}
}

func TestExpiredTamperedOrLegacyTokenNeverBecomesOwnedExpiryEvidence(t *testing.T) {
	raw := expiredScopedTicket()
	parts := strings.Split(raw, ".")
	parts[2] = "A" + parts[2][1:]
	if strings.Join(parts, ".") == raw {
		parts[2] = "B" + parts[2][1:]
	}
	legacy := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "exp": time.Now().Add(-time.Minute).Unix()}, testutils.ParseTestPrivateKey())
	for _, token := range []string{strings.Join(parts, "."), legacy, "unsigned"} {
		backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
		calls, attempts := &atomic.Int32{}, []string{}
		handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(),
			failures: expiredReporter(t, raw, true, calls, &attempts)}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://proxy/v2-beta/logs/?token="+url.QueryEscape(token), nil))
		if response.Code != 401 || calls.Load() != 0 || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
			t.Fatal("unverified or legacy token changed owned expiry audit/authentication")
		}
	}
}

func TestExpiredAuditOnlySignatureParserNeverAuthorizesOrClassifiesAnUnexpiredGrant(t *testing.T) {
	raw := expiredScopedTicket()
	if token, err := parseSignedJWT(raw, testutils.ParseTestPublicKey()); err == nil || token.Valid {
		t.Fatal("ordinary authentication accepted expired signature-only evidence")
	}
	if token, err := parseAuditSignatureJWT(raw, testutils.ParseTestPublicKey()); err != nil || !token.Valid {
		t.Fatal("expired verified signature cannot supply audit-only identity")
	}
	fresh, _, _, _ := scopedProxyFixture(t)
	if expiredDelegationAudit(fresh, testutils.ParseTestPublicKey()) != nil {
		t.Fatal("unexpired grant became a fixed expiry denial")
	}
}

func TestExpiredScopedPersistentSessionIsAuditedBeforeAnyAllocation(t *testing.T) {
	raw := expiredScopedTicket()
	backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
	calls, attempts := &atomic.Int32{}, []string{}
	frontend := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), failures: expiredReporter(t, raw, true, calls, &attempts)}
	handler := NewPersistentSessionHandler(frontend, backend)
	defer func() { close(handler.manager.stop); <-handler.manager.done }()
	body, _ := json.Marshal(map[string]string{"kind": "logs", "secret": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH", "target": "ws://proxy/v2-beta/logs/", "token": raw})
	response := httptest.NewRecorder()
	handler.createSession(response, httptest.NewRequest("POST", "http://proxy/v1/exec/sessions/psw_abcdefghijklmnopqrstuv01", strings.NewReader(string(body))), "psw_abcdefghijklmnopqrstuv01")
	if response.Code != 401 || response.Header().Get("X-Api-Error-Code") != "ApiKeyExpired" || calls.Load() != 1 ||
		backend.initialized.Load() != 0 || backend.connected.Load() != 0 || handler.manager.get("psw_abcdefghijklmnopqrstuv01") != nil {
		t.Fatal("expired session bypassed durable denial or allocated backend/replay")
	}
}

func TestExpiredScopedStatsAggregateVerifiesEveryInnerSignatureAndBindingBeforeReporting(t *testing.T) {
	for _, variant := range []string{"valid", "duplicate", "tampered", "foreign", "principalId", "accountId", "requestId", "requestMethod", "requestAction", "requestLink"} {
		t.Run(variant, func(t *testing.T) {
			expires := time.Now().Add(-time.Minute).Unix()
			entries, proofs := []interface{}{}, map[string]string{}
			for _, host := range []string{"h1", "h2"} {
				grant := map[string]interface{}{"version": 1, "keyId": 12, "principalId": 42, "accountId": 5, "revision": 3, "targetType": "service", "targetId": "1s9", "operation": "read", "issuedAt": expires - 60, "expiresAt": expires,
					"requestId": "d3819b41-95fb-4351-b95a-0d82e94a477c", "requestMethod": "GET", "requestLink": "containerstats",
					"payload": map[string]interface{}{"hostUuid": host, "containerIds": map[string]interface{}{"docker9": "1i9"}}}
				if host == "h2" && variant == "foreign" {
					grant["keyId"] = 99
				}
				if host == "h2" && variant != "valid" && variant != "duplicate" && variant != "tampered" && variant != "foreign" {
					grant[variant] = "different-signed-request"
				}
				raw := testutils.CreateTokenWithPayload(map[string]interface{}{delegation.Claim: grant, "exp": expires}, testutils.ParseTestPrivateKey())
				if host == "h2" && variant == "tampered" {
					parts := strings.Split(raw, ".")
					parts[2] = "A" + parts[2][1:]
					if strings.Join(parts, ".") == raw {
						parts[2] = "B" + parts[2][1:]
					}
					raw = strings.Join(parts, ".")
				}
				entry := map[string]interface{}{"token": raw, "url": "ws://untrusted.test/ignored"}
				entries = append(entries, entry)
				if variant == "duplicate" {
					entries = append(entries, entry)
				}
				proofs[raw] = "trusted-" + host
			}
			outer := map[string]interface{}{"version": 1, "keyId": 12, "principalId": 42, "accountId": 5, "revision": 3, "targetType": "service", "targetId": "1s9", "operation": "read", "issuedAt": expires - 60, "expiresAt": expires,
				"requestId": "d3819b41-95fb-4351-b95a-0d82e94a477c", "requestMethod": "GET", "requestLink": "containerstats",
				"payload": map[string]interface{}{"service": entries}}
			raw := testutils.CreateTokenWithPayload(map[string]interface{}{delegation.Claim: outer, "exp": expires}, testutils.ParseTestPrivateKey())
			backend := &routeMultiBackend{capabilityTestBackend: capabilityTestBackend{capable: true}}
			calls, attempts := &atomic.Int32{}, []string{}
			handler := &StatsHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), failures: expiredReporterWithProofs(t, proofs, true, calls, &attempts)}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "http://proxy/v2-beta/containerstats/service/?token="+url.QueryEscape(raw), nil))
			status, reports := 503, int32(0)
			if variant == "valid" || variant == "duplicate" {
				status, reports = 401, 2
			}
			if response.Code != status || calls.Load() != reports || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
				t.Fatal("expired aggregate initialized business or trusted tampered/foreign proof")
			}
			if reports == 2 && (len(attempts) != 2 || attempts[0] != attempts[1]) {
				t.Fatal("one aggregate HTTP attempt lost its common server nonce")
			}
		})
	}
}
