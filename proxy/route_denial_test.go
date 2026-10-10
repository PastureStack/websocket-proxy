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

func routeReporter(t *testing.T, tickets map[string]string, accept bool, calls *atomic.Int32) *delegation.FailureReporter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		var body map[string]string
		if req.Method != "POST" || req.URL.Path != "/v2-beta/apiKeyDelegationFailure/report" || req.URL.RawQuery != "" ||
			req.Header.Get("Authorization") != "" || json.NewDecoder(req.Body).Decode(&body) != nil || len(body) != 4 ||
			body["failureCode"] != delegationRouteDeniedCode || tickets[body["token"]] != body["backendToken"] || body["backendToken"] == "" {
			t.Error("route report accepted caller-selected identity/outcome or wrong proof")
			w.WriteHeader(400)
			return
		}
		if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`).MatchString(body["attemptId"]) || body["attemptId"] == req.URL.Query().Get("attemptId") {
			t.Error("route attempt is not a Proxy-generated UUID")
			w.WriteHeader(400)
			return
		}
		if !accept {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(server.Close)
	return delegation.NewFailureReporter(server.URL)
}

func TestEachRouteDeniedAttemptHasItsOwnNonceNotTheCallersNonce(t *testing.T) {
	raw, grant, _, _ := scopedProxyFixture(t)
	token, err := parseRequestToken(raw, testutils.ParseTestPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	first := checkStreamRoute(token, grant, "/v2-beta/logs/", testutils.ParseTestPublicKey()).(*routeDenialFailure)
	second := checkStreamRoute(token, grant, "/v2-beta/logs/", testutils.ParseTestPublicKey()).(*routeDenialFailure)
	if first.attemptID == "" || first.attemptID == second.attemptID || len(first.targets) != 1 {
		t.Fatal("new wrong-route operation was collapsed to the ticket digest")
	}
	outer, _ := routeAggregate(t, "valid")
	outerToken, err := parseRequestToken(outer, testutils.ParseTestPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	outerGrant, err := streamGrant(outerToken)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := checkStreamRoute(outerToken, outerGrant, "/v2-beta/hoststats/project/", testutils.ParseTestPublicKey()).(*routeDenialFailure)
	if aggregate.attemptID == "" || len(aggregate.targets) != 2 {
		t.Fatal("aggregate did not retain one attempt across its two Host proofs")
	}
}

func TestRouteSubstitutionNeedsOneDurableReceiptAndNeverInitializesBackend(t *testing.T) {
	raw, _, verifier, _ := scopedProxyFixture(t)
	for _, scenario := range []struct {
		name            string
		accepted, proof bool
	}{{"accepted", true, true}, {"unavailable", false, true}, {"missingProof", true, false}} {
		t.Run(scenario.name, func(t *testing.T) {
			backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
			if !scenario.proof {
				backend.proof = ""
			}
			calls := &atomic.Int32{}
			handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), delegations: verifier,
				failures: routeReporter(t, map[string]string{raw: backend.proof}, scenario.accepted, calls)}
			request := httptest.NewRequest("GET", "http://proxy/v2-beta/logs/?failureCode=SUCCEEDED&keyId=caller", nil)
			request.Header.Set("Authorization", "Bearer "+raw)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			status, code, reports := 503, "AuditUnavailable", int32(1)
			if scenario.accepted && scenario.proof {
				status, code = 403, delegationRouteDeniedCode
			}
			if !scenario.proof {
				reports = 0
			}
			if response.Code != status || response.Header().Get("X-Api-Error-Code") != code || response.Header().Get("Cache-Control") != "no-store" ||
				strings.TrimSpace(response.Body.String()) != code || calls.Load() != reports || backend.initialized.Load() != 0 || backend.connected.Load() != 0 || strings.Contains(response.Body.String(), raw) {
				t.Fatal("unrecorded/wrong route denial or business side effect")
			}
		})
	}
}

func TestRouteSubstitutionDoesNotReportTamperedTokenOrChangeLegacyAndAllowedPath(t *testing.T) {
	raw, _, verifier, _ := scopedProxyFixture(t)
	backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
	calls := &atomic.Int32{}
	handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), delegations: verifier,
		failures: routeReporter(t, map[string]string{raw: backend.proof}, true, calls)}
	parts := strings.Split(raw, ".")
	parts[2] = "A" + parts[2][1:]
	if parts[2] == strings.Split(raw, ".")[2] {
		parts[2] = "B" + parts[2][1:]
	}
	request := httptest.NewRequest("GET", "http://proxy/v2-beta/logs/", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Join(parts, "."))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 || calls.Load() != 0 || backend.connected.Load() != 0 {
		t.Fatal("tampered signature became audit proof or authority")
	}
	legacy := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1"}, testutils.ParseTestPrivateKey())
	request.Header.Set("Authorization", "Bearer "+legacy)
	if _, host, err := handler.auth(request); err != nil || host != "h1" || calls.Load() != 0 {
		t.Fatal("legacy path gained a delegation rule")
	}
	request.URL.Path = "/v2-beta/exec/"
	request.Header.Set("Authorization", "Bearer "+raw)
	if _, host, err := handler.auth(request); err != nil || host != "h1" || calls.Load() != 0 {
		t.Fatal("valid scoped path changed")
	}
}

type routeMultiBackend struct{ capabilityTestBackend }

func (*routeMultiBackend) backendTicket(host string) string { return "trusted-" + host }

func routeAggregate(t *testing.T, variant string) (string, map[string]string) {
	t.Helper()
	expires := time.Now().Add(time.Hour).Unix()
	inners, proofs := []interface{}{}, map[string]string{}
	for _, host := range []string{"h1", "h2"} {
		grant := map[string]interface{}{"version": 1, "keyId": 12, "revision": 3, "targetType": "service", "targetId": "1s9",
			"operation": "read", "expiresAt": expires, "payload": map[string]interface{}{"hostUuid": host, "containerIds": map[string]interface{}{"docker9": "1i9"}}}
		if host == "h2" && strings.HasPrefix(variant, "mismatch:") {
			grant[strings.TrimPrefix(variant, "mismatch:")] = map[string]interface{}{"keyId": 13, "revision": 4, "targetType": "host", "targetId": "1s10", "operation": "exec"}[strings.TrimPrefix(variant, "mismatch:")]
		}
		raw := testutils.CreateTokenWithPayload(map[string]interface{}{delegation.Claim: grant, "exp": expires}, testutils.ParseTestPrivateKey())
		if host == "h2" && variant == "tampered" {
			p := strings.Split(raw, ".")
			p[2] = "A" + p[2][1:]
			if p[2] == strings.Split(raw, ".")[2] {
				p[2] = "B" + p[2][1:]
			}
			raw = strings.Join(p, ".")
		}
		entry := map[string]interface{}{"token": raw, "url": "ws://caller-must-not-supply-identity/v2-beta/containerstats/"}
		inners = append(inners, entry)
		if variant == "duplicate" {
			inners = append(inners, entry)
		}
		proofs[raw] = "trusted-" + host
	}
	outer := map[string]interface{}{"version": 1, "keyId": 12, "revision": 3, "targetType": "service", "targetId": "1s9",
		"operation": "read", "expiresAt": expires, "payload": map[string]interface{}{"service": inners}}
	return testutils.CreateTokenWithPayload(map[string]interface{}{delegation.Claim: outer, "exp": expires}, testutils.ParseTestPrivateKey()), proofs
}

func TestAggregateRouteDenialVerifiesAllInnerBindingsAndDedupesHostReceipts(t *testing.T) {
	for _, variant := range []string{"valid", "duplicate", "tampered", "mismatch:keyId", "mismatch:revision", "mismatch:targetType", "mismatch:targetId", "mismatch:operation", "reportFailed"} {
		t.Run(variant, func(t *testing.T) {
			raw, proofs := routeAggregate(t, variant)
			backend := &routeMultiBackend{capabilityTestBackend: capabilityTestBackend{capable: true}}
			calls := &atomic.Int32{}
			handler := &StatsHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), failures: routeReporter(t, proofs, variant != "reportFailed", calls)}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "http://proxy/v2-beta/hoststats/project/?token="+url.QueryEscape(raw), nil))
			status, reports := 503, int32(0)
			if variant == "valid" || variant == "duplicate" {
				status, reports = 403, 2
			}
			if variant == "reportFailed" {
				reports = 1
			}
			if response.Code != status || calls.Load() != reports || backend.initialized.Load() != 0 || backend.connected.Load() != 0 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("aggregate trusted-host receipt binding or pre-execution barrier failed")
			}
		})
	}
}

func TestPersistentSessionRouteDenialUsesTheSameReceiptBeforeAllocation(t *testing.T) {
	raw, _, verifier, _ := scopedProxyFixture(t)
	backend := &capabilityTestBackend{capable: true, proof: "trusted-backend"}
	calls := &atomic.Int32{}
	frontend := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), delegations: verifier, failures: routeReporter(t, map[string]string{raw: backend.proof}, true, calls)}
	handler := NewPersistentSessionHandler(frontend, backend)
	defer func() { close(handler.manager.stop); <-handler.manager.done }()
	body, _ := json.Marshal(map[string]string{"kind": "logs", "secret": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH", "target": "ws://proxy/v2-beta/logs/", "token": raw})
	request := httptest.NewRequest("POST", "http://proxy/v1/exec/sessions/psw_abcdefghijklmnopqrstuv01", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	handler.createSession(response, request, "psw_abcdefghijklmnopqrstuv01")
	if response.Code != 403 || response.Header().Get("X-Api-Error-Code") != delegationRouteDeniedCode || calls.Load() != 1 || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
		t.Fatal("persistent session allocated backend before recording route denial")
	}
}
