package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/delegation"
	"github.com/PastureStack/websocket-proxy/testutils"
	"github.com/gorilla/websocket"
)

type capabilityTestBackend struct {
	capable     bool
	proof       string
	initialized atomic.Int32
	connected   atomic.Int32
}

func (b *capabilityTestBackend) initializeClient(string) (string, <-chan common.Message, error) {
	b.initialized.Add(1)
	return "message", make(chan common.Message), nil
}
func (b *capabilityTestBackend) connect(string, string, string) error { b.connected.Add(1); return nil }
func (*capabilityTestBackend) send(string, string, string) error      { return nil }
func (*capabilityTestBackend) closeConnection(string, string) error   { return nil }
func (*capabilityTestBackend) releaseConnection(string, string) error { return nil }
func (*capabilityTestBackend) hasBackend(string) bool                 { return true }
func (b *capabilityTestBackend) supportsKeyTraces(string) bool        { return b.capable }
func (b *capabilityTestBackend) backendTicket(string) string          { return b.proof }

func capabilityReporter(t *testing.T, expectedToken, proof string, accepted bool, calls *atomic.Int32) *delegation.FailureReporter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		var body map[string]string
		if request.URL.Path != "/v2-beta/apiKeyDelegationFailure/report" || request.Method != "POST" || request.Header.Get("Authorization") != "" || request.URL.RawQuery != "" || json.NewDecoder(request.Body).Decode(&body) != nil || len(body) != 2 || body["token"] != expectedToken || body["backendToken"] != proof {
			t.Error("failure report escaped the fixed dual-ticket contract")
			w.WriteHeader(400)
			return
		}
		if !accepted {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true})
	}))
	t.Cleanup(server.Close)
	return delegation.NewFailureReporter(server.URL)
}

func TestVerifiedFullAndRestrictedTicketsNeedCapableBackendButCookieWireDoesNot(t *testing.T) {
	scoped, _, verifier, _ := scopedProxyFixture(t)
	full := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	cookie := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1"}, testutils.ParseTestPrivateKey())
	for _, test := range []struct {
		name, token string
		key         bool
	}{{"full", full, true}, {"restricted", scoped, true}, {"ordinaryCookieTicket", cookie, false}} {
		t.Run(test.name, func(t *testing.T) {
			backend := &capabilityTestBackend{proof: "authenticated-backend-proof"}
			calls := &atomic.Int32{}
			handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), delegations: verifier, failures: capabilityReporter(t, test.token, backend.proof, true, calls)}
			request := httptest.NewRequest("GET", "http://proxy/v2-beta/exec/?hostApiCapabilities=key-audit-v1,key-delegation-v1", nil)
			request.Header.Set("Authorization", "Bearer "+test.token)
			if test.key {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != 503 || response.Header().Get(streamErrorCodeHeader) != backendAuditCapabilityCode || strings.TrimSpace(response.Body.String()) != backendAuditCapabilityCode || backend.initialized.Load() != 0 || backend.connected.Load() != 0 || calls.Load() != 1 {
					t.Fatal("old backend received Key payload or unrecorded/wrong failure")
				}
			} else {
				if _, host, err := handler.auth(request); err != nil || host != "h1" || calls.Load() != 0 {
					t.Fatal("ordinary cookie wire gained a Key capability requirement")
				}
			}
			backend.capable = true
			if _, _, err := handler.auth(request); err != nil {
				t.Fatal("new authenticated producer rejected")
			}
		})
	}
}

func TestCapabilityFailureMustBeDurablyAcceptedBeforeIts503AndNeverRetriesBusiness(t *testing.T) {
	raw := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	backend := &capabilityTestBackend{proof: "authenticated-backend-proof"}
	calls := &atomic.Int32{}
	handler := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), failures: capabilityReporter(t, raw, backend.proof, false, calls)}
	request := httptest.NewRequest("GET", "http://proxy/v2-beta/logs/", nil)
	request.Header.Set("Authorization", "Bearer "+raw)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 503 || response.Header().Get(streamErrorCodeHeader) != "AuditUnavailable" || calls.Load() != 1 || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
		t.Fatal("audit outage became permission denial, lost bounds, or started business")
	}
}

type capabilityManager struct {
	registered chan bool
	calls      atomic.Int32
}

func (m *capabilityManager) addBackend(string, *websocket.Conn) { m.calls.Add(1) }
func (m *capabilityManager) addBackendWithKeyCapabilities(_ string, ws *websocket.Conn, capable bool, _ string) {
	m.calls.Add(1)
	m.registered <- capable
	_ = ws.Close()
}
func (*capabilityManager) removeBackend(string, string)         {}
func (*capabilityManager) closeConnection(string, string) error { return nil }

func TestDeclaredKeyCapabilitiesCompatiblePatch(t *testing.T) {
	for _, version := range []string{"0.38.5", "0.38.6", "0.38.7", "0.38.10", "0.38.100"} {
		query := url.Values{"hostApiVersion": {version}, "hostApiCapabilities": {"key-audit-v1,key-delegation-v1"}, "mode": {"host"}}
		if !declaredKeyCapabilities(&http.Request{URL: &url.URL{RawQuery: query.Encode()}}) {
			t.Errorf("compatible canonical patch %q rejected", version)
		}
	}
	for _, version := range []string{"", "0.38.0", "0.38.4", "0.38", "0.38.5.0", "v0.38.5", "00.38.5", "0.038.5",
		"0.38.05", "0.38.+5", "0.38.-5", "0.38.5-alpha", "0.38.5+build", " 0.38.5", "0.38.5 ", "0.38.5\n",
		"0.38.18446744073709551616", "0.39.5", "1.38.5", "0.37.999"} {
		query := url.Values{"hostApiVersion": {version}, "hostApiCapabilities": {"key-audit-v1,key-delegation-v1"}}
		if declaredKeyCapabilities(&http.Request{URL: &url.URL{RawQuery: query.Encode()}}) {
			t.Errorf("unsupported version %q accepted", version)
		}
	}
	valid := "hostApiVersion=0.38.6&hostApiCapabilities=key-audit-v1,key-delegation-v1"
	for _, query := range []string{
		"hostApiCapabilities=key-audit-v1,key-delegation-v1", "hostApiVersion=0.38.6",
		valid + "&hostApiVersion=0.38.6", valid + "&hostApiVersion=",
		valid + "&hostApiCapabilities=key-audit-v1,key-delegation-v1", valid + "&hostApiCapabilities=",
		"hostApiVersion=0.38.6&hostApiCapabilities=", "hostApiVersion=0.38.6&hostApiCapabilities=key-audit-v1",
		"hostApiVersion=0.38.6&hostApiCapabilities=key-delegation-v1,key-audit-v1",
		"hostApiVersion=0.38.6&hostApiCapabilities=key-audit-v1,key-delegation-v2",
		valid + ";invalid", valid + "&hostApiVersion=%zz",
	} {
		if declaredKeyCapabilities(&http.Request{URL: &url.URL{RawQuery: query}}) {
			t.Errorf("malformed or ambiguous declaration accepted: %q", query)
		}
	}
}

func TestCompatiblePatchBackendRegistrationKeepsKeyAndOrdinaryAuth(t *testing.T) {
	scoped, _, verifier, _ := scopedProxyFixture(t)
	full := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	ordinary := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1"}, testutils.ParseTestPrivateKey())
	for _, version := range []string{"0.38.5", "0.38.6"} {
		t.Run(version, func(t *testing.T) {
			manager := &capabilityManager{registered: make(chan bool, 1)}
			handler := &BackendHandler{proxyManager: manager, parsedPublicKey: testutils.ParseTestPublicKey()}
			server := httptest.NewServer(handler)
			defer server.Close()
			backendToken := testutils.CreateTokenWithPayload(map[string]interface{}{"reportedUuid": "h1"}, testutils.ParseTestPrivateKey())
			query := url.Values{"hostApiVersion": {version}, "hostApiCapabilities": {"key-audit-v1,key-delegation-v1"}}
			headers := http.Header{"Authorization": []string{"Bearer " + backendToken}}
			ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/?"+query.Encode(), headers)
			if err != nil {
				t.Fatal("authenticated compatible backend registration failed")
			}
			defer ws.Close()
			var capable bool
			select {
			case capable = <-manager.registered:
			case <-time.After(time.Second):
				t.Fatal("backend registration barrier timed out")
			}
			if !capable || manager.calls.Load() != 1 {
				t.Fatal("authenticated compatible patch lost capability")
			}
			backend := &capabilityTestBackend{capable: capable}
			frontend := &FrontendHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey(), delegations: verifier}
			for _, raw := range []string{scoped, full, ordinary} {
				request := httptest.NewRequest("GET", "http://proxy/v2-beta/exec/", nil)
				request.Header.Set("Authorization", "Bearer "+raw)
				if _, host, err := frontend.auth(request); err != nil || host != "h1" {
					t.Fatal("registered capability did not preserve Key and ordinary authentication")
				}
			}
		})
	}
}

func TestBackendCapabilityCannotBeForgedWithoutAnAuthenticatedReportedHostTicket(t *testing.T) {
	manager := &capabilityManager{registered: make(chan bool, 1)}
	handler := &BackendHandler{proxyManager: manager, parsedPublicKey: testutils.ParseTestPublicKey()}
	for _, raw := range []string{"forged", testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1"}, testutils.ParseTestPrivateKey())} {
		request := httptest.NewRequest("GET", "http://proxy/backend?hostApiVersion=0.38.5&hostApiCapabilities=key-audit-v1,key-delegation-v1", nil)
		request.Header.Set("Authorization", "Bearer "+raw)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 401 || manager.calls.Load() != 0 {
			t.Fatal("public capability claim registered a backend")
		}
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	backendToken := testutils.CreateTokenWithPayload(map[string]interface{}{"reportedUuid": "h1"}, testutils.ParseTestPrivateKey())
	headers := http.Header{"Authorization": []string{"Bearer " + backendToken}}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/?hostApiVersion=0.38.5&hostApiCapabilities=key-audit-v1,key-delegation-v1", headers)
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.Close()
	select {
	case capable := <-manager.registered:
		if !capable {
			t.Fatal("authenticated producer declaration lost")
		}
	case <-time.After(time.Second):
		t.Fatal("backend registration barrier timed out")
	}
}

func TestBackendReplacementCannotCarryAKeyConnectIntoAnOldConnection(t *testing.T) {
	raw := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	old := &multiplexer{messagesToBackend: make(chan string, 1), frontendMu: &sync.RWMutex{}, frontendChans: make(map[string]chan<- common.Message), done: make(chan struct{})}
	manager := &backendProxyManager{multiplexers: map[string]*multiplexer{"h1": old}, mu: &sync.RWMutex{}}
	if _, _, err := manager.initializeKeyClient("h1"); !errors.Is(err, errBackendAuditCapability) {
		t.Fatal("old backend allocated Key client")
	}
	if err := manager.connect("h1", "previous-client", "/v2-beta/exec/?token="+raw); !errors.Is(err, errBackendAuditCapability) || len(old.messagesToBackend) != 0 {
		t.Fatal("replacement backend received Key connect")
	}
	if err := old.connect("previous-client", "/v2-beta/exec/"); err == nil || len(old.messagesToBackend) != 0 {
		t.Fatal("stale client attached to another backend")
	}
}

func TestBearerKeyConnectRetainsVerifiedTicketAndCookieURLIsUnchanged(t *testing.T) {
	raw := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	token, err := parseRequestToken(raw, testutils.ParseTestPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://proxy/v2-beta/exec/?existing=value", nil)
	request.Header.Set("Authorization", "Bearer "+raw)
	internal := keyRequestURL(request, token)
	parsed, _ := url.Parse(internal)
	if !keyTraceURL(internal) || parsed.Query().Get("token") != raw || parsed.Query().Get("existing") != "value" || request.URL.Query().Get("token") != "" {
		t.Fatal("Bearer ticket escaped the internal capability gate or mutated client URL")
	}
	cookieRaw := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1"}, testutils.ParseTestPrivateKey())
	cookie, _ := parseRequestToken(cookieRaw, testutils.ParseTestPublicKey())
	if keyRequestURL(request, cookie) != request.URL.String() {
		t.Fatal("ordinary Cookie ticket wire changed")
	}
}

func TestAggregateCapabilityFailureUsesTheVerifiedHostBoundInnerTicket(t *testing.T) {
	inner := testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	outer := testutils.CreateTokenWithPayload(map[string]interface{}{"project": []interface{}{map[string]interface{}{"token": inner, "url": "ws://proxy/v2-beta/hoststats/"}}, "apiKeyAudit": map[string]interface{}{"version": 1}}, testutils.ParseTestPrivateKey())
	backend := &capabilityTestBackend{proof: "authenticated-backend-proof"}
	handler := &StatsHandler{backend: backend, parsedPublicKey: testutils.ParseTestPublicKey()}
	_, err := handler.parseStatsInfo(httptest.NewRequest("GET", "http://proxy/v2-beta/hoststats/project/", nil), outer, true)
	var failure *backendCapabilityFailure
	if !errors.As(err, &failure) || failure.token != inner || failure.host != "h1" || backend.initialized.Load() != 0 || backend.connected.Load() != 0 {
		t.Fatal("aggregate denial lost its exact host proof or started business")
	}
	calls := &atomic.Int32{}
	if reportCapabilityError(capabilityReporter(t, inner, backend.proof, true, calls), backend, err) != backendAuditCapabilityCode || calls.Load() != 1 {
		t.Fatal("host-bound aggregate failure was not accepted")
	}
}
