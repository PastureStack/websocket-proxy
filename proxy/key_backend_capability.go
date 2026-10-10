package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/delegation"
	jwt "github.com/golang-jwt/jwt/v5"
)

const backendAuditCapabilityCode = "BackendAuditCapabilityUnavailable"
const streamErrorCodeHeader = "X-PastureStack-Stream-Error-Code"
const delegationRouteDeniedCode = "DelegationRouteDenied"

var errBackendAuditCapability = errors.New(backendAuditCapabilityCode)
var errDelegationRouteDenied = errors.New(delegationRouteDeniedCode)

type routeDenialTarget struct{ token, host string }
type routeDenialFailure struct {
	targets   []routeDenialTarget
	attemptID string
}

func (*routeDenialFailure) Error() string { return delegationRouteDeniedCode }
func (*routeDenialFailure) Unwrap() error { return errDelegationRouteDenied }

// Call only after signature validation and Grant parsing. This records a fixed
// operational denial; it never turns either ticket into general authorization.
func checkStreamRoute(token *jwt.Token, grant *delegation.Grant, path string, publicKey interface{}) error {
	if grant == nil || grant.AllowsPath(path) {
		return nil
	}
	// One nonce belongs to this observed HTTP attempt, never a browser value.
	// It remains attached to this failure for every per-Host receipt.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return &routeDenialFailure{}
	}
	nonce[6], nonce[8] = (nonce[6]&0x0f)|0x40, (nonce[8]&0x3f)|0x80
	encoded := hex.EncodeToString(nonce)
	attemptID := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	host, _ := grant.Payload["hostUuid"].(string)
	if host != "" {
		return &routeDenialFailure{targets: []routeDenialTarget{{token.Raw, host}}, attemptID: attemptID}
	}
	// An aggregate has no single Host identity. Validate every inner signature
	// and binding before sending any receipt. URLs and browser inputs supply no
	// identity; only the original signed outer payload may supply inner tickets.
	failed := &routeDenialFailure{}
	if grant.Operation != "read" || len(grant.Payload) != 1 {
		return failed
	}
	raw, present := grant.Payload["project"]
	if !present {
		raw = grant.Payload["service"]
	}
	entries, ok := raw.([]interface{})
	if !ok || len(entries) == 0 || len(entries) > maxStatsTargets {
		return failed
	}
	seen := map[string]bool{}
	targets := []routeDenialTarget{}
	for _, entry := range entries {
		data, ok := entry.(map[string]interface{})
		if !ok {
			return failed
		}
		rawToken, ok := data["token"].(string)
		if !ok {
			return failed
		}
		innerToken, err := parseRequestToken(rawToken, publicKey)
		if err != nil || !innerToken.Valid {
			return failed
		}
		inner, err := streamGrant(innerToken)
		if err != nil || inner == nil || inner.KeyID != grant.KeyID || inner.Revision != grant.Revision ||
			inner.TargetType != grant.TargetType || inner.TargetID != grant.TargetID || inner.Operation != grant.Operation {
			return failed
		}
		innerHost, ok := inner.Payload["hostUuid"].(string)
		if !ok || innerHost == "" {
			return failed
		}
		if !seen[innerHost] {
			targets = append(targets, routeDenialTarget{rawToken, innerHost})
			seen[innerHost] = true
		}
	}
	failed.targets = targets
	failed.attemptID = attemptID
	return failed
}

func reportRouteDenial(reporter *delegation.FailureReporter, backend backendProxy, err error) (int, string) {
	var failure *routeDenialFailure
	proof, ok := backend.(backendTicketSource)
	if !errors.As(err, &failure) || !ok || len(failure.targets) == 0 || len(failure.targets) > maxStatsTargets {
		return http.StatusServiceUnavailable, "AuditUnavailable"
	}
	// Receipt failure never retries a Docker action. Bound the entire aggregate
	// attempt as well as each existing two-second HTTP request.
	deadline := time.Now().Add(5 * time.Second)
	for _, target := range failure.targets {
		if time.Now().After(deadline) || !reporter.ReportRouteDenied(target.token, proof.backendTicket(target.host), failure.attemptID) {
			return http.StatusServiceUnavailable, "AuditUnavailable"
		}
	}
	return http.StatusForbidden, delegationRouteDeniedCode
}

func writeRouteDenial(rw http.ResponseWriter, reporter *delegation.FailureReporter, backend backendProxy, err error) {
	status, code := reportRouteDenial(reporter, backend, err)
	rw.Header().Set(streamErrorCodeHeader, code)
	rw.Header().Set("X-Api-Error-Code", code)
	rw.Header().Set("Cache-Control", "no-store")
	http.Error(rw, code, status)
}

type keyTraceBackend interface{ supportsKeyTraces(string) bool }
type backendTicketSource interface{ backendTicket(string) string }
type backendCapabilityFailure struct{ token, host string }

func (*backendCapabilityFailure) Error() string { return backendAuditCapabilityCode }
func (*backendCapabilityFailure) Unwrap() error { return errBackendAuditCapability }

type keyTraceInitializer interface {
	initializeKeyClient(string) (string, <-chan common.Message, error)
}

func declaredKeyCapabilities(req *http.Request) bool {
	query := req.URL.Query()
	return len(query["hostApiVersion"]) == 1 && query.Get("hostApiVersion") == "0.38.5" && len(query["hostApiCapabilities"]) == 1 && query.Get("hostApiCapabilities") == "key-audit-v1,key-delegation-v1"
}

// The caller must have verified the JWT before considering these claims.
func isKeyTrace(token *jwt.Token) bool {
	claims, ok := mapClaims(token)
	if !ok {
		return false
	}
	_, scoped := claims["apiKeyDelegation"]
	_, legacy := claims["apiKeyAudit"]
	return scoped || legacy
}

func requireKeyBackend(backend backendProxy, token *jwt.Token, host string) error {
	if !isKeyTrace(token) {
		return nil
	}
	capable, ok := backend.(keyTraceBackend)
	if !ok || !capable.supportsKeyTraces(host) {
		return &backendCapabilityFailure{token: token.Raw, host: host}
	}
	return nil
}

// Internal connection URLs already passed signature/live checks. Parsing here
// only adds a conservative operational restriction, never grants authority.
func keyTraceURL(raw string) bool {
	target, err := url.Parse(raw)
	if err != nil {
		return true
	}
	rawToken := target.Query().Get("token")
	if rawToken == "" {
		return false
	}
	if len(rawToken) > maxJWTBytes {
		return true
	}
	claims := jwt.MapClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(rawToken, claims)
	return err != nil || isKeyTrace(token)
}

// Bearer authentication and query authentication must carry the same verified
// ticket into the internal connect gate. Do not mutate the client's URL or the
// ordinary (non-Key) wire contract.
func keyRequestURL(req *http.Request, token *jwt.Token) string {
	if !isKeyTrace(token) {
		return req.URL.String()
	}
	target := *req.URL
	query := target.Query()
	query.Set("token", token.Raw)
	target.RawQuery = query.Encode()
	return target.String()
}

func initializeForURL(backend backendProxy, host, target string) (string, <-chan common.Message, error) {
	if keyTraceURL(target) {
		if initializer, ok := backend.(keyTraceInitializer); ok {
			return initializer.initializeKeyClient(host)
		}
		if capable, ok := backend.(keyTraceBackend); !ok || !capable.supportsKeyTraces(host) {
			return "", nil, errBackendAuditCapability
		}
	}
	return backend.initializeClient(host)
}

func reportBackendFailure(reporter *delegation.FailureReporter, backend backendProxy, token, host string) string {
	proof, ok := backend.(backendTicketSource)
	if !ok || !reporter.Report(token, proof.backendTicket(host)) {
		return "AuditUnavailable"
	}
	return backendAuditCapabilityCode
}

func reportCapabilityError(reporter *delegation.FailureReporter, backend backendProxy, err error) string {
	var failure *backendCapabilityFailure
	if !errors.As(err, &failure) {
		return "AuditUnavailable"
	}
	return reportBackendFailure(reporter, backend, failure.token, failure.host)
}

func writeBackendAuditUnavailable(rw http.ResponseWriter, code string) {
	rw.Header().Set(streamErrorCodeHeader, code)
	http.Error(rw, code, http.StatusServiceUnavailable)
}
