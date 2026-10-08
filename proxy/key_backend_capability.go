package proxy

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/delegation"
	jwt "github.com/golang-jwt/jwt/v5"
)

const backendAuditCapabilityCode = "BackendAuditCapabilityUnavailable"
const streamErrorCodeHeader = "X-PastureStack-Stream-Error-Code"

var errBackendAuditCapability = errors.New(backendAuditCapabilityCode)

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
