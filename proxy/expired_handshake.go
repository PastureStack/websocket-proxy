package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/PastureStack/websocket-proxy/delegation"
	jwt "github.com/golang-jwt/jwt/v5"
)

var errDelegationExpired = errors.New("ApiKeyExpired")

type expiredDelegationFailure struct {
	targets   []routeDenialTarget
	attemptID string
}

func (*expiredDelegationFailure) Error() string { return "ApiKeyExpired" }
func (*expiredDelegationFailure) Unwrap() error { return errDelegationExpired }

// Called only after normal authentication rejects expiry. Ignoring expiry here
// verifies audit identity only; the returned error can never install a grant.
func expiredDelegationAudit(raw string, publicKey interface{}) error {
	token, err := parseAuditSignatureJWT(raw, publicKey)
	if err != nil || !token.Valid {
		return nil
	}
	metadata, payload, scoped, ok := expiredAuditMetadata(token)
	if !ok {
		return nil
	}
	nonce := make([]byte, 16)
	failed := &expiredDelegationFailure{}
	if _, err := rand.Read(nonce); err != nil {
		return failed
	}
	nonce[6], nonce[8] = (nonce[6]&0x0f)|0x40, (nonce[8]&0x3f)|0x80
	encoded := hex.EncodeToString(nonce)
	failed.attemptID = encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	if host, _ := payload["hostUuid"].(string); host != "" {
		failed.targets = []routeDenialTarget{{raw, host}}
		return failed
	}
	// Existing aggregate tickets need one independently verified Host proof per
	// inner signed target, just like the fixed wrong-route failure lane.
	if metadata["operation"] != "read" || len(payload) != 1 {
		return failed
	}
	entries, ok := payload["project"].([]interface{})
	if !ok {
		entries, ok = payload["service"].([]interface{})
	}
	if !ok || len(entries) == 0 || len(entries) > maxStatsTargets {
		return failed
	}
	seen := map[string]bool{}
	targets := []routeDenialTarget{}
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			return failed
		}
		innerRaw, _ := entry["token"].(string)
		innerToken, err := parseAuditSignatureJWT(innerRaw, publicKey)
		if err != nil || !innerToken.Valid {
			return failed
		}
		innerEvidence, innerPayload, innerScoped, ok := expiredAuditMetadata(innerToken)
		if !ok || innerScoped != scoped || !sameExpiredAuditBindings(metadata, innerEvidence) {
			return failed
		}
		host, _ := innerPayload["hostUuid"].(string)
		if host == "" {
			return failed
		}
		if !seen[host] {
			targets = append(targets, routeDenialTarget{innerRaw, host})
			seen[host] = true
		}
	}
	failed.targets = targets
	return failed
}

// A full Key trace remains non-enforcing metadata, never a delegation Grant.
// The ordinary parser still rejects exp; Engine independently re-verifies the
// signature, receipt retention, original account and authenticated Host proof.
func expiredAuditMetadata(token *jwt.Token) (map[string]interface{}, map[string]interface{}, bool, bool) {
	claims, ok := mapClaims(token)
	if !ok {
		return nil, nil, false, false
	}
	expiry, ok := delegation.Integer(claims["exp"])
	if !ok || expiry <= 0 || expiry > time.Now().Unix() {
		return nil, nil, false, false
	}
	grant, err := streamGrant(token)
	if err != nil {
		return nil, nil, false, false
	}
	metadata, scoped := map[string]interface{}(nil), grant != nil
	payload := map[string]interface{}{}
	if scoped {
		if claims["apiKeyAudit"] != nil {
			return nil, nil, false, false
		}
		metadata, ok = objectClaim(token, delegation.Claim)
		payload = grant.Payload
	} else {
		metadata, ok = objectClaim(token, "apiKeyAudit")
		for field, value := range claims {
			if field != "apiKeyAudit" && field != "exp" && field != "iat" {
				payload[field] = value
			}
		}
	}
	if !ok {
		return nil, nil, false, false
	}
	version, versionOK := delegation.Integer(metadata["version"])
	revision, revisionOK := delegation.Integer(metadata["revision"])
	issued, issuedOK := delegation.Integer(metadata["issuedAt"])
	if !versionOK || version != 1 || !revisionOK || revision < 0 || !issuedOK || issued <= 0 || issued >= expiry || issued > time.Now().Unix()+30 {
		return nil, nil, false, false
	}
	for _, field := range []string{"keyId", "principalId", "accountId"} {
		value, valid := delegation.Integer(metadata[field])
		if !valid || value <= 0 {
			return nil, nil, false, false
		}
	}
	for _, field := range []string{"targetType", "targetId", "requestId", "requestMethod"} {
		value, valid := metadata[field].(string)
		if !valid || value == "" || len(value) > 256 {
			return nil, nil, false, false
		}
	}
	if metadata["operation"] != "logs" && metadata["operation"] != "exec" && metadata["operation"] != "read" {
		return nil, nil, false, false
	}
	return metadata, payload, scoped, true
}

func sameExpiredAuditBindings(outer, inner map[string]interface{}) bool {
	for _, field := range []string{"principalId", "accountId"} {
		value, ok := delegation.Integer(outer[field])
		if !ok || value <= 0 {
			return false
		}
	}
	for _, field := range []string{"requestId", "requestMethod"} {
		value, ok := outer[field].(string)
		if !ok || value == "" {
			return false
		}
	}
	// These are the shared Engine nested-envelope bindings, plus the common
	// request UUID from the same original API request. Host payloads may differ.
	for _, field := range []string{"keyId", "revision", "targetType", "targetId", "operation", "principalId", "accountId", "requestId", "requestMethod", "requestAction", "requestLink"} {
		if !reflect.DeepEqual(outer[field], inner[field]) {
			return false
		}
	}
	return true
}

func reportExpiredDenial(reporter *delegation.FailureReporter, backend backendProxy, err error) (int, string) {
	var failure *expiredDelegationFailure
	proof, ok := backend.(backendTicketSource)
	if !errors.As(err, &failure) || !ok || len(failure.targets) == 0 || len(failure.targets) > maxStatsTargets {
		return http.StatusServiceUnavailable, "AuditUnavailable"
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, target := range failure.targets {
		if time.Now().After(deadline) || !reporter.ReportExpired(target.token, proof.backendTicket(target.host), failure.attemptID) {
			return http.StatusServiceUnavailable, "AuditUnavailable"
		}
	}
	return http.StatusUnauthorized, "ApiKeyExpired"
}

func writeExpiredDenial(rw http.ResponseWriter, reporter *delegation.FailureReporter, backend backendProxy, err error) {
	status, code := reportExpiredDenial(reporter, backend, err)
	rw.Header().Set(streamErrorCodeHeader, code)
	rw.Header().Set("X-Api-Error-Code", code)
	rw.Header().Set("Cache-Control", "no-store")
	http.Error(rw, code, status)
}
