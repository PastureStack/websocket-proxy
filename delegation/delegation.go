// Package delegation verifies target-bound API Key stream tickets against the
// trusted Engine. It never accepts an introspection URL from a JWT.
package delegation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const Claim = "apiKeyDelegation"
const MaxTokenBytes = 16 << 10
const Interval = 5 * time.Second

var ErrDenied = errors.New("delegated API key access denied")

type Grant struct {
	KeyID      int64
	Revision   int64
	TargetType string
	TargetID   string
	Operation  string
	ExpiresAt  int64
	Payload    map[string]interface{}
}

func Integer(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		result, err := n.Int64()
		return result, err == nil
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < math.MinInt64 || n >= math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}

// nil denotes an unchanged legacy token; a malformed new token is never legacy.
func Parse(claims map[string]interface{}) (*Grant, error) {
	raw, found := claims[Claim]
	if !found {
		return nil, nil
	}
	for _, old := range []string{"hostUuid", "exec", "logs", "resourceId", "containerIds", "project", "service"} {
		if _, present := claims[old]; present {
			return nil, ErrDenied
		}
	}
	data, ok := raw.(map[string]interface{})
	if !ok {
		return nil, ErrDenied
	}
	version, ok := Integer(data["version"])
	if !ok || version != 1 {
		return nil, ErrDenied
	}
	key, keyOK := Integer(data["keyId"])
	revision, revisionOK := Integer(data["revision"])
	expiry, expiryOK := Integer(data["expiresAt"])
	jwtExpiry, jwtExpiryOK := Integer(claims["exp"])
	typ, typeOK := data["targetType"].(string)
	id, idOK := data["targetId"].(string)
	operation, operationOK := data["operation"].(string)
	payload, payloadOK := data["payload"].(map[string]interface{})
	if !keyOK || key <= 0 || !revisionOK || revision <= 0 || !expiryOK || !jwtExpiryOK || expiry != jwtExpiry ||
		!typeOK || typ == "" || len(typ) > 256 || !idOK || id == "" || len(id) > 256 || !operationOK || !payloadOK || len(payload) == 0 || len(payload) > 256 {
		return nil, ErrDenied
	}
	if operation != "read" && operation != "exec" && operation != "logs" {
		return nil, ErrDenied
	}
	return &Grant{key, revision, typ, id, operation, expiry, payload}, nil
}

func (g *Grant) AllowsPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || (parts[0] != "v1" && parts[0] != "v2-beta" && parts[0] != "v2") {
		return false
	}
	switch g.Operation {
	case "exec":
		_, ok := g.Payload["exec"]
		return ok && parts[1] == "exec" && len(parts) == 2
	case "logs":
		_, ok := g.Payload["logs"]
		return ok && parts[1] == "logs" && len(parts) == 2
	case "read":
		if _, ok := g.Payload["resourceId"]; ok {
			return (parts[1] == "hoststats" || parts[1] == "stats") && len(parts) == 2
		}
		if _, ok := g.Payload["containerIds"]; ok {
			return (parts[1] == "containerstats" || parts[1] == "stats") && (len(parts) == 2 || len(parts) == 3)
		}
		if _, ok := g.Payload["project"]; ok {
			return parts[1] == "hoststats" && len(parts) == 3 && parts[2] == "project"
		}
		if _, ok := g.Payload["service"]; ok {
			return parts[1] == "containerstats" && len(parts) == 3 && parts[2] == "service"
		}
	}
	return false
}

type Verifier struct {
	Endpoint string
	Client   *http.Client
	Now      func() time.Time
}

func New(platformURL string) *Verifier {
	v := &Verifier{Now: time.Now, Client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	u, err := url.Parse(platformURL)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		u.Path = "/v2-beta/apiKeyDelegation/introspect"
		u.RawPath = ""
		v.Endpoint = u.String()
	}
	return v
}

func (v *Verifier) Check(ctx context.Context, token string, g *Grant) error {
	if g == nil {
		return nil
	}
	if v == nil || v.Endpoint == "" || v.Client == nil || v.Now == nil || token == "" || len(token) > MaxTokenBytes || v.Now().Unix() >= g.ExpiresAt {
		return ErrDenied
	}
	encoded, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Endpoint, bytes.NewReader(encoded))
	if err != nil {
		return ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := v.Client.Do(req)
	if err != nil {
		return ErrDenied
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ErrDenied
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return ErrDenied
	}
	var result map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		return ErrDenied
	}
	key, keyOK := Integer(result["keyId"])
	revision, revisionOK := Integer(result["revision"])
	expiry, expiryOK := Integer(result["expiresAt"])
	digest := sha256.Sum256([]byte(token))
	if result["allowed"] != true || !keyOK || key != g.KeyID || !revisionOK || revision != g.Revision || !expiryOK || expiry != g.ExpiresAt ||
		result["targetType"] != g.TargetType || result["targetId"] != g.TargetID || result["operation"] != g.Operation || result["tokenDigest"] != hex.EncodeToString(digest[:]) || v.Now().Unix() >= g.ExpiresAt {
		return ErrDenied
	}
	return nil
}

// Run accepts controllable barriers: tests do not sleep to simulate revocation.
func (v *Verifier) Run(ctx context.Context, token string, g *Grant, ticks, expiry <-chan time.Time, deny func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiry:
			deny()
			return
		case <-ticks:
			if v.Check(ctx, token, g) != nil {
				deny()
				return
			}
		}
	}
}

func (v *Verifier) Watch(parent context.Context, token string, g *Grant, deny func()) context.CancelFunc {
	ctx, cancel := context.WithCancel(parent)
	if g == nil {
		return cancel
	}
	ticker := time.NewTicker(Interval)
	lifetime := time.Unix(g.ExpiresAt, 0).Sub(v.Now())
	if lifetime < 0 {
		lifetime = 0
	}
	timer := time.NewTimer(lifetime)
	go func() { defer ticker.Stop(); defer timer.Stop(); v.Run(ctx, token, g, ticker.C, timer.C, deny) }()
	return cancel
}
