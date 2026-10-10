package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/delegation"
)

const maxStatsTargets = 256

type StatsHandler struct {
	backend         backendProxy
	parsedPublicKey interface{}
	delegations     *delegation.Verifier
	failures        *delegation.FailureReporter
}

type statsInfo struct {
	hostKey     string
	url         string
	msgKey      string
	respChannel <-chan common.Message
}

func (s *statsInfo) initializeClient(h *StatsHandler) error {
	if s.hostKey == "" {
		return fmt.Errorf("hostKey is empty")
	}
	msgKey, respChannel, err := initializeForURL(h.backend, s.hostKey, s.url)
	if err != nil {
		return err
	}
	s.msgKey = msgKey
	s.respChannel = respChannel
	return nil
}

func (s *statsInfo) closeClient(h *StatsHandler) {
	if s.msgKey != "" {
		_ = h.backend.closeConnection(s.hostKey, s.msgKey)
	}
}

func (s *statsInfo) connect(h *StatsHandler) error {
	return h.backend.connect(s.hostKey, s.msgKey, s.url)
}

func (h *StatsHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	multiHost := false

	if strings.HasSuffix(req.URL.Path, "project") || strings.HasSuffix(req.URL.Path, "project/") || strings.HasSuffix(req.URL.Path, "service") || strings.HasSuffix(req.URL.Path, "service/") {
		multiHost = true
	}

	tokenString, authToken, err := h.auth(req)
	if err != nil {
		if errors.Is(err, errDelegationExpired) {
			writeExpiredDenial(rw, h.failures, h.backend, err)
			return
		}
		if errors.Is(err, errDelegationRouteDenied) {
			writeRouteDenial(rw, h.failures, h.backend, err)
			return
		}
		http.Error(rw, "Failed authentication", 401)
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: workspaceSameOrigin,
	}
	ws, err := upgrader.Upgrade(rw, req, nil)
	if err != nil {
		http.Error(rw, "Failed to upgrade connection.", 500)
		return
	}
	ws.SetReadLimit(common.MaxWireMessageBytes)

	if ok, _ := boolClaim(authToken, "payload"); ok {
		ws.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, content, err := ws.ReadMessage()
		if err != nil {
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Invalid statistics payload"), time.Now().Add(time.Second))
			return
		}
		_ = ws.SetReadDeadline(time.Time{})
		tokenString = string(content)
	}

	statsInfoStructs, err := h.parseStatsInfo(req, tokenString, multiHost)
	if err != nil {
		log.Error("Failed to read statistics targets")
		if errors.Is(err, errDelegationRouteDenied) {
			status, code := reportRouteDenial(h.failures, h.backend, err)
			closeCode := websocket.ClosePolicyViolation
			if status == http.StatusServiceUnavailable {
				closeCode = websocket.CloseTryAgainLater
			}
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(closeCode, code), time.Now().Add(time.Second))
			closeConnection(ws)
			return
		}
		if errors.Is(err, errBackendAuditCapability) {
			closeForBackendOutcome(ws, reportCapabilityError(h.failures, h.backend, err)+":503")
			closeConnection(ws)
			return
		}
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Invalid statistics targets"), time.Now().Add(time.Second))
		return
	}
	actualToken, err := parseRequestToken(tokenString, h.parsedPublicKey)
	if err != nil {
		closeConnection(ws)
		return
	}
	grant, err := streamGrant(actualToken)
	if err != nil {
		closeConnection(ws)
		return
	}
	if grant != nil {
		cancel := h.delegations.Watch(req.Context(), tokenString, grant, func() { closeConnection(ws) })
		defer cancel()
	}

	var mutex sync.Mutex
	var countMutex sync.Mutex

	doneCounter := len(statsInfoStructs)

	defer func() {
		for _, statsInfoStruct := range statsInfoStructs {
			statsInfoStruct.closeClient(h)
		}
		closeConnection(ws)
	}()

	for _, statsInfoStruct := range statsInfoStructs {
		if err := statsInfoStruct.initializeClient(h); err != nil {
			if errors.Is(err, errBackendAuditCapability) {
				target, _ := url.Parse(statsInfoStruct.url)
				closeForBackendOutcome(ws, reportBackendFailure(h.failures, h.backend, target.Query().Get("token"), statsInfoStruct.hostKey)+":503")
			}
			return
		}
	}

	for _, statsInfoStruct := range statsInfoStructs {
		// Send response messages to client
		go func(s *statsInfo) {
			for {
				message, ok := <-s.respChannel
				if !ok {
					return
				}
				switch message.Type {
				case common.Body:
					mutex.Lock()
					ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := ws.WriteMessage(1, []byte(message.Body)); err != nil {
						mutex.Unlock()
						closeConnection(ws)
						return
					}
					mutex.Unlock()
				case common.Close:
					closeForBackendOutcome(ws, message.Body)
					countMutex.Lock()
					doneCounter--
					shouldClose := doneCounter == 0
					countMutex.Unlock()
					if shouldClose {
						closeConnection(ws)
					}
					return
				}
			}
		}(statsInfoStruct)

		if err = statsInfoStruct.connect(h); err != nil {
			if errors.Is(err, errBackendAuditCapability) {
				target, _ := url.Parse(statsInfoStruct.url)
				closeForBackendOutcome(ws, reportBackendFailure(h.failures, h.backend, target.Query().Get("token"), statsInfoStruct.hostKey)+":503")
			}
			return
		}
	}
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			return
		}
	}
}

func (h *StatsHandler) auth(req *http.Request) (string, *jwt.Token, error) {
	tokenString := req.URL.Query().Get("token")
	token, err := parseRequestToken(tokenString, h.parsedPublicKey)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			if auditErr := expiredDelegationAudit(tokenString, h.parsedPublicKey); auditErr != nil {
				return "", nil, auditErr
			}
		}
		return "", nil, fmt.Errorf("Error parsing stats token. Failing auth. Error: %v", err)
	}

	if !token.Valid {
		return "", nil, fmt.Errorf("Token not valid")
	}
	grant, err := streamGrant(token)
	if err != nil {
		return "", nil, delegation.ErrDenied
	}
	if err := checkStreamRoute(token, grant, req.URL.Path, h.parsedPublicKey); err != nil {
		return "", nil, err
	}
	if grant != nil && h.delegations.Check(req.Context(), tokenString, grant) != nil {
		if auditErr := expiredDelegationAudit(tokenString, h.parsedPublicKey); auditErr != nil {
			return "", nil, auditErr
		}
		return "", nil, delegation.ErrDenied
	}

	return tokenString, token, nil
}

func (h *StatsHandler) parseStatsInfo(req *http.Request, tokenString string, multiHost bool) ([]*statsInfo, error) {
	token, err := parseRequestToken(tokenString, h.parsedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error parsing stats token. Failing auth. Error: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("Token not valid")
	}
	grant, err := streamGrant(token)
	if err != nil {
		return nil, delegation.ErrDenied
	}
	if err := checkStreamRoute(token, grant, req.URL.Path, h.parsedPublicKey); err != nil {
		return nil, err
	}
	if grant != nil && h.delegations.Check(req.Context(), tokenString, grant) != nil {
		return nil, delegation.ErrDenied
	}
	originalToken := token
	if grant != nil {
		// Only the already signature/live-verified envelope is exposed to the
		// existing statistics target parser; the wire JWT stays fail-closed.
		copyToken := *token
		claims := jwt.MapClaims{}
		for key, value := range grant.Payload {
			claims[key] = value
		}
		copyToken.Claims = claims
		token = &copyToken
	}

	var statsInfoStructs []*statsInfo

	if multiHost {
		projectsOrServices, err := getProjectOrService(token)
		if err != nil {
			return nil, fmt.Errorf("Error getting project or service info from token: %v", err)
		}
		if len(projectsOrServices) == 0 || len(projectsOrServices) > maxStatsTargets {
			return nil, fmt.Errorf("statistics target count must be between 1 and %d", maxStatsTargets)
		}
		for _, projectOrService := range projectsOrServices {
			data := projectOrService
			innerTokenString, ok := data["token"]
			if !ok {
				return nil, fmt.Errorf("Empty set of hosts or containers in project/service")
			}
			innerJwtToken, err := parseRequestToken(innerTokenString, h.parsedPublicKey)
			if err != nil {

				return nil, fmt.Errorf("Error getting inner token: %v. Inner token parameter: %v", err, redactSecretForLog(innerTokenString))
			}
			hostUUID, found := h.extractHostUUID(innerJwtToken)
			if !found {
				return nil, fmt.Errorf("Couldn't find host uuid on inner token")
			}
			if err := requireKeyBackend(h.backend, innerJwtToken, hostUUID); err != nil {
				return nil, err
			}
			if err := requireKeyBackend(h.backend, originalToken, hostUUID); err != nil {
				return nil, err
			}
			urlString, ok := data["url"]
			if !ok {
				return nil, fmt.Errorf("Could't find url field in inner token payload")
			}
			targetURL, err := statsTargetURL(urlString, innerTokenString)
			if err != nil {
				return nil, err
			}
			innerGrant, err := streamGrant(innerJwtToken)
			if err != nil {
				return nil, delegation.ErrDenied
			}
			if innerGrant != nil {
				parsedURL, _ := url.Parse(targetURL)
				if err := checkStreamRoute(innerJwtToken, innerGrant, parsedURL.Path, h.parsedPublicKey); err != nil {
					return nil, err
				}
				if h.delegations.Check(context.Background(), innerTokenString, innerGrant) != nil {
					return nil, delegation.ErrDenied
				}
			}
			statsInfoStructs = append(statsInfoStructs, &statsInfo{hostKey: hostUUID, url: targetURL})
		}
	} else {
		hostUUID, found := h.extractHostUUID(token)
		if !found {
			return nil, fmt.Errorf("could not find host uuid")
		}
		if err := requireKeyBackend(h.backend, originalToken, hostUUID); err != nil {
			return nil, err
		}
		statsInfoStructs = append(statsInfoStructs, &statsInfo{hostKey: hostUUID, url: req.URL.RequestURI()})
	}
	return statsInfoStructs, nil
}

func getProjectOrService(token *jwt.Token) ([]map[string]string, error) {
	claims, ok := mapClaims(token)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	data, ok := claims["project"]
	if !ok {
		data, ok = claims["service"]
	}
	if ok {
		if interfaceList, isList := data.([]interface{}); isList {
			projectList := []map[string]string{}
			for _, inter := range interfaceList {
				projectInterfaceMap, ok := inter.(map[string]interface{})
				if ok {
					projectMap := map[string]string{}
					for key, value := range projectInterfaceMap {
						valueString, valid := value.(string)
						if !valid {
							return nil, fmt.Errorf("invalid project/service field type")
						}
						projectMap[key] = valueString
					}
					projectList = append(projectList, projectMap)
				} else {
					return nil, fmt.Errorf("invalid project/service input data type")
				}
			}
			return projectList, nil
		}
		return nil, fmt.Errorf("invalid project/service input data type")
	}
	return nil, fmt.Errorf("empty token")
}

func (h *StatsHandler) extractHostUUID(token *jwt.Token) (string, bool) {
	hostUUID, found := stringClaim(token, "hostUuid")
	if !found {
		if grant, err := streamGrant(token); err == nil && grant != nil {
			hostUUID, found = grant.Payload["hostUuid"].(string)
		}
	}
	if !found {
		log.Info("Host identifier was not found in statistics token.")
		return "", false
	}
	if !h.backend.hasBackend(hostUUID) {
		log.Info("Statistics token referenced an unavailable host.")
		return "", false
	}
	return hostUUID, true
}

func statsTargetURL(rawURL, token string) (string, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target == nil || (target.Scheme != "ws" && target.Scheme != "wss") ||
		target.Host == "" || target.User != nil || target.Fragment != "" || target.Opaque != "" {
		return "", fmt.Errorf("invalid statistics target URL")
	}
	path := strings.ToLower(strings.TrimSuffix(target.EscapedPath(), "/"))
	validPath := false
	for _, prefix := range []string{
		"/v1/hoststats", "/v1/containerstats",
		"/v2-beta/hoststats", "/v2-beta/containerstats",
		"/v2/hoststats", "/v2/containerstats",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			validPath = true
			break
		}
	}
	if !validPath {
		return "", fmt.Errorf("statistics target path is not allowed")
	}
	query := target.Query()
	query.Set("token", token)
	internal := &url.URL{Path: target.Path, RawPath: target.RawPath, RawQuery: query.Encode()}
	return internal.RequestURI(), nil
}

func parseRequestToken(tokenString string, parsedPublicKey interface{}) (*jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("No JWT provided")
	}

	token, err := parseSignedJWT(tokenString, parsedPublicKey)
	return token, err
}
