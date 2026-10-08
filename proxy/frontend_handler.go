package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/delegation"
	"github.com/PastureStack/websocket-proxy/internal/logsafe"
)

const wsProto string = "Sec-Websocket-Protocol"
const wsProtoBinary string = "binary"

type FrontendHandler struct {
	backend         backendProxy
	parsedPublicKey interface{}
	delegations     *delegation.Verifier
	failures        *delegation.FailureReporter
}

func (h *FrontendHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token, hostKey, authErr := h.auth(req)
	if authErr != nil {
		if errors.Is(authErr, errBackendAuditCapability) {
			writeBackendAuditUnavailable(rw, reportCapabilityError(h.failures, h.backend, authErr))
			return
		}
		log.Infof("Frontend auth failed: %s", logsafe.Value(authErr))
		http.Error(rw, "Failed authentication", 401)
		return
	}

	binary := strings.EqualFold(req.Header.Get(wsProto), wsProtoBinary)
	respHeaders := make(http.Header)
	if binary {
		respHeaders.Add(wsProto, wsProtoBinary)
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: workspaceSameOrigin,
	}
	ws, err := upgrader.Upgrade(rw, req, respHeaders)
	if err != nil {
		log.Errorf("Error during upgrade: [%s]", logsafe.Value(err))
		http.Error(rw, "Failed to upgrade connection.", 500)
		return
	}
	defer closeConnection(ws)
	grant, _ := streamGrant(token)
	if grant != nil {
		cancel := h.delegations.Watch(req.Context(), token.Raw, grant, func() { closeConnection(ws) })
		defer cancel()
	}
	ws.SetReadLimit(common.MaxWireMessageBytes)

	requestURL := keyRequestURL(req, token)
	msgKey, respChannel, err := initializeForURL(h.backend, hostKey, requestURL)
	if err != nil {
		if errors.Is(err, errBackendAuditCapability) {
			closeForBackendOutcome(ws, reportBackendFailure(h.failures, h.backend, token.Raw, hostKey)+":503")
		}
		log.Errorf("Error during initialization: [%s]", logsafe.Value(err))
		closeConnection(ws)
		return
	}
	defer h.backend.closeConnection(hostKey, msgKey)

	// Send response messages to client
	go func() {
		defer closeConnection(ws)
		for {
			message, ok := <-respChannel
			if !ok {
				return
			}
			switch message.Type {
			case common.Body:
				var data []byte
				var e error
				msgType := 1
				if binary {
					msgType = 2
					data, e = base64.StdEncoding.DecodeString(message.Body)
					if e != nil {
						log.Errorf("Error decoding message: %s", logsafe.Value(e))
						closeConnection(ws)
						continue
					}
				} else {
					data = []byte(message.Body)
				}

				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if e := ws.WriteMessage(msgType, data); e != nil {
					closeConnection(ws)
				}
			case common.Close:
				closeForBackendOutcome(ws, message.Body)
				closeConnection(ws)
			}
		}
	}()

	if err = h.backend.connect(hostKey, msgKey, requestURL); err != nil {
		if errors.Is(err, errBackendAuditCapability) {
			closeForBackendOutcome(ws, reportBackendFailure(h.failures, h.backend, token.Raw, hostKey)+":503")
		}
		return
	}

	// Send request messages to backend
	for {
		msgType, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var data string
		if binary {
			data = base64.StdEncoding.EncodeToString(msg)
		} else {
			data = string(msg)
		}
		if msgType == websocket.BinaryMessage || msgType == websocket.TextMessage {
			if err = h.backend.send(hostKey, msgKey, data); err != nil {
				return
			}
		}
	}
}

func (h *FrontendHandler) auth(req *http.Request) (*jwt.Token, string, error) {
	token, tokenParam, err := parseToken(req, h.parsedPublicKey)
	if err != nil {
		if tokenParam == "" {
			return nil, "", noAuthError{err: err.Error()}
		}
		return nil, "", fmt.Errorf("Error parsing token: %v. Token parameter: %v", err, redactSecretForLog(tokenParam))
	}

	if !token.Valid {
		return nil, "", fmt.Errorf("Token not valid. Token parameter: %v", redactSecretForLog(tokenParam))
	}
	grant, err := streamGrant(token)
	if err != nil {
		return nil, "", delegation.ErrDenied
	}
	if grant != nil {
		if !grant.AllowsPath(req.URL.Path) || h.delegations.Check(context.Background(), token.Raw, grant) != nil {
			return nil, "", delegation.ErrDenied
		}
		hostUUID, ok := grant.Payload["hostUuid"].(string)
		if ok && h.backend.hasBackend(hostUUID) {
			if err := requireKeyBackend(h.backend, token, hostUUID); err != nil {
				return token, hostUUID, err
			}
			return token, hostUUID, nil
		}
		return nil, "", delegation.ErrDenied
	}

	hostUUID, found := stringClaim(token, "hostUuid")
	if found && h.backend.hasBackend(hostUUID) {
		if err := requireKeyBackend(h.backend, token, hostUUID); err != nil {
			return token, hostUUID, err
		}
		return token, hostUUID, nil
	}

	return nil, "", fmt.Errorf("invalid or unavailable backend host")
}

func streamGrant(token *jwt.Token) (*delegation.Grant, error) {
	claims, ok := mapClaims(token)
	if !ok {
		return nil, delegation.ErrDenied
	}
	return delegation.Parse(map[string]interface{}(claims))
}

func closeConnection(ws *websocket.Conn) {
	ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	ws.Close()
}

func parseToken(req *http.Request, parsedPublicKey interface{}) (*jwt.Token, string, error) {
	tokenString := ""
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		parts := strings.Fields(authHeader)
		if len(parts) == 2 && strings.EqualFold("bearer", parts[0]) {
			tokenString = parts[1]
		}
	}

	if tokenString == "" {
		tokenString = req.URL.Query().Get("token")
	}

	if tokenString == "" {
		return nil, "", fmt.Errorf("No JWT provided")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("No JWT provided")
	}

	token, err := parseSignedJWT(tokenString, parsedPublicKey)
	return token, tokenString, err
}

type noAuthError struct {
	err string
}

func (e noAuthError) Error() string {
	return e.err
}

func IsNoAuthError(err error) bool {
	_, ok := err.(noAuthError)
	return ok
}
