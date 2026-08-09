package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/common"
)

const wsProto string = "Sec-Websocket-Protocol"
const wsProtoBinary string = "binary"

type FrontendHandler struct {
	backend         backendProxy
	parsedPublicKey interface{}
}

func (h *FrontendHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	_, hostKey, authErr := h.auth(req)
	if authErr != nil {
		log.Infof("Frontend auth failed: %v", authErr)
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
		log.Errorf("Error during upgrade: [%v]", err)
		http.Error(rw, "Failed to upgrade connection.", 500)
		return
	}
	defer closeConnection(ws)
	ws.SetReadLimit(common.MaxWireMessageBytes)

	msgKey, respChannel, err := h.backend.initializeClient(hostKey)
	if err != nil {
		log.Errorf("Error during initialization: [%v]", err)
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
						log.Errorf("Error decoding message: %v", e)
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
				closeConnection(ws)
			}
		}
	}()

	requestURL := req.URL.String()
	if err = h.backend.connect(hostKey, msgKey, requestURL); err != nil {
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

	hostUUID, found := stringClaim(token, "hostUuid")
	if found && h.backend.hasBackend(hostUUID) {
		return token, hostUUID, nil
	}

	return nil, "", fmt.Errorf("invalid or unavailable backend host")
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
