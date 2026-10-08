package proxy

import (
	"net/http"

	"github.com/PastureStack/websocket-proxy/internal/logsafe"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type BackendHandler struct {
	proxyManager    proxyManager
	parsedPublicKey interface{}
}

func (h *BackendHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Infof("Handling backend connection request.")
	hostKey, backendToken, authed := h.authTicket(req)
	if !authed {
		http.Error(rw, "Failed authentication", 401)
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: workspaceSameOrigin,
	}

	ws, err := upgrader.Upgrade(rw, req, nil)
	if err != nil {
		log.Errorf("Error during upgrade for host [%s]: [%s]", logsafe.Value(hostKey), logsafe.Value(err))
		http.Error(rw, "Failed to upgrade connection.", 500)
		return
	}

	// Capability metadata belongs only to this signature-verified agent/host
	// connection. Public clients cannot register it with a stream ticket.
	if capable, ok := h.proxyManager.(interface {
		addBackendWithKeyCapabilities(string, *websocket.Conn, bool, string)
	}); ok {
		capable.addBackendWithKeyCapabilities(hostKey, ws, declaredKeyCapabilities(req), backendToken)
	} else {
		h.proxyManager.addBackend(hostKey, ws)
	}
}

func (h *BackendHandler) auth(req *http.Request) (string, bool) {
	host, _, valid := h.authTicket(req)
	return host, valid
}

func (h *BackendHandler) authTicket(req *http.Request) (string, string, bool) {
	token, tokenParam, err := parseToken(req, h.parsedPublicKey)
	if err != nil {
		log.Warnf("Error parsing backend token: %s. Failing auth. Token parameter: %s", logsafe.Value(err), logsafe.Value(redactSecretForLog(tokenParam)))
		return "", "", false
	}
	if token == nil || !token.Valid {
		log.Warn("Backend token was invalid.")
		return "", "", false
	}

	reportedUUID, found := claimValue(token, "reportedUuid")
	if !found {
		log.Warnf("Token did not have a reportedUuid. Failing auth. Token parameter: %s", logsafe.Value(redactSecretForLog(tokenParam)))
		return "", "", false
	}

	hostKey, ok := reportedUUID.(string)
	if !ok || hostKey == "" {
		log.Warnf("Backend token host identifier was invalid. Token parameter: %s", logsafe.Value(redactSecretForLog(tokenParam)))
		return "", "", false
	}

	return hostKey, tokenParam, true
}
