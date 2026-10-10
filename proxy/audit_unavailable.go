package proxy

import (
	"github.com/gorilla/websocket"
	"time"
)

func closeForBackendOutcome(ws *websocket.Conn, body string) {
	if body == "AuditUnavailable:503" {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "AuditUnavailable (503)"), time.Now().Add(time.Second))
	}
	if body == backendAuditCapabilityCode+":503" {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, backendAuditCapabilityCode+" (503)"), time.Now().Add(time.Second))
	}
}
