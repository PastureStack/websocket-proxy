package proxy

import (
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditUnavailableIsSafeRetryableWebsocket503Semantic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		closeForBackendOutcome(ws, "AuditUnavailable:503")
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_, _, err = ws.ReadMessage()
	closed, ok := err.(*websocket.CloseError)
	if !ok || closed.Code != websocket.CloseTryAgainLater || closed.Text != "AuditUnavailable (503)" {
		t.Fatalf("wrong safe close status: %v", err)
	}
}
