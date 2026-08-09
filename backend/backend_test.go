package backend

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/PastureStack/websocket-proxy/proxy"
	"github.com/PastureStack/websocket-proxy/testutils"
)

var privateKey interface{}

func TestProxyLogEndpointRedactsCredentials(t *testing.T) {
	const secret = "signed-token-value"
	endpoint := proxyLogEndpoint("wss://user:password@example.test/v1/connectbackend?token=" + secret + "#fragment")
	if strings.Contains(endpoint, secret) || strings.Contains(endpoint, "password") || strings.Contains(endpoint, "token=") {
		t.Fatalf("proxy log endpoint leaked credentials: %q", endpoint)
	}
	if endpoint != "wss://example.test/v1/connectbackend" {
		t.Fatalf("unexpected redacted endpoint: %q", endpoint)
	}
	if endpoint := proxyLogEndpoint("%zz"); endpoint != "<invalid>" {
		t.Fatalf("invalid URL was not redacted: %q", endpoint)
	}
	connectionError := proxyDialError("wss://example.test/v1/connectbackend?token=" + secret)
	if strings.Contains(connectionError.Error(), secret) || strings.Contains(connectionError.Error(), "token=") {
		t.Fatalf("proxy dial error leaked credentials: %q", connectionError)
	}
}

func TestMain(m *testing.M) {
	c := getTestConfig()
	privateKey = testutils.ParseTestPrivateKey()

	ps := &proxy.Starter{
		BackendPaths:  []string{"/v1/connectbackend"},
		FrontendPaths: []string{"/v1/echo"},
		Config:        c,
	}
	go ps.StartProxy()
	if err := waitForProxy("127.0.0.1:2223"); err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func waitForProxy(addr string) error {
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("proxy did not listen on %s: %v", addr, lastErr)
}

func TestBackendGoesAway(t *testing.T) {
	dialer := &websocket.Dialer{}
	headers := http.Header{}
	signedToken := testutils.CreateBackendToken("1", privateKey)
	url := "ws://127.0.0.1:2223/v1/connectbackend?token=" + signedToken
	backendWs, _, err := dialer.Dial(url, headers)
	if err != nil {
		t.Fatal("Failed to connect to proxy.", err)
	}

	handlers := make(map[string]Handler)
	handlers["/v1/echo"] = &echoHandler{}
	go connectToProxyWS(backendWs, handlers)

	signedToken = testutils.CreateToken("1", privateKey)
	url = "ws://127.0.0.1:2223/v1/echo?token=" + signedToken
	ws := getClientConnection(url, t)

	if err := ws.WriteMessage(1, []byte("a message")); err != nil {
		t.Fatal(err)
	}

	ws.ReadMessage() // Read initial echo message
	backendWs.Close()

	if _, msg, err := ws.ReadMessage(); err == nil {
		t.Fatalf("expected closed websocket, received message %q", msg)
	}

	dialer = &websocket.Dialer{}
	ws, _, err = dialer.Dial(url, http.Header{})
	if ws != nil || err != websocket.ErrBadHandshake {
		t.Fatal("Should not have been able to connect.")
	}
}

func TestBackendReplaced(t *testing.T) {
	// This tests that if a backend connection A is replaced by backend connection B and then A is closed, the
	// multiplexer for B is not lost or removed.
	dialer := &websocket.Dialer{}
	url := "ws://127.0.0.1:2223/v1/connectbackend?token=" + testutils.CreateBackendToken("1", privateKey)
	backendWs, _, err := dialer.Dial(url, http.Header{})
	if err != nil {
		t.Fatal("Failed to connect to proxy.", err)
	}

	backendWs2, _, err := dialer.Dial(url, http.Header{})
	if err != nil {
		t.Fatal("Failed to connect to proxy second time.", err)
	}
	defer backendWs2.Close()

	go connectToProxyWS(backendWs2, map[string]Handler{"/v1/echo": &echoHandler{}})

	backendWs.Close()

	ws := getClientConnection("ws://127.0.0.1:2223/v1/echo?token="+testutils.CreateToken("1", privateKey), t)
	if err := ws.WriteMessage(1, []byte("a message")); err != nil {
		t.Fatal(err)
	}

	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Unexpected error: %s", msg)
	}

	if string(msg) != "a message-response" {
		t.Fatalf("Unexpected message: %s", msg)
	}
}

// Simple unit test for asserting the GetHandler algorithm
func TestGetHandler(t *testing.T) {
	handlers := map[string]Handler{}
	logKey := "/v1/logs/"
	statKey := "/v1/stats/"
	handlers[logKey] = &mockHandler{hType: logKey}
	handlers[statKey] = &mockHandler{hType: statKey}

	if !assertHandler("/v1/logs", logKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if !assertHandler("/v1/logs/", logKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if !assertHandler("/v1/stats/", statKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if !assertHandler("/v1/stats", statKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if !assertHandler("/v1/stats/1234", statKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if !assertHandler("/v1/stats/1234/", statKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if assertHandler("/v1/foo", statKey, handlers, t) {
		t.Fatal("Bad handler")
	}
	if assertHandler("/v1/stats-impersonator", statKey, handlers, t) {
		t.Fatal("handler prefix crossed a path-segment boundary")
	}
}

func assertHandler(path string, expectedType string, handlers map[string]Handler, t *testing.T) bool {
	if h, ok := getHandler(path, handlers); ok {
		if mh, yes := h.(*mockHandler); yes && mh.hType == expectedType {
			return true
		}
	}
	return false
}

type mockHandler struct {
	hType string
}

func (h *mockHandler) Handle(messageKey string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {

}

func getClientConnection(url string, t *testing.T) *websocket.Conn {
	dialer := &websocket.Dialer{}
	ws, _, err := dialer.Dial(url, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

type echoHandler struct {
}

func (e *echoHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer SignalHandlerClosed(key, response)
	for {
		m, ok := <-incomingMessages
		if !ok {
			return
		}
		if m != "" {
			data := fmt.Sprintf("%s-response", m)
			wrap := common.Message{
				Key:  key,
				Type: common.Body,
				Body: data,
			}
			response <- wrap
		}
	}
}

func getTestConfig() *proxy.Config {
	config := &proxy.Config{
		ListenAddr:   "127.0.0.1:2223",
		PlatformAddr: "127.0.0.1:8081",
	}

	pubKey, err := proxy.ParsePublicKey("../testutils/public.pem")
	if err != nil {
		log.Fatal("Failed to parse key. ", err)
	}
	config.PublicKey = pubKey
	return config
}
