package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/websocket-proxy/common"
)

type securityTestBackend struct {
	sends atomic.Int32
}

func (*securityTestBackend) initializeClient(string) (string, <-chan common.Message, error) {
	channel := make(chan common.Message)
	return "message", channel, nil
}
func (*securityTestBackend) connect(string, string, string) error   { return nil }
func (b *securityTestBackend) send(string, string, string) error    { b.sends.Add(1); return nil }
func (*securityTestBackend) closeConnection(string, string) error   { return nil }
func (*securityTestBackend) releaseConnection(string, string) error { return nil }
func (*securityTestBackend) hasBackend(string) bool                 { return true }

func TestBackendHTTPWriterCloseIsIdempotentWithoutDeadlock(t *testing.T) {
	backend := &securityTestBackend{}
	writer := &BackendHTTPWriter{hostKey: "host", msgKey: "message", backend: backend}
	for attempt := 0; attempt < 3; attempt++ {
		done := make(chan struct{})
		go func() {
			_ = writer.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("repeated backend HTTP writer close deadlocked")
		}
	}
	if got := backend.sends.Load(); got != 1 {
		t.Fatalf("EOF was sent %d times, want 1", got)
	}
}

func TestBackendHTTPReaderRejectsInvalidStatusCode(t *testing.T) {
	backend := &securityTestBackend{}
	messages := make(chan common.Message, 1)
	payload, err := json.Marshal(common.HTTPMessage{Code: 42, Body: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	messages <- common.Message{Type: common.Body, Body: string(payload)}
	close(messages)
	reader := NewBackendHTTPReader(httptest.NewRecorder(), "host", "message", backend, messages)
	if _, err := reader.Read(make([]byte, 16)); err == nil {
		t.Fatal("invalid backend HTTP status code was accepted")
	}
}
