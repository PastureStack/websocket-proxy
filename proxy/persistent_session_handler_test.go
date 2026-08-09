package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/websocket-proxy/testutils"
	"github.com/gorilla/websocket"
)

const workspaceTestBaseURL = "http://127.0.0.1:1111/v1/exec/sessions/"

func TestPersistentWorkspaceHTTPContract(t *testing.T) {
	sessionID := "psw_abcdefghijklmnopqrstuv01"
	secret := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH"
	token := testutils.CreateToken("1", privateKey)

	missingRequest, err := http.NewRequest(http.MethodGet, workspaceTestBaseURL+sessionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	missingRequest.Header.Set(workspaceSecretHeader, secret)
	missingResponse, err := http.DefaultClient.Do(missingRequest)
	if err != nil {
		t.Fatal(err)
	}
	missingPayload := decodeWorkspaceResponse(t, missingResponse)
	if missingResponse.StatusCode != http.StatusOK || missingPayload["status"] != "missing" {
		t.Fatalf("unexpected missing-session response: status=%d payload=%#v", missingResponse.StatusCode, missingPayload)
	}
	if missingResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing-session response was cacheable: %q", missingResponse.Header.Get("Cache-Control"))
	}

	createdResponse := createWorkspaceSession(t, sessionID, secret, "terminal", "ws://127.0.0.1:1111/v1/exec", token, "")
	createdPayload := decodeWorkspaceResponse(t, createdResponse)
	if createdResponse.StatusCode != http.StatusCreated || createdPayload["status"] != "connected" {
		t.Fatalf("unexpected create response: status=%d payload=%#v", createdResponse.StatusCode, createdPayload)
	}

	idempotentResponse := createWorkspaceSession(t, sessionID, secret, "terminal", "ws://127.0.0.1:1111/v1/exec", token, "")
	_ = decodeWorkspaceResponse(t, idempotentResponse)
	if idempotentResponse.StatusCode != http.StatusOK {
		t.Fatalf("idempotent create returned %d", idempotentResponse.StatusCode)
	}

	statusWithoutSecret, err := http.Get(workspaceTestBaseURL + sessionID)
	if err != nil {
		t.Fatal(err)
	}
	_ = decodeWorkspaceResponse(t, statusWithoutSecret)
	if statusWithoutSecret.StatusCode != http.StatusForbidden {
		t.Fatalf("status without a secret returned %d", statusWithoutSecret.StatusCode)
	}

	conflictResponse := createWorkspaceSession(
		t,
		sessionID,
		"1123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
		"terminal",
		"ws://127.0.0.1:1111/v1/exec",
		token,
		"",
	)
	_ = decodeWorkspaceResponse(t, conflictResponse)
	if conflictResponse.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting create returned %d", conflictResponse.StatusCode)
	}

	foreignResponse := createWorkspaceSession(
		t,
		"psw_abcdefghijklmnopqrstuv02",
		"2123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
		"terminal",
		"ws://example.invalid/v1/exec",
		token,
		"",
	)
	_ = decodeWorkspaceResponse(t, foreignResponse)
	if foreignResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign target returned %d", foreignResponse.StatusCode)
	}

	crossOriginResponse := createWorkspaceSession(
		t,
		"psw_abcdefghijklmnopqrstuv03",
		"3123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
		"terminal",
		"ws://127.0.0.1:1111/v1/exec",
		token,
		"https://example.invalid",
	)
	_ = decodeWorkspaceResponse(t, crossOriginResponse)
	if crossOriginResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin create returned %d", crossOriginResponse.StatusCode)
	}

	deleteRequest, err := http.NewRequest(http.MethodDelete, workspaceTestBaseURL+sessionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest.Header.Set(workspaceSecretHeader, secret)
	deleteResponse, err := http.DefaultClient.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	deleteResponse.Body.Close()
	if deleteResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("delete returned %d", deleteResponse.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		statusRequest, requestErr := http.NewRequest(http.MethodGet, workspaceTestBaseURL+sessionID, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		statusRequest.Header.Set(workspaceSecretHeader, secret)
		statusResponse, requestErr := http.DefaultClient.Do(statusRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		statusPayload := decodeWorkspaceResponse(t, statusResponse)
		if statusPayload["status"] == "ended" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session did not end: %#v", statusPayload)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPersistentWorkspaceWebSocketReconnectAndReplay(t *testing.T) {
	sessionID := "psw_abcdefghijklmnopqrstuv04"
	secret := "4123456789abcdefghijklmnopqrstuvwxyzABCDEFGH"
	clientID := "tab_abcdefghijklmnopqrstuv01"
	token := testutils.CreateToken("1", privateKey)
	createdResponse := createWorkspaceSession(t, sessionID, secret, "terminal", "ws://127.0.0.1:1111/v1/exec", token, "")
	_ = decodeWorkspaceResponse(t, createdResponse)
	if createdResponse.StatusCode != http.StatusCreated {
		t.Fatalf("create returned %d", createdResponse.StatusCode)
	}

	websocketURL := "ws://127.0.0.1:1111/v1/exec/sessions/" + sessionID
	if strings.Contains(websocketURL, secret) || strings.Contains(websocketURL, token) {
		t.Fatal("workspace credentials leaked into the WebSocket URL")
	}

	wrongDialer := &websocket.Dialer{Subprotocols: []string{
		workspaceSubprotocol,
		workspaceSecretProtocolPrefix + "wrong-secret",
		workspaceClientProtocolPrefix + clientID,
	}}
	wrongConnection, wrongResponse, err := wrongDialer.Dial(websocketURL, nil)
	if wrongConnection != nil {
		wrongConnection.Close()
	}
	if err == nil || wrongResponse == nil || wrongResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong secret was not rejected: response=%#v error=%v", wrongResponse, err)
	}
	wrongResponse.Body.Close()

	first := attachWorkspaceClient(t, websocketURL, secret, clientID)
	hello := readWorkspaceFrame(t, first, "hello")
	if hello["status"] != "connected" || hello["controllerId"] != clientID {
		t.Fatalf("unexpected hello frame: %#v", hello)
	}
	_ = readWorkspaceFrame(t, first, "replay")

	invalidInput, _ := json.Marshal(workspaceClientFrame{Type: "input", Data: "not-base64"})
	if err := first.WriteMessage(websocket.TextMessage, invalidInput); err != nil {
		t.Fatal(err)
	}
	invalidFrame := readWorkspaceFrame(t, first, "error")
	if invalidFrame["code"] != "invalid_input" {
		t.Fatalf("unexpected invalid-input response: %#v", invalidFrame)
	}

	input := base64.StdEncoding.EncodeToString([]byte("echo-test"))
	inputFrame, _ := json.Marshal(workspaceClientFrame{Type: "input", Data: input})
	if err := first.WriteMessage(websocket.TextMessage, inputFrame); err != nil {
		t.Fatal(err)
	}
	output := readWorkspaceFrame(t, first, "output")
	if output["data"] != input+"-response" {
		t.Fatalf("unexpected terminal output: %#v", output)
	}
	first.Close()

	second := attachWorkspaceClient(t, websocketURL, secret, clientID)
	defer second.Close()
	_ = readWorkspaceFrame(t, second, "hello")
	replay := readWorkspaceFrame(t, second, "replay")
	entries, ok := replay["replay"].([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("unexpected replay frame: %#v", replay)
	}
	entry, ok := entries[0].(map[string]interface{})
	if !ok || entry["data"] != input+"-response" {
		t.Fatalf("unexpected replay entry: %#v", replay)
	}

	deleteRequest, err := http.NewRequest(http.MethodDelete, workspaceTestBaseURL+sessionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest.Header.Set(workspaceSecretHeader, secret)
	deleteResponse, err := http.DefaultClient.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	deleteResponse.Body.Close()
	if deleteResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("delete returned %d", deleteResponse.StatusCode)
	}
	ended := readWorkspaceFrame(t, second, "status")
	if ended["status"] == "closing" {
		ended = readWorkspaceFrame(t, second, "status")
	}
	if ended["status"] != "ended" {
		t.Fatalf("unexpected final status: %#v", ended)
	}
}

func createWorkspaceSession(t *testing.T, sessionID, secret, kind, target, token, origin string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(workspaceCreateRequest{
		Secret: secret,
		Kind:   kind,
		Target: target,
		Token:  token,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, workspaceTestBaseURL+sessionID, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func attachWorkspaceClient(t *testing.T, target, secret, clientID string) *websocket.Conn {
	t.Helper()
	dialer := &websocket.Dialer{Subprotocols: []string{
		workspaceSubprotocol,
		workspaceSecretProtocolPrefix + secret,
		workspaceClientProtocolPrefix + clientID,
	}}
	connection, response, err := dialer.Dial(target, nil)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	if connection.Subprotocol() != workspaceSubprotocol {
		connection.Close()
		t.Fatalf("unexpected negotiated subprotocol %q", connection.Subprotocol())
	}
	return connection
}

func readWorkspaceFrame(t *testing.T, connection *websocket.Conn, expectedType string) map[string]interface{} {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		_, payload, err := connection.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		var frame map[string]interface{}
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		if frame["type"] == expectedType {
			return frame
		}
	}
	t.Fatalf("did not receive workspace frame type %q", expectedType)
	return nil
}

func decodeWorkspaceResponse(t *testing.T, response *http.Response) map[string]interface{} {
	t.Helper()
	defer response.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}
