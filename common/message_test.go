package common

import (
	"strings"
	"testing"
)

func TestParseMessageRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{
		"",
		"missing-separators",
		"key||9||body",
		"||1||body",
		strings.Repeat("k", maxMessageKeyBytes+1) + "||1||body",
		strings.Repeat("x", MaxWireMessageBytes+1),
	} {
		if _, err := ParseMessageSafe(input); err == nil {
			t.Fatalf("malformed proxy message was accepted: length=%d", len(input))
		}
	}
}

func TestParseMessageRoundTripPreservesSeparatorInBody(t *testing.T) {
	raw := FormatMessage("message-key", Body, "left||right")
	message, err := ParseMessageSafe(raw)
	if err != nil {
		t.Fatal(err)
	}
	if message.Key != "message-key" || message.Type != Body || message.Body != "left||right" {
		t.Fatalf("unexpected parsed message: %#v", message)
	}
}

func TestParseMessageCompatibilityAPIIsPanicFree(t *testing.T) {
	if message := ParseMessage("malformed"); message != (Message{}) {
		t.Fatalf("malformed compatibility parse returned data: %#v", message)
	}
}
