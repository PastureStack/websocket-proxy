package common

import (
	"errors"
	"fmt"
	"strings"
)

const (
	MessageFormat       = "%s||%s||%s" // message key || message type || message body
	MessageSeparator    = "||"
	MaxWireMessageBytes = 16 << 20
	maxMessageKeyBytes  = 256
)

type MessageType string

const (
	Connect MessageType = "0"
	Body    MessageType = "1"
	Close   MessageType = "2"
)

func FormatMessage(msgKey string, messageType MessageType, body string) string {
	return fmt.Sprintf(MessageFormat, msgKey, messageType, body)
}

// ParseMessage preserves the historical one-result API. Malformed input now
// returns a zero value instead of panicking; security-sensitive callers should
// use ParseMessageSafe to inspect the validation error.
func ParseMessage(rawMessage string) Message {
	message, _ := ParseMessageSafe(rawMessage)
	return message
}

func ParseMessageSafe(rawMessage string) (Message, error) {
	if len(rawMessage) > MaxWireMessageBytes {
		return Message{}, fmt.Errorf("proxy message exceeds %d bytes", MaxWireMessageBytes)
	}
	parts := strings.SplitN(rawMessage, MessageSeparator, 3)
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[0]) > maxMessageKeyBytes {
		return Message{}, errors.New("invalid proxy message envelope")
	}
	message := Message{
		Key:  parts[0],
		Type: MessageType(parts[1]),
		Body: parts[2],
	}
	if message.Type != Connect && message.Type != Body && message.Type != Close {
		return Message{}, errors.New("invalid proxy message type")
	}
	return message, nil
}

type Message struct {
	Key  string
	Type MessageType
	Body string
}

type HTTPMessage struct {
	Hijack  bool                `json:"hijack,omitempty"`
	Host    string              `json:"host,omitempty"`
	Method  string              `json:"method,omitempty"`
	URL     string              `json:"url,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Code    int                 `json:"code,omitempty"`
	Body    []byte              `json:"body,omitempty"`
	EOF     bool                `json:"eof,omitempty"`
}
