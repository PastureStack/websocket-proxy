package backend

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/common"
)

// Handler is the iterface passed into ConnectToProxy() to have messages routed to and from the handler.
type Handler interface {
	Handle(messageKey string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message)
}

func ConnectToProxy(proxyURL string, handlers map[string]Handler) error {
	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil || parsedProxyURL == nil || (parsedProxyURL.Scheme != "ws" && parsedProxyURL.Scheme != "wss") ||
		parsedProxyURL.Host == "" || parsedProxyURL.User != nil || parsedProxyURL.Fragment != "" || parsedProxyURL.Opaque != "" {
		return fmt.Errorf("invalid proxy WebSocket endpoint")
	}
	endpoint := proxyLogEndpoint(proxyURL)
	log.WithField("endpoint", endpoint).Info("Connecting to proxy.")

	dialer := &websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	headers := http.Header{}
	ws, _, err := dialer.Dial(proxyURL, headers)
	if err != nil {
		log.WithField("endpoint", endpoint).Error("Failed to connect to proxy.")
		return proxyDialError(proxyURL)
	}

	return connectToProxyWS(ws, handlers)
}

func proxyDialError(rawURL string) error {
	return fmt.Errorf("proxy WebSocket connection to %s failed", proxyLogEndpoint(rawURL))
}

func proxyLogEndpoint(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func connectToProxyWS(ws *websocket.Conn, handlers map[string]Handler) error {
	ws.SetReadLimit(common.MaxWireMessageBytes)
	responders := make(map[string]chan string)
	responseChannel := make(chan common.Message, 10)

	// Write messages to proxy
	go func() {
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for {
			select {
			case message, ok := <-responseChannel:
				if !ok {
					return
				}
				data := common.FormatMessage(message.Key, message.Type, message.Body)
				if len(data) > common.MaxWireMessageBytes {
					_ = ws.Close()
					return
				}
				if err := ws.WriteMessage(websocket.TextMessage, []byte(data)); err != nil {
					_ = ws.Close()
					return
				}
			case <-ticker.C:
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
					_ = ws.Close()
					return
				}
			}
		}
	}()

	ph := newPongHandler(ws)
	ws.SetPongHandler(ph.handle)

	// Read and route messages from proxy
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Received error reading from socket. Exiting.")
			for _, msgChan := range responders {
				close(msgChan)
			}
			return err
		}

		message, err := common.ParseMessageSafe(string(msg))
		if err != nil {
			log.WithField("error", err).Warn("Received malformed proxy message; closing connection.")
			_ = ws.Close()
			return err
		}
		switch message.Type {
		case common.Connect:
			requestURL, err := url.Parse(message.Body)
			if err != nil {
				continue
			}

			handler, ok := getHandler(requestURL.Path, handlers)
			if ok {
				msgChan := make(chan string, 10)
				responders[message.Key] = msgChan
				go handler.Handle(message.Key, message.Body, msgChan, responseChannel)
			} else {
				log.WithFields(log.Fields{"path": requestURL.Path}).Warn("Could not find appropriate message handler for supplied path.")
				responseChannel <- common.Message{
					Key:  message.Key,
					Type: common.Close,
					Body: ""}
			}
		case common.Body:
			if msgChan, ok := responders[message.Key]; ok {
				msgChan <- message.Body
			} else {
				log.WithFields(log.Fields{"key": message.Key}).Warn("Could not find responder for specified key.")
				responseChannel <- common.Message{
					Key:  message.Key,
					Type: common.Close,
				}
			}
		case common.Close:
			closeHandler(responders, message.Key)
		default:
			log.WithFields(log.Fields{"messageType": message.Type}).Warn("Unrecognized message type. Closing connection.")
			closeHandler(responders, message.Key)
			SignalHandlerClosed(message.Key, responseChannel)
			continue
		}
	}
}

// Returns the handler that best matches the provided path and true if one is found,
// otherwise returns nil and false. This function is not robust enough to handle
// pattern matching. If it can't find an exact match, it will look for a handler that
// is a prefix for path. So, '/v1/stats/' will be a match for '/v1/stats/id-123'
func getHandler(path string, handlers map[string]Handler) (Handler, bool) {
	if handler, ok := handlers[path]; ok {
		return handler, true
	}

	path = strings.TrimSuffix(path, "/")
	for key, handler := range handlers {
		key = strings.TrimSuffix(key, "/")
		if path == key || strings.HasPrefix(path, key+"/") {
			return handler, true
		}
	}
	return nil, false
}

func closeHandler(responders map[string]chan string, msgKey string) {
	if msgChan, ok := responders[msgKey]; ok {
		close(msgChan)
		delete(responders, msgKey)
	}
}

func SignalHandlerClosed(msgKey string, response chan<- common.Message) {
	wrap := common.Message{
		Key:  msgKey,
		Type: common.Close,
	}
	response <- wrap

}
