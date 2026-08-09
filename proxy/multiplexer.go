package proxy

import (
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/common"
)

type multiplexer struct {
	backendSessionID  string
	backendKey        string
	messagesToBackend chan string
	frontendChans     map[string]chan<- common.Message
	proxyManager      proxyManager
	frontendMu        *sync.RWMutex
	connection        *websocket.Conn
	done              chan struct{}
	shutdownOnce      sync.Once
}

func (m *multiplexer) initializeClient() (string, <-chan common.Message, error) {
	msgKey := common.NewRandomUUID()
	frontendChan := make(chan common.Message)
	m.frontendMu.Lock()
	defer m.frontendMu.Unlock()
	select {
	case <-m.done:
		return "", nil, fmt.Errorf("backend connection is closed")
	default:
	}
	m.frontendChans[msgKey] = frontendChan
	return msgKey, frontendChan, nil
}

func (m *multiplexer) connect(msgKey, url string) error {
	return m.enqueue(common.FormatMessage(msgKey, common.Connect, url))
}

func (m *multiplexer) send(msgKey, msg string) error {
	return m.enqueue(common.FormatMessage(msgKey, common.Body, msg))
}

func (m *multiplexer) sendClose(msgKey string) error {
	return m.enqueue(common.FormatMessage(msgKey, common.Close, ""))
}

func (m *multiplexer) enqueue(message string) error {
	if len(message) > common.MaxWireMessageBytes {
		return fmt.Errorf("backend message exceeds %d bytes", common.MaxWireMessageBytes)
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-m.done:
		return fmt.Errorf("backend connection is closed")
	case m.messagesToBackend <- message:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out queueing backend message")
	}
}

func (m *multiplexer) closeConnection(msgKey string, notifyBackend bool) error {
	var sendErr error
	if notifyBackend {
		sendErr = m.sendClose(msgKey)
	}

	m.frontendMu.Lock()
	defer m.frontendMu.Unlock()
	if frontendChan, ok := m.frontendChans[msgKey]; ok {
		close(frontendChan)
		delete(m.frontendChans, msgKey)
	}
	return sendErr
}

func (m *multiplexer) routeMessages(ws *websocket.Conn) {
	ws.SetReadLimit(common.MaxWireMessageBytes)
	// Read messages from backend
	go func() {
		for {
			msgType, msg, err := ws.ReadMessage()
			if err != nil {
				log.Infof("Shutting down backend %v. Connection closed because: %v.", m.backendKey, err)
				m.shutdown()
				return
			}

			if msgType != websocket.TextMessage {
				continue
			}
			message, parseErr := common.ParseMessageSafe(string(msg))
			if parseErr != nil {
				log.WithField("error", parseErr).Warn("Received malformed backend message; closing connection.")
				m.shutdown()
				_ = ws.Close()
				return
			}

			m.frontendMu.RLock()
			frontendChan, ok := m.frontendChans[message.Key]
			timedOut := false
			if ok {
				select {
				case frontendChan <- message:
				case <-time.After(time.Second * 10):
					timedOut = true
				}
			}
			m.frontendMu.RUnlock()

			if timedOut {
				log.Warnf("Timed out sending message with key %v to frontend channel.", message.Key)
				m.proxyManager.closeConnection(m.backendKey, message.Key)
			}

			if !ok && message.Type != common.Close {
				log.Infof("Couldn't find frontend channel for key %v. Closing frontend connection.", m.backendKey)
				m.proxyManager.closeConnection(m.backendKey, message.Key)
			}
		}
	}()

	// Write messages to backend
	go func() {
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for {
			select {
			case message, ok := <-m.messagesToBackend:
				if !ok {
					return
				}
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				err := ws.WriteMessage(websocket.TextMessage, []byte(message))
				if err != nil {
					log.Errorf("Error writing message to backend %v - %v. Error: %v", m.backendKey, m.backendSessionID, err)
					m.shutdown()
					return
				}
			case <-ticker.C:
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
					m.shutdown()
					return
				}

			case <-m.done:
				return
			}
		}
	}()
}

func (m *multiplexer) shutdown() {
	m.shutdownOnce.Do(func() {
		close(m.done)
		_ = m.connection.Close()
		m.proxyManager.removeBackend(m.backendKey, m.backendSessionID)

		m.frontendMu.Lock()
		defer m.frontendMu.Unlock()
		for key, frontendChan := range m.frontendChans {
			close(frontendChan)
			delete(m.frontendChans, key)
		}
	})
}
