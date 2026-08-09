package proxy

import (
	"fmt"
	"sync"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type backendProxy interface {
	initializeClient(backendKey string) (string, <-chan common.Message, error)
	connect(backendKey, msgKey, url string) error
	send(backendKey, msgKey, msg string) error
	closeConnection(backendKey, msgKey string) error
	releaseConnection(backendKey, msgKey string) error
	hasBackend(backendKey string) bool
}

type proxyManager interface {
	addBackend(backendKey string, ws *websocket.Conn)
	removeBackend(backendKey, sessionID string)
	closeConnection(backendKey, msgKey string) error
}

type backendProxyManager struct {
	multiplexers map[string]*multiplexer
	mu           *sync.RWMutex
}

func (b *backendProxyManager) initializeClient(backendKey string) (string, <-chan common.Message, error) {
	b.mu.RLock()
	multiplexer, ok := b.multiplexers[backendKey]
	b.mu.RUnlock()
	if !ok {
		return "", nil, fmt.Errorf("No backend for key [%v]", backendKey)
	}
	return multiplexer.initializeClient()
}

func (b *backendProxyManager) connect(backendKey, msgKey, url string) error {
	b.mu.RLock()
	multiplexer, ok := b.multiplexers[backendKey]
	b.mu.RUnlock()
	if !ok {
		return fmt.Errorf("No backend for key [%v]", backendKey)
	}
	return multiplexer.connect(msgKey, url)
}

func (b *backendProxyManager) send(backendKey, msgKey, msg string) error {
	b.mu.RLock()
	multiplexer, ok := b.multiplexers[backendKey]
	b.mu.RUnlock()
	if !ok {
		return fmt.Errorf("No backend for key [%v]", backendKey)
	}
	return multiplexer.send(msgKey, msg)
}

func (b *backendProxyManager) closeConnection(backendKey, msgKey string) error {
	b.mu.RLock()
	multiplexer, ok := b.multiplexers[backendKey]
	b.mu.RUnlock()
	if !ok {
		return fmt.Errorf("No backend for key [%v]", backendKey)
	}
	return multiplexer.closeConnection(msgKey, true)
}

func (b *backendProxyManager) releaseConnection(backendKey, msgKey string) error {
	b.mu.RLock()
	multiplexer, ok := b.multiplexers[backendKey]
	b.mu.RUnlock()
	if !ok {
		return fmt.Errorf("No backend for key [%v]", backendKey)
	}
	return multiplexer.closeConnection(msgKey, false)
}

func (b *backendProxyManager) hasBackend(backendKey string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.multiplexers[backendKey]
	return ok
}

func (b *backendProxyManager) addBackend(backendKey string, ws *websocket.Conn) {
	sessionID := common.NewRandomUUID()
	logrus.Infof("Registering backend for host %v with session ID %v.", backendKey, sessionID)

	msgs := make(chan string, 10)
	clients := make(map[string]chan<- common.Message)
	m := &multiplexer{
		backendSessionID:  sessionID,
		backendKey:        backendKey,
		messagesToBackend: msgs,
		frontendChans:     clients,
		proxyManager:      b,
		frontendMu:        &sync.RWMutex{},
		connection:        ws,
		done:              make(chan struct{}),
	}

	b.mu.Lock()
	previous := b.multiplexers[backendKey]
	b.multiplexers[backendKey] = m
	b.mu.Unlock()

	m.routeMessages(ws)
	if previous != nil {
		previous.shutdown()
	}
}

func (b *backendProxyManager) removeBackend(backendKey, sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m, ok := b.multiplexers[backendKey]; ok {
		if m.backendSessionID == sessionID {
			delete(b.multiplexers, backendKey)
			logrus.Infof("Removed backend. Key: %v. Session ID %v .", backendKey, sessionID)
		} else {
			logrus.Infof("Not removing backend for key %v. The provided session ID %v doesn't match registered session ID %v.",
				backendKey, sessionID, m.backendSessionID)
		}
	}
}
