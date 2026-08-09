package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	workspaceSubprotocol          = "pasturestack-console-v1"
	workspaceSecretProtocolPrefix = "pasturestack-secret."
	workspaceClientProtocolPrefix = "pasturestack-client."
	workspaceSecretHeader         = "X-PastureStack-Session-Secret"

	workspaceMaxCreateBody          = 128 * 1024
	workspaceMaxClientFrame         = 96 * 1024
	workspaceClientQueueSize        = 256
	workspaceWriteWait              = 10 * time.Second
	workspacePongWait               = 60 * time.Second
	workspacePingPeriod             = 25 * time.Second
	defaultWorkspaceSessions        = 24
	defaultWorkspaceReplayBytes     = 2 * 1024 * 1024
	defaultWorkspaceActiveRetention = 72 * time.Hour
	defaultWorkspaceEndedRetention  = 24 * time.Hour
	defaultWorkspaceCleanupInterval = time.Minute
)

var (
	workspaceSessionIDPattern = regexp.MustCompile(`^psw_[A-Za-z0-9_-]{20,96}$`)
	workspaceClientIDPattern  = regexp.MustCompile(`^tab_[A-Za-z0-9_-]{20,96}$`)
	workspaceSecretPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{40,256}$`)

	errWorkspaceSessionConflict = errors.New("workspace session conflict")
	errWorkspaceSessionLimit    = errors.New("workspace session limit reached")
)

type PersistentSessionHandler struct {
	frontend *FrontendHandler
	manager  *persistentSessionManager
	upgrader websocket.Upgrader
}

type persistentSessionManager struct {
	backend         backendProxy
	maxSessions     int
	maxReplayBytes  int
	activeRetention time.Duration
	endedRetention  time.Duration
	cleanupInterval time.Duration

	mu       sync.RWMutex
	sessions map[string]*persistentSession
	stop     chan struct{}
	done     chan struct{}
}

type persistentSession struct {
	id         string
	kind       string
	hostKey    string
	msgKey     string
	secretHash [sha256.Size]byte
	backend    backendProxy

	mu             sync.Mutex
	status         string
	controller     string
	createdAt      time.Time
	lastActivity   time.Time
	endedAt        time.Time
	closeOnce      sync.Once
	nextSequence   uint64
	replayBytes    int
	maxReplayBytes int
	replay         []workspaceReplayEntry
	clients        map[string]*workspaceClient
}

type workspaceClient struct {
	clientID  string
	ws        *websocket.Conn
	send      chan []byte
	done      chan struct{}
	closeOnce sync.Once
	session   *persistentSession
}

type workspaceCreateRequest struct {
	Secret string `json:"secret"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Token  string `json:"token"`
}

type workspaceReplayEntry struct {
	Sequence uint64 `json:"sequence"`
	Data     string `json:"data"`
}

type workspaceServerFrame struct {
	Type         string                 `json:"type"`
	Code         string                 `json:"code,omitempty"`
	Message      string                 `json:"message,omitempty"`
	SessionID    string                 `json:"sessionId,omitempty"`
	Kind         string                 `json:"kind,omitempty"`
	Status       string                 `json:"status,omitempty"`
	ControllerID string                 `json:"controllerId,omitempty"`
	Sequence     uint64                 `json:"sequence,omitempty"`
	Data         string                 `json:"data,omitempty"`
	CreatedAt    string                 `json:"createdAt,omitempty"`
	LastActivity string                 `json:"lastActivity,omitempty"`
	Replay       []workspaceReplayEntry `json:"replay,omitempty"`
}

type workspaceClientFrame struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func NewPersistentSessionHandler(frontend *FrontendHandler, backend backendProxy) *PersistentSessionHandler {
	manager := &persistentSessionManager{
		backend:         backend,
		maxSessions:     workspaceInteger("PASTURESTACK_WORKSPACE_MAX_SESSIONS", defaultWorkspaceSessions, 1, 256),
		maxReplayBytes:  workspaceInteger("PASTURESTACK_WORKSPACE_REPLAY_BYTES", defaultWorkspaceReplayBytes, 64*1024, 16*1024*1024),
		activeRetention: workspaceDuration("PASTURESTACK_WORKSPACE_ACTIVE_RETENTION", defaultWorkspaceActiveRetention, time.Minute, 7*24*time.Hour),
		endedRetention:  workspaceDuration("PASTURESTACK_WORKSPACE_ENDED_RETENTION", defaultWorkspaceEndedRetention, time.Minute, 7*24*time.Hour),
		cleanupInterval: workspaceDuration("PASTURESTACK_WORKSPACE_CLEANUP_INTERVAL", defaultWorkspaceCleanupInterval, time.Second, time.Hour),
		sessions:        make(map[string]*persistentSession),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}
	go manager.cleanupLoop()

	return &PersistentSessionHandler{
		frontend: frontend,
		manager:  manager,
		upgrader: websocket.Upgrader{
			HandshakeTimeout: 10 * time.Second,
			ReadBufferSize:   16 * 1024,
			WriteBufferSize:  16 * 1024,
			CheckOrigin:      workspaceSameOrigin,
			Subprotocols:     []string{workspaceSubprotocol},
		},
	}
}

func (h *PersistentSessionHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	sessionID := mux.Vars(req)["sessionId"]
	if !workspaceSessionIDPattern.MatchString(sessionID) {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_session_id", "Invalid console session identifier")
		return
	}

	switch req.Method {
	case http.MethodPost:
		h.createSession(rw, req, sessionID)
	case http.MethodGet:
		if workspaceIsWebSocketUpgrade(req) {
			h.attachSession(rw, req, sessionID)
		} else {
			h.sessionStatus(rw, req, sessionID)
		}
	case http.MethodDelete:
		h.terminateSession(rw, req, sessionID)
	default:
		rw.Header().Set("Allow", "GET, POST, DELETE")
		writeWorkspaceJSONError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (h *PersistentSessionHandler) createSession(rw http.ResponseWriter, req *http.Request, sessionID string) {
	if !workspaceRequestOriginAllowed(req) {
		writeWorkspaceJSONError(rw, http.StatusForbidden, "origin_denied", "Cross-origin session creation is not allowed")
		return
	}

	body := http.MaxBytesReader(rw, req.Body, workspaceMaxCreateBody)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var input workspaceCreateRequest
	if err := decoder.Decode(&input); err != nil {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_request", "Invalid session creation request")
		return
	}
	if err := ensureWorkspaceJSONEnd(decoder); err != nil {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_request", "Invalid session creation request")
		return
	}
	if err := validateWorkspaceCredentials(sessionID, input.Secret, input.Kind); err != nil {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(input.Token) < 8 || len(input.Token) > 16*1024 {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_token", "Invalid upstream access token")
		return
	}

	secretHash := sha256.Sum256([]byte(input.Secret))
	if existing := h.manager.get(sessionID); existing != nil {
		if !existing.matchesSecretHash(secretHash) || existing.kind != input.Kind {
			writeWorkspaceJSONError(rw, http.StatusConflict, "session_conflict", "Console session identifier is already in use")
			return
		}
		writeWorkspaceSession(rw, http.StatusOK, existing)
		return
	}

	targetURL, err := workspaceTargetURL(req, input.Kind, input.Target, input.Token)
	if err != nil {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}

	authRequest := req.Clone(req.Context())
	authRequest.Header = req.Header.Clone()
	authRequest.Header.Set("Authorization", "Bearer "+input.Token)
	authURL := *req.URL
	authURL.RawQuery = ""
	authRequest.URL = &authURL
	_, hostKey, err := h.frontend.auth(authRequest)
	if err != nil {
		writeWorkspaceJSONError(rw, http.StatusUnauthorized, "authentication_failed", "Workspace session authentication failed")
		return
	}

	session, created, err := h.manager.create(sessionID, input.Kind, secretHash, hostKey, targetURL)
	if err != nil {
		switch err {
		case errWorkspaceSessionConflict:
			writeWorkspaceJSONError(rw, http.StatusConflict, "session_conflict", "Console session identifier is already in use")
		case errWorkspaceSessionLimit:
			writeWorkspaceJSONError(rw, http.StatusTooManyRequests, "session_limit", "Console session limit reached")
		default:
			log.WithField("error", err).Error("Failed to create persistent workspace session.")
			writeWorkspaceJSONError(rw, http.StatusBadGateway, "upstream_unavailable", "Unable to start the console session")
		}
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeWorkspaceSession(rw, status, session)
}

func (h *PersistentSessionHandler) sessionStatus(rw http.ResponseWriter, req *http.Request, sessionID string) {
	session := h.manager.get(sessionID)
	if session == nil {
		writeWorkspaceJSON(rw, http.StatusOK, map[string]string{"status": "missing"})
		return
	}
	secretHash := sha256.Sum256([]byte(req.Header.Get(workspaceSecretHeader)))
	if !session.matchesSecretHash(secretHash) {
		writeWorkspaceJSONError(rw, http.StatusForbidden, "secret_denied", "Console session access was denied")
		return
	}
	writeWorkspaceSession(rw, http.StatusOK, session)
}

func (h *PersistentSessionHandler) terminateSession(rw http.ResponseWriter, req *http.Request, sessionID string) {
	if !workspaceRequestOriginAllowed(req) {
		writeWorkspaceJSONError(rw, http.StatusForbidden, "origin_denied", "Cross-origin session termination is not allowed")
		return
	}
	session := h.manager.get(sessionID)
	if session == nil {
		rw.Header().Set("Cache-Control", "no-store")
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	secretHash := sha256.Sum256([]byte(req.Header.Get(workspaceSecretHeader)))
	if !session.matchesSecretHash(secretHash) {
		writeWorkspaceJSONError(rw, http.StatusForbidden, "secret_denied", "Console session access was denied")
		return
	}
	session.terminate("user")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusNoContent)
}

func (h *PersistentSessionHandler) attachSession(rw http.ResponseWriter, req *http.Request, sessionID string) {
	if !workspaceHasWebsocketProtocol(req, workspaceSubprotocol) {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_subprotocol", "Console WebSocket subprotocol is required")
		return
	}
	session := h.manager.get(sessionID)
	if session == nil {
		writeWorkspaceJSONError(rw, http.StatusNotFound, "session_not_found", "Console session was not found")
		return
	}
	secret := workspaceWebsocketCredential(req, workspaceSecretProtocolPrefix)
	secretHash := sha256.Sum256([]byte(secret))
	if !workspaceSecretPattern.MatchString(secret) || !session.matchesSecretHash(secretHash) {
		writeWorkspaceJSONError(rw, http.StatusForbidden, "secret_denied", "Console session access was denied")
		return
	}
	clientID := workspaceWebsocketCredential(req, workspaceClientProtocolPrefix)
	if !workspaceClientIDPattern.MatchString(clientID) {
		writeWorkspaceJSONError(rw, http.StatusBadRequest, "invalid_client_id", "Invalid browser tab identifier")
		return
	}

	ws, err := h.upgrader.Upgrade(rw, req, nil)
	if err != nil {
		return
	}
	client := &workspaceClient{
		clientID: clientID,
		ws:       ws,
		send:     make(chan []byte, workspaceClientQueueSize),
		done:     make(chan struct{}),
		session:  session,
	}
	session.addClient(client)
	go client.writeLoop()
	client.readLoop()
}

func (m *persistentSessionManager) get(id string) *persistentSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

func (m *persistentSessionManager) create(id, kind string, secretHash [sha256.Size]byte, hostKey, targetURL string) (*persistentSession, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing := m.sessions[id]; existing != nil {
		if !existing.matchesSecretHash(secretHash) || existing.kind != kind {
			return nil, false, errWorkspaceSessionConflict
		}
		return existing, false, nil
	}
	if m.activeSessionCountLocked() >= m.maxSessions {
		return nil, false, errWorkspaceSessionLimit
	}

	msgKey, responseChannel, err := m.backend.initializeClient(hostKey)
	if err != nil {
		return nil, false, err
	}

	now := time.Now().UTC()
	session := &persistentSession{
		id:             id,
		kind:           kind,
		hostKey:        hostKey,
		msgKey:         msgKey,
		secretHash:     secretHash,
		backend:        m.backend,
		status:         "connecting",
		createdAt:      now,
		lastActivity:   now,
		maxReplayBytes: m.maxReplayBytes,
		replay:         make([]workspaceReplayEntry, 0),
		clients:        make(map[string]*workspaceClient),
	}
	m.sessions[id] = session

	if err := m.backend.connect(hostKey, msgKey, targetURL); err != nil {
		delete(m.sessions, id)
		_ = m.backend.releaseConnection(hostKey, msgKey)
		return nil, false, err
	}
	session.status = "connected"
	session.lastActivity = time.Now().UTC()

	go session.pump(responseChannel)
	return session, true, nil
}

func (m *persistentSessionManager) activeSessionCountLocked() int {
	count := 0
	for _, session := range m.sessions {
		session.mu.Lock()
		status := session.status
		session.mu.Unlock()
		if status != "ended" && status != "error" {
			count++
		}
	}
	return count
}

func (m *persistentSessionManager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer func() {
		ticker.Stop()
		close(m.done)
	}()
	for {
		select {
		case now := <-ticker.C:
			m.cleanup(now.UTC())
		case <-m.stop:
			return
		}
	}
}

func (m *persistentSessionManager) cleanup(now time.Time) {
	type expiredSession struct {
		session *persistentSession
		active  bool
	}
	var expired []expiredSession

	m.mu.Lock()
	for id, session := range m.sessions {
		remove, active := session.expired(now, m.activeRetention, m.endedRetention)
		if !remove {
			continue
		}
		delete(m.sessions, id)
		expired = append(expired, expiredSession{session: session, active: active})
	}
	m.mu.Unlock()

	for _, entry := range expired {
		if entry.active {
			entry.session.terminate("expired")
		}
		entry.session.closeClients()
	}
}

func (s *persistentSession) matchesSecretHash(candidate [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(candidate[:], s.secretHash[:]) == 1
}

func (s *persistentSession) expired(now time.Time, activeRetention, endedRetention time.Duration) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == "ended" || s.status == "error" {
		return !s.endedAt.IsZero() && now.Sub(s.endedAt) >= endedRetention, false
	}
	return now.Sub(s.lastActivity) >= activeRetention, true
}

func (s *persistentSession) pump(responseChannel <-chan common.Message) {
	defer func() {
		s.markEnded()
		_ = s.backend.releaseConnection(s.hostKey, s.msgKey)
	}()
	for message := range responseChannel {
		switch message.Type {
		case common.Body:
			s.appendOutput(message.Body)
		case common.Close:
			return
		}
	}
}

func (s *persistentSession) appendOutput(data string) {
	now := time.Now().UTC()
	s.mu.Lock()
	if s.status == "ended" || s.status == "error" || s.status == "closing" {
		s.mu.Unlock()
		return
	}
	s.status = "connected"
	s.lastActivity = now
	s.nextSequence++
	entry := workspaceReplayEntry{Sequence: s.nextSequence, Data: data}
	frameBytes := len(data) + 32
	if frameBytes <= s.maxReplayBytes {
		s.replay = append(s.replay, entry)
		s.replayBytes += frameBytes
		for s.replayBytes > s.maxReplayBytes && len(s.replay) > 0 {
			removed := s.replay[0]
			s.replay = s.replay[1:]
			s.replayBytes -= len(removed.Data) + 32
		}
	}
	s.broadcastLocked(workspaceServerFrame{
		Type:      "output",
		SessionID: s.id,
		Sequence:  entry.Sequence,
		Data:      entry.Data,
		Status:    s.status,
	})
	s.mu.Unlock()
}

func (s *persistentSession) addClient(client *workspaceClient) {
	s.mu.Lock()
	if previous := s.clients[client.clientID]; previous != nil {
		delete(s.clients, client.clientID)
		previous.close()
	}
	s.clients[client.clientID] = client
	s.lastActivity = time.Now().UTC()
	if s.kind == "terminal" && s.controller == "" && s.status != "ended" && s.status != "error" {
		s.controller = client.clientID
	}
	replay := append([]workspaceReplayEntry(nil), s.replay...)
	client.enqueueJSON(workspaceServerFrame{
		Type:         "hello",
		SessionID:    s.id,
		Kind:         s.kind,
		Status:       s.status,
		ControllerID: s.controller,
		CreatedAt:    s.createdAt.Format(time.RFC3339Nano),
		LastActivity: s.lastActivity.Format(time.RFC3339Nano),
	})
	client.enqueueJSON(workspaceServerFrame{
		Type:      "replay",
		SessionID: s.id,
		Replay:    replay,
	})
	s.broadcastLocked(s.controlFrameLocked())
	s.mu.Unlock()
}

func (s *persistentSession) removeClient(client *workspaceClient) {
	s.mu.Lock()
	if current := s.clients[client.clientID]; current == client {
		delete(s.clients, client.clientID)
	}
	if s.controller == client.clientID {
		s.controller = ""
		for id := range s.clients {
			s.controller = id
			break
		}
		s.broadcastLocked(s.controlFrameLocked())
	}
	s.mu.Unlock()
	client.close()
}

func (s *persistentSession) handleClientFrame(client *workspaceClient, frame workspaceClientFrame) {
	switch frame.Type {
	case "claim":
		s.claimControl(client)
	case "input":
		s.writeInput(client, frame.Data)
	case "resize":
		s.resize(client, frame.Cols, frame.Rows)
	case "ping":
		client.enqueueJSON(workspaceServerFrame{Type: "pong"})
	}
}

func (s *persistentSession) claimControl(client *workspaceClient) {
	s.mu.Lock()
	if s.kind == "terminal" && s.status != "ended" && s.status != "error" &&
		s.clients[client.clientID] == client {
		s.controller = client.clientID
		s.lastActivity = time.Now().UTC()
		s.broadcastLocked(s.controlFrameLocked())
	}
	s.mu.Unlock()
}

func (s *persistentSession) writeInput(client *workspaceClient, data string) {
	s.mu.Lock()
	allowed := s.kind == "terminal" && s.status == "connected" &&
		s.controller == client.clientID && s.clients[client.clientID] == client
	s.mu.Unlock()
	if !allowed || len(data) == 0 || len(data) > workspaceMaxClientFrame {
		return
	}
	if _, err := base64.StdEncoding.DecodeString(data); err != nil {
		client.enqueueJSON(workspaceServerFrame{Type: "error", Code: "invalid_input", Message: "Terminal input was not valid base64 data"})
		return
	}
	s.touch()
	if err := s.backend.send(s.hostKey, s.msgKey, data); err != nil {
		client.enqueueJSON(workspaceServerFrame{Type: "error", Code: "input_failed", Message: "Unable to send terminal input"})
		s.terminate("input-failed")
	}
}

func (s *persistentSession) resize(client *workspaceClient, cols, rows int) {
	s.mu.Lock()
	allowed := s.kind == "terminal" && s.status == "connected" &&
		s.controller == client.clientID && s.clients[client.clientID] == client
	s.mu.Unlock()
	if !allowed || cols < 2 || cols > 1000 || rows < 2 || rows > 1000 {
		return
	}
	s.touch()
	resize := ":resizeTTY:" + strconv.Itoa(cols) + "," + strconv.Itoa(rows)
	if err := s.backend.send(s.hostKey, s.msgKey, resize); err != nil {
		client.enqueueJSON(workspaceServerFrame{Type: "error", Code: "resize_failed", Message: "Unable to resize terminal"})
		s.terminate("resize-failed")
	}
}

func (s *persistentSession) touch() {
	s.mu.Lock()
	if s.status == "connected" {
		s.lastActivity = time.Now().UTC()
	}
	s.mu.Unlock()
}

func (s *persistentSession) terminate(reason string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.status == "ended" || s.status == "error" {
			s.mu.Unlock()
			return
		}
		s.status = "closing"
		s.lastActivity = time.Now().UTC()
		s.broadcastLocked(workspaceServerFrame{
			Type:         "status",
			Status:       s.status,
			ControllerID: s.controller,
			LastActivity: s.lastActivity.Format(time.RFC3339Nano),
		})
		s.mu.Unlock()

		if err := s.backend.closeConnection(s.hostKey, s.msgKey); err != nil {
			log.WithFields(log.Fields{"error": err, "reason": reason}).Warn("Failed to close persistent workspace backend.")
			s.markEnded()
		}
	})
}

func (s *persistentSession) markEnded() {
	s.mu.Lock()
	if s.status == "ended" {
		s.mu.Unlock()
		return
	}
	s.status = "ended"
	s.controller = ""
	s.endedAt = time.Now().UTC()
	s.lastActivity = s.endedAt
	s.broadcastLocked(workspaceServerFrame{
		Type:         "status",
		Status:       s.status,
		ControllerID: "",
		LastActivity: s.lastActivity.Format(time.RFC3339Nano),
	})
	s.mu.Unlock()
}

func (s *persistentSession) closeClients() {
	s.mu.Lock()
	clients := make([]*workspaceClient, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.clients = make(map[string]*workspaceClient)
	s.controller = ""
	s.mu.Unlock()
	for _, client := range clients {
		client.close()
	}
}

func (s *persistentSession) controlFrameLocked() workspaceServerFrame {
	return workspaceServerFrame{
		Type:         "control",
		SessionID:    s.id,
		Status:       s.status,
		ControllerID: s.controller,
	}
}

func (s *persistentSession) broadcastLocked(frame workspaceServerFrame) {
	payload, err := json.Marshal(frame)
	if err != nil {
		return
	}
	for _, client := range s.clients {
		if !client.enqueue(payload) {
			client.close()
		}
	}
}

func (c *workspaceClient) enqueueJSON(frame workspaceServerFrame) bool {
	payload, err := json.Marshal(frame)
	if err != nil {
		return false
	}
	return c.enqueue(payload)
}

func (c *workspaceClient) enqueue(payload []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- payload:
		return true
	default:
		return false
	}
}

func (c *workspaceClient) readLoop() {
	defer c.session.removeClient(c)
	c.ws.SetReadLimit(workspaceMaxClientFrame)
	_ = c.ws.SetReadDeadline(time.Now().Add(workspacePongWait))
	c.ws.SetPongHandler(func(string) error {
		return c.ws.SetReadDeadline(time.Now().Add(workspacePongWait))
	})
	for {
		_, raw, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		var frame workspaceClientFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			c.enqueueJSON(workspaceServerFrame{Type: "error", Code: "invalid_frame", Message: "Invalid console client frame"})
			continue
		}
		c.session.handleClientFrame(c, frame)
	}
}

func (c *workspaceClient) writeLoop() {
	ticker := time.NewTicker(workspacePingPeriod)
	defer ticker.Stop()
	defer c.close()
	for {
		select {
		case payload := <-c.send:
			_ = c.ws.SetWriteDeadline(time.Now().Add(workspaceWriteWait))
			if err := c.ws.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.ws.SetWriteDeadline(time.Now().Add(workspaceWriteWait))
			if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(workspaceWriteWait)); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *workspaceClient) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.ws.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
		_ = c.ws.Close()
	})
}

func validateWorkspaceCredentials(sessionID, secret, kind string) error {
	if !workspaceSessionIDPattern.MatchString(sessionID) {
		return errors.New("invalid console session identifier")
	}
	if !workspaceSecretPattern.MatchString(secret) {
		return errors.New("invalid console session secret")
	}
	if kind != "terminal" && kind != "logs" {
		return errors.New("console session kind must be terminal or logs")
	}
	return nil
}

func workspaceTargetURL(req *http.Request, kind, rawTarget, token string) (string, error) {
	if len(rawTarget) < 8 || len(rawTarget) > 16*1024 {
		return "", errors.New("invalid upstream target")
	}
	target, err := url.Parse(rawTarget)
	if err != nil || (target.Scheme != "ws" && target.Scheme != "wss") ||
		target.Host == "" || target.User != nil || target.Fragment != "" {
		return "", errors.New("invalid upstream target")
	}
	if !workspaceSameHost(target.Host, req.Host) {
		return "", errors.New("upstream target must match the current PastureStack server")
	}
	path := strings.TrimSuffix(target.EscapedPath(), "/")
	allowed := false
	switch kind {
	case "terminal":
		allowed = path == "/v1/exec" || path == "/v2-beta/exec" || path == "/v2/exec"
	case "logs":
		allowed = path == "/v1/logs" || path == "/v2-beta/logs" || path == "/v2/logs"
	}
	if !allowed {
		return "", errors.New("upstream target path is not allowed")
	}
	query := target.Query()
	query.Set("token", token)
	internal := &url.URL{Path: target.Path, RawPath: target.RawPath, RawQuery: query.Encode()}
	return internal.RequestURI(), nil
}

func ensureWorkspaceJSONEnd(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func workspaceWebsocketCredential(req *http.Request, prefix string) string {
	for _, protocol := range websocket.Subprotocols(req) {
		if strings.HasPrefix(protocol, prefix) {
			return strings.TrimPrefix(protocol, prefix)
		}
	}
	return ""
}

func workspaceHasWebsocketProtocol(req *http.Request, expected string) bool {
	for _, protocol := range websocket.Subprotocols(req) {
		if protocol == expected {
			return true
		}
	}
	return false
}

func workspaceIsWebSocketUpgrade(req *http.Request) bool {
	return workspaceHeaderContainsToken(req.Header, "Connection", "upgrade") &&
		workspaceHeaderContainsToken(req.Header, "Upgrade", "websocket")
}

func workspaceHeaderContainsToken(header http.Header, name, expected string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func workspaceRequestOriginAllowed(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") &&
		workspaceSameHost(parsed.Host, req.Host)
}

func workspaceSameOrigin(req *http.Request) bool {
	return workspaceRequestOriginAllowed(req)
}

func workspaceSameHost(left, right string) bool {
	leftHost, leftPort := workspaceSplitHostPort(left)
	rightHost, rightPort := workspaceSplitHostPort(right)
	return strings.EqualFold(leftHost, rightHost) && leftPort == rightPort
}

func workspaceSplitHostPort(value string) (string, string) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return strings.Trim(strings.ToLower(host), "[]"), port
	}
	return strings.Trim(strings.ToLower(value), "[]"), ""
}

func writeWorkspaceSession(rw http.ResponseWriter, status int, session *persistentSession) {
	session.mu.Lock()
	response := map[string]interface{}{
		"sessionId":    session.id,
		"kind":         session.kind,
		"status":       session.status,
		"controllerId": session.controller,
		"clientCount":  len(session.clients),
		"replayFrames": len(session.replay),
		"lastActivity": session.lastActivity.Format(time.RFC3339Nano),
		"createdAt":    session.createdAt.Format(time.RFC3339Nano),
	}
	session.mu.Unlock()
	writeWorkspaceJSON(rw, status, response)
}

func writeWorkspaceJSONError(rw http.ResponseWriter, status int, code, message string) {
	writeWorkspaceJSON(rw, status, workspaceServerFrame{
		Type:    "error",
		Code:    code,
		Message: message,
	})
}

func writeWorkspaceJSON(rw http.ResponseWriter, status int, value interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(value)
}

func workspaceInteger(key string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(workspaceEnv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func workspaceDuration(key string, fallback, minimum, maximum time.Duration) time.Duration {
	raw := strings.TrimSpace(workspaceEnv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

var workspaceEnv = os.Getenv
