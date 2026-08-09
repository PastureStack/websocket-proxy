package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/PastureStack/websocket-proxy/k8s"
	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor"
	"github.com/PastureStack/websocket-proxy/proxy/proxyprotocol"
	proxyTls "github.com/PastureStack/websocket-proxy/proxy/tls"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var slashRegex = regexp.MustCompile("[/]{2,}")

type Starter struct {
	BackendPaths         []string
	FrontendPaths        []string
	FrontendHTTPPaths    []string
	StatsPaths           []string
	PlatformProxyPaths   []string
	PlatformWSProxyPaths []string
	Config               *Config
}

func (s *Starter) StartProxy() error {
	switcher := NewSwitcher(s.Config)
	tokenLookup, err := newTokenLookup(s.Config.PlatformAddr)
	if err != nil {
		return fmt.Errorf("invalid service-proxy configuration: %w", err)
	}

	backendMultiplexers := make(map[string]*multiplexer)
	bpm := &backendProxyManager{
		multiplexers: backendMultiplexers,
		mu:           &sync.RWMutex{},
	}

	frontendBaseHandler := &FrontendHandler{
		backend:         bpm,
		parsedPublicKey: s.Config.PublicKey,
	}
	frontendHandler := switcher.Wrap(frontendBaseHandler)
	persistentSessionHandler := switcher.Wrap(NewPersistentSessionHandler(frontendBaseHandler, bpm))

	statsHandler := switcher.Wrap(&StatsHandler{
		backend:         bpm,
		parsedPublicKey: s.Config.PublicKey,
	})

	backendHandler := switcher.Wrap(&BackendHandler{
		proxyManager:    bpm,
		parsedPublicKey: s.Config.PublicKey,
	})

	frontendHTTPHandler := switcher.Wrap(&FrontendHTTPHandler{
		FrontendHandler: FrontendHandler{
			backend:         bpm,
			parsedPublicKey: s.Config.PublicKey,
		},
		HTTPSPorts:  s.Config.ProxyProtoHTTPSPorts,
		TokenLookup: tokenLookup,
	})

	platformProxy, platformWsProxy, err := newPlatformProxies(s.Config)
	if err != nil {
		log.Fatalf("Couldn't create platform proxies: %v", err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/version", k8s.Version)
	router.HandleFunc("/swaggerapi/api/v1", k8s.Swagger)
	router.Handle("/v1/exec/sessions/{sessionId}", persistentSessionHandler).Methods("GET", "POST", "DELETE")

	for _, p := range s.BackendPaths {
		router.Handle(p, backendHandler).Methods("GET")
	}
	for _, p := range s.FrontendPaths {
		router.Handle(p, frontendHandler).Methods("GET")
	}
	for _, p := range s.FrontendHTTPPaths {
		router.Handle(p, frontendHTTPHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")
	}
	for _, p := range s.StatsPaths {
		router.Handle(p, statsHandler).Methods("GET")
	}

	if s.Config.PlatformAddr != "" {
		for _, p := range s.PlatformWSProxyPaths {
			router.Handle(p, platformWsProxy)
		}

		for _, p := range s.PlatformProxyPaths {
			router.Handle(p, platformProxy)
		}
	}

	if s.Config.ParentPid != 0 {
		go func() {
			for {
				process, err := os.FindProcess(s.Config.ParentPid)
				if err != nil {
					log.Fatalf("Failed to find process: %s\n", err)
				} else {
					err := process.Signal(syscall.Signal(0))
					if err != nil {
						log.Fatal("Parent process went away. Shutting down.")
					}
				}
				time.Sleep(time.Millisecond * 250)
			}
		}()
	}

	pcRouter := &pathCleaner{
		router: router,
	}

	swarmHandler := &SwarmHandler{
		FrontendHandler: frontendHTTPHandler,
		DefaultHandler:  pcRouter,
	}

	server := &http.Server{
		Handler:           swarmHandler,
		Addr:              s.Config.ListenAddr,
		ConnState:         proxyprotocol.StateCleanup,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	listener, err := net.Listen("tcp", s.Config.ListenAddr)
	if err != nil {
		log.Fatalf("Couldn't create listener: %s\n", err)
	}

	listener = &proxyprotocol.Listener{Listener: listener, TrustedProxyCIDRs: s.Config.TrustedProxyCIDRs}

	if s.Config.TLSListenAddr != "" {
		tlsConfig, err := s.setupTLS()
		if err != nil {
			return err
		}

		if s.Config.TLSListenAddr == s.Config.ListenAddr {
			listener = &proxyTls.SplitListener{
				Listener: listener,
				Config:   tlsConfig,
			}
		} else {
			tlsListener, err := net.Listen("tcp", s.Config.TLSListenAddr)
			if err != nil {
				return err
			}
			tlsListener = &proxyprotocol.Listener{Listener: tlsListener, TrustedProxyCIDRs: s.Config.TrustedProxyCIDRs}
			go func() {
				defer listener.Close()
				log.Error(server.Serve(tls.NewListener(tlsListener, tlsConfig)))
			}()
		}
	}

	err = server.Serve(listener)
	return err
}

func (s *Starter) setupTLS() (*tls.Config, error) {
	if s.Config.PlatformAccessKey == "" {
		return nil, fmt.Errorf("no access key supplied to download certificate")
	}

	certs, err := s.Config.GetCerts()
	if err != nil {
		return nil, err
	}
	return newServerTLSConfig(certs)
}

func newServerTLSConfig(certs *Certs) (*tls.Config, error) {
	if certs == nil {
		return nil, fmt.Errorf("certificate bundle is required")
	}
	tlsCert, err := tls.X509KeyPair(certs.Cert, certs.Key)
	if err != nil {
		return nil, fmt.Errorf("invalid server certificate or key: %w", err)
	}

	clientCas := x509.NewCertPool()
	if !clientCas.AppendCertsFromPEM(certs.CA) {
		return nil, fmt.Errorf("invalid client certificate authority bundle")
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCas,
		Certificates: []tls.Certificate{tlsCert},
	}

	return tlsConfig, nil
}

type pathCleaner struct {
	router *mux.Router
}

func (p *pathCleaner) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if cleanedPath := p.cleanPath(req.URL.Path); cleanedPath != req.URL.Path {
		req.URL.Path = cleanedPath
		req.URL.RawPath = ""
	}
	p.router.ServeHTTP(rw, req)
}

func (p *pathCleaner) cleanPath(path string) string {
	return slashRegex.ReplaceAllString(path, "/")
}

func newWSProxy(config *Config) (http.Handler, error) {
	baseURL, err := controlPlatformBaseURL(config.PlatformAddr)
	if err != nil {
		return nil, err
	}
	platformAddr := baseURL.Host
	director := func(req *http.Request) {
		req.URL.Scheme = baseURL.Scheme
		req.URL.Host = platformAddr
	}

	platformProxy := &httputil.ReverseProxy{
		Director:      director,
		FlushInterval: time.Millisecond * 100,
	}

	reverseProxy := &proxyProtocolConverter{
		p:          platformProxy,
		httpsPorts: config.ProxyProtoHTTPSPorts,
	}

	wsProxy := &platformWSProxy{
		reverseProxy: reverseProxy,
		platformAddr: platformAddr,
	}

	return wsProxy, nil
}

func newPlatformProxies(config *Config) (*proxyProtocolConverter, *platformWSProxy, error) {
	platformAddr := config.PlatformAddr

	apiProxyHandler, err := apiinterceptor.NewInterceptor(config.APIInterceptorConfigFile, platformAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create API interceptor: %w", err)
	}

	reverseProxy := &proxyProtocolConverter{
		httpsPorts: config.ProxyProtoHTTPSPorts,
		p:          apiProxyHandler,
	}

	wsProxy := &platformWSProxy{
		reverseProxy: reverseProxy,
		platformAddr: platformAddr,
	}

	return reverseProxy, wsProxy, nil
}

type proxyProtocolConverter struct {
	httpsPorts map[int]bool
	p          http.Handler
}

func (h *proxyProtocolConverter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	proxyprotocol.AddHeaders(req, h.httpsPorts)
	h.p.ServeHTTP(rw, req)
}

type platformWSProxy struct {
	reverseProxy *proxyProtocolConverter
	platformAddr string
}

func (h *platformWSProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if websocket.IsWebSocketUpgrade(req) {
		if !workspaceSameOrigin(req) {
			http.Error(rw, "Cross-origin websocket request denied", http.StatusForbidden)
			return
		}
		proxyprotocol.AddHeaders(req, h.reverseProxy.httpsPorts)
		h.serveWebsocket(rw, req)
	} else {
		h.reverseProxy.ServeHTTP(rw, req)
	}
}

func (h *platformWSProxy) serveWebsocket(rw http.ResponseWriter, req *http.Request) {
	// Inspired by https://groups.google.com/forum/#!searchin/golang-nuts/httputil.ReverseProxy$20$2B$20websockets/golang-nuts/KBx9pDlvFOc/01vn1qUyVdwJ
	target := h.platformAddr
	d, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.WithField("error", err).Error("Error dialing websocket backend.")
		http.Error(rw, "Unable to establish websocket connection: can't dial.", 500)
		return
	}
	hj, ok := rw.(http.Hijacker)
	if !ok {
		http.Error(rw, "Unable to establish websocket connection: no hijacker.", 500)
		return
	}
	nc, _, err := hj.Hijack()
	if err != nil {
		log.WithField("error", err).Error("Hijack error.")
		http.Error(rw, "Unable to establish websocket connection: can't hijack.", 500)
		return
	}
	defer nc.Close()
	defer d.Close()

	err = req.Write(d)
	if err != nil {
		log.WithField("error", err).Error("Error copying request to target.")
		return
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(d, nc)
	go cp(nc, d)
	<-errc
}
