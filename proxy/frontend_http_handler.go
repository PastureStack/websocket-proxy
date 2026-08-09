package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/proxy/proxyprotocol"
)

type FrontendHTTPHandler struct {
	FrontendHandler
	HTTPSPorts  map[int]bool
	TokenLookup *TokenLookup
}

func (h *FrontendHTTPHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if err := h.serveHTTP(rw, req); err != nil {
		log.WithFields(log.Fields{"method": req.Method, "path": req.URL.EscapedPath()}).Error("Failed to handle proxied HTTP request.")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *FrontendHTTPHandler) serveHTTP(rw http.ResponseWriter, req *http.Request) error {
	token, hostKey, err := h.authAndLookup(req)
	if IsNoAuthError(err) {
		redirect := *req.URL
		redirect.RawQuery = "redirectTo=" + url.QueryEscape(req.URL.Path) + "#"
		redirect.Path = "/login"
		http.Redirect(rw, req, redirect.String(), 302)
		return nil
	} else if err != nil {
		http.Error(rw, "Service unavailable", 503)
		return nil
	}

	data, _ := objectClaim(token, "proxy")
	address, _ := data["address"].(string)
	scheme, _ := data["scheme"].(string)
	stripProxyAuthenticationQuery(req)

	proxyprotocol.AddHeaders(req, h.HTTPSPorts)
	proxyprotocol.AddForwardedFor(req)

	reader, writer, err := NewHTTPPipe(rw, h.backend, hostKey)
	if err != nil {
		log.Errorf("Failed to construct pipe to backend %s: %v", hostKey, err)
		return err
	}
	defer writer.Close()
	defer reader.Close()

	h.copyAuthHeaders(req)

	hijack := h.shouldHijack(req)

	if err := writer.WriteRequest(req, hijack, address, scheme); err != nil {
		log.Errorf("Failed to write request to backend: %v", err)
		return err
	}

	var input io.Reader
	var output io.Writer

	if hijack {
		hijacker, ok := rw.(http.Hijacker)
		if !ok {
			return errors.New("Invalid input")
		}

		httpConn, buf, err := hijacker.Hijack()
		if err != nil {
			log.Errorf("Failed to hijack connection: %v", err)
			return err
		}
		defer httpConn.Close()
		defer buf.Flush()

		input = buf
		output = buf
	} else {
		input = req.Body
		output = rw
	}

	go func() {
		io.Copy(writer, input)
		writer.Close()
	}()
	_, err = io.Copy(flusher{output}, reader)
	return err
}

func stripProxyAuthenticationQuery(req *http.Request) {
	query := req.URL.Query()
	query.Del("token")
	query.Del("access_token")
	req.URL.RawQuery = query.Encode()
}

func (h *FrontendHTTPHandler) copyAuthHeaders(req *http.Request) {
	c, err := req.Cookie("token")
	if err != nil {
		c = nil
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		tokenValue := "unauthorized"
		if c != nil {
			tokenValue = c.Value
		}
		req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte("Bearer "+tokenValue)))
	}
	stripProxyAuthenticationCookies(req)
	req.Header.Del("Proxy-Authorization")
}

func stripProxyAuthenticationCookies(req *http.Request) {
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != "token" {
			req.AddCookie(cookie)
		}
	}
}

type flusher struct {
	writer io.Writer
}

func (f flusher) Write(b []byte) (int, error) {
	defer flush(f.writer)
	return f.writer.Write(b)
}

func flush(writer io.Writer) {
	if buf, ok := writer.(*bufio.ReadWriter); ok {
		buf.Flush()
	} else if buf, ok := writer.(http.Flusher); ok {
		buf.Flush()
	}
}

func (h *FrontendHTTPHandler) shouldHijack(req *http.Request) bool {
	return workspaceHeaderContainsToken(req.Header, "Connection", "upgrade") && req.Header.Get("Upgrade") != ""
}

func (h *FrontendHTTPHandler) authAndLookup(req *http.Request) (*jwt.Token, string, error) {
	token, hostKey, err := h.FrontendHandler.auth(req)
	if err == nil {
		return token, hostKey, nil
	}

	tokenString, err := h.TokenLookup.Lookup(req)
	if err != nil {
		log.Error("Error looking up proxy token.")
		return nil, "", err
	}

	token, err = parseSignedJWT(tokenString, h.parsedPublicKey)
	if err != nil {
		return nil, "", err
	} else if !token.Valid {
		return nil, "", noAuthError{err: "Token is not valid"}
	}

	hostUUID, found := stringClaim(token, "hostUuid")
	if found && h.backend.hasBackend(hostUUID) {
		return token, hostUUID, nil
	}
	log.Info("Invalid backend host requested.")
	return nil, "", errors.New("invalid backend")
}
