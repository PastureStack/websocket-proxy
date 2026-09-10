package proxyprotocol

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	xForwardedProto string = "X-Forwarded-Proto"
	xForwardedPort  string = "X-Forwarded-Port"
	xForwardedFor   string = "X-Forwarded-For"
	xForwardedHost  string = "X-Forwarded-Host"
)

func AddHeaders(req *http.Request, httpsPorts map[int]bool, publicOrigin *url.URL) {
	proxyProtoInfo := getInfo(req.RemoteAddr)
	if proxyProtoInfo != nil {
		proto := "http"
		if _, ok := httpsPorts[proxyProtoInfo.ProxyAddr.Port]; ok {
			proto = "https"
		}
		req.Header.Set(xForwardedProto, proto)
		req.Header.Set(xForwardedPort, strconv.Itoa(proxyProtoInfo.ProxyAddr.Port))
		req.Header.Set(xForwardedFor, proxyProtoInfo.ClientAddr.IP.String())
	} else if req.TLS != nil {
		req.Header.Set(xForwardedProto, "https")
		req.Header.Del(xForwardedPort)
		req.Header.Set(xForwardedFor, requestClientIP(req))
	} else {
		req.Header.Set(xForwardedProto, "http")
		req.Header.Del(xForwardedPort)
		req.Header.Set(xForwardedFor, requestClientIP(req))
	}

	// A configured origin is explicit deployment authority, not a forwarded
	// client claim. Apply it only to requests for that same public host; all
	// other hosts retain transport-derived values above.
	if publicOriginMatchesRequest(req, publicOrigin) {
		req.Header.Set(xForwardedProto, publicOrigin.Scheme)
		req.Header.Set(xForwardedHost, publicOrigin.Host)
		port := publicOrigin.Port()
		if port == "" {
			if publicOrigin.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		req.Header.Set(xForwardedPort, port)
	} else {
		req.Header.Set(xForwardedHost, req.Host)
	}
}

func publicOriginMatchesRequest(req *http.Request, origin *url.URL) bool {
	if origin == nil || req == nil || req.Host == "" {
		return false
	}

	requestAuthority, err := url.Parse("//" + req.Host)
	if err != nil || requestAuthority.User != nil || requestAuthority.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(requestAuthority.Hostname(), origin.Hostname()) {
		return false
	}

	defaultPort := "80"
	if origin.Scheme == "https" {
		defaultPort = "443"
	}
	requestPort := requestAuthority.Port()
	if requestPort == "" {
		requestPort = defaultPort
	}
	originPort := origin.Port()
	if originPort == "" {
		originPort = defaultPort
	}
	return requestPort == originPort
}

func AddForwardedFor(req *http.Request) {
	req.Header.Set(xForwardedFor, requestClientIP(req))
}

func requestClientIP(req *http.Request) string {
	if info := getInfo(req.RemoteAddr); info != nil && info.ClientAddr != nil {
		return info.ClientAddr.IP.String()
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.Trim(req.RemoteAddr, "[]")
}

func StateCleanup(conn net.Conn, connState http.ConnState) {
	if connState == http.StateClosed {
		deleteInfo(conn.RemoteAddr().String())
	}
}
