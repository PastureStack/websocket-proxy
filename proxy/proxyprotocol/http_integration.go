package proxyprotocol

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

const (
	xForwardedProto string = "X-Forwarded-Proto"
	xForwardedPort  string = "X-Forwarded-Port"
	xForwardedFor   string = "X-Forwarded-For"
)

func AddHeaders(req *http.Request, httpsPorts map[int]bool) {
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
