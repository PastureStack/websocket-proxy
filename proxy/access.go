// Package proxy is inspired by https://gist.github.com/cespare/3985516
package proxy

import (
	"net"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

type accessLog struct {
	ip, method, uri, protocol, host string
	elapsedTime                     time.Duration
}

func logAccess(w http.ResponseWriter, req *http.Request, duration time.Duration) {
	clientIP := req.RemoteAddr

	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	record := &accessLog{
		ip:          clientIP,
		method:      req.Method,
		uri:         safeAccessPath(req),
		protocol:    req.Proto,
		host:        req.Host,
		elapsedTime: duration,
	}

	writeAccessLog(record)
}

func safeAccessPath(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func writeAccessLog(record *accessLog) {
	logRecord := "" + record.ip + " " + record.protocol + " " + record.method + ": " + record.uri + ", host: " + record.host + " (load time: " + strconv.FormatFloat(record.elapsedTime.Seconds(), 'f', 5, 64) + " seconds)"
	log.Info(logRecord)
}
