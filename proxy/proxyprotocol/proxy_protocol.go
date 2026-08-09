// Package proxyprotocol is adapted from:
// https://github.com/armon/go-proxyproto
//
// The MIT License (MIT)
//
// # Copyright (c) 2014 Armon Dadgar
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package proxyprotocol

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// prefix is the string we look for at the start of a connection
	// to check if this connection is using the proxy protocol
	prefix    = []byte("PROXY ")
	prefixLen = len(prefix)
)

const maxProxyHeaderBytes = 108

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// Parsed client identity is made available to the HTTP forwarding-header
// integration without changing the underlying socket address.
type Listener struct {
	Listener          net.Listener
	TrustedProxyCIDRs []*net.IPNet
}

// Conn is used to wrap an underlying connection which
// may be speaking the Proxy Protocol. If it is, when Read() is called,
// the Proxy protocol header will be stripped and added to the context.
type Conn struct {
	bufReader *bufio.Reader
	conn      net.Conn
	allow     bool
	once      sync.Once
}

type ProxyProtoInfo struct {
	Protocol   string
	ClientAddr *net.TCPAddr
	ProxyAddr  *net.TCPAddr
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(conn, trustedProxySource(conn.RemoteAddr(), p.TrustedProxyCIDRs)), nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn) *Conn {
	return newConn(conn, true)
}

func newConn(conn net.Conn, allow bool) *Conn {
	pConn := &Conn{
		bufReader: bufio.NewReaderSize(conn, maxProxyHeaderBytes),
		conn:      conn,
		allow:     allow,
	}
	return pConn
}

// Read checks for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(b []byte) (int, error) {
	var err error
	p.once.Do(func() { err = p.checkPrefix() })
	if err != nil {
		return 0, err
	}
	return p.bufReader.Read(b)
}

func (p *Conn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *Conn) Close() error {
	return p.conn.Close()
}

func (p *Conn) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

func (p *Conn) RemoteAddr() net.Addr {
	return p.conn.RemoteAddr()
}

func (p *Conn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *Conn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) checkPrefix() error {
	if !p.allow {
		return nil
	}
	// Incrementally check each byte of the prefix
	for i := 1; i <= prefixLen; i++ {
		inp, err := p.bufReader.Peek(i)
		if err != nil {
			return err
		}

		// Check for a prefix mis-match, quit early
		if !bytes.Equal(inp, prefix[:i]) {
			return nil
		}
	}

	// Read the header line
	headerBytes, err := p.bufReader.ReadSlice('\n')
	if err != nil {
		p.conn.Close()
		return fmt.Errorf("invalid or oversized proxy protocol header")
	}
	if len(headerBytes) > maxProxyHeaderBytes || !bytes.HasSuffix(headerBytes, []byte("\r\n")) {
		p.conn.Close()
		return fmt.Errorf("invalid or oversized proxy protocol header")
	}
	// Strip the carriage return and new line.
	header := string(headerBytes[:len(headerBytes)-2])

	// Split on spaces, should be (PROXY <type> <src addr> <dst addr> <src port> <dst port>)
	parts := strings.Split(header, " ")
	if len(parts) != 6 {
		p.conn.Close()
		return fmt.Errorf("invalid proxy protocol header")
	}

	// Verify the type is known
	if parts[1] != "TCP4" && parts[1] != "TCP6" {
		p.conn.Close()
		return fmt.Errorf("unsupported proxy protocol address type")
	}

	// Parse out the source address
	srcAddr, err := parseAddr(parts[2], parts[4])
	if err != nil {
		p.conn.Close()
		return err
	}

	// Parse out the destination address
	destAddr, err := parseAddr(parts[3], parts[5])
	if err != nil {
		p.conn.Close()
		return err
	}
	if (parts[1] == "TCP4" && (srcAddr.IP.To4() == nil || destAddr.IP.To4() == nil)) ||
		(parts[1] == "TCP6" && (srcAddr.IP.To4() != nil || destAddr.IP.To4() != nil)) {
		p.conn.Close()
		return fmt.Errorf("proxy protocol address family mismatch")
	}

	proxyInfo := &ProxyProtoInfo{
		Protocol:   parts[1],
		ClientAddr: srcAddr,
		ProxyAddr:  destAddr,
	}
	putInfo(p.conn.RemoteAddr().String(), proxyInfo)

	return nil
}

func trustedProxySource(address net.Addr, trusted []*net.IPNet) bool {
	var ip net.IP
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		ip = tcpAddress.IP
	} else if address != nil {
		host, _, err := net.SplitHostPort(address.String())
		if err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return false
	}
	if len(trusted) == 0 {
		return ip.IsLoopback()
	}
	for _, network := range trusted {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseAddr(ipStr, portStr string) (*net.TCPAddr, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("Invalid ip: %s", ipStr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("Invalid port: %s", portStr)
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
