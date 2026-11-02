package udpserver

import (
	"net"
	"time"
)

// UDPConn is the server's DNS socket. *net.UDPConn is one; niko-server passes a
// virtual one fed by its DNS front (neko).
type UDPConn interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	Close() error
	LocalAddr() net.Addr
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
	SetReadDeadline(t time.Time) error
}

// SetListener makes Run serve on conn instead of opening UDP_HOST:UDP_PORT (neko).
func (s *Server) SetListener(conn UDPConn) {
	s.nekoListener = conn
}

// SetStreamDialer replaces how the server connects a client stream to its upstream
// (neko: niko-server dials the inner stage's unix socket, whatever the address).
func (s *Server) SetStreamDialer(dial func(network, address string, timeout time.Duration) (net.Conn, error)) {
	s.dialStreamUpstreamFn = dial
}
