//go:build unix

package udpdesync

import (
	"net"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

// setTTL sets the IP TTL (or IPv6 hop limit) of the socket under conn and returns how to restore it.
func setTTL(conn net.Conn, ttl int) (func(), error) {
	syscallConn, ok := findSyscallConn(conn)
	if !ok {
		return func() {}, E.New("no socket")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return func() {}, err
	}
	level, option := syscall.IPPROTO_IP, syscall.IP_TTL
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok && addr.IP.To4() == nil {
		level, option = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	var old int
	var opErr error
	err = raw.Control(func(fd uintptr) {
		old, opErr = syscall.GetsockoptInt(int(fd), level, option)
		if opErr == nil {
			opErr = syscall.SetsockoptInt(int(fd), level, option, ttl)
		}
	})
	if err == nil {
		err = opErr
	}
	if err != nil {
		return func() {}, err
	}
	return func() {
		raw.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), level, option, old) })
	}, nil
}

func findSyscallConn(conn any) (syscall.Conn, bool) {
	for i := 0; i < 8 && conn != nil; i++ {
		if c, ok := conn.(syscall.Conn); ok {
			return c, true
		}
		upstream, ok := conn.(interface{ Upstream() any })
		if !ok {
			return nil, false
		}
		conn = upstream.Upstream()
	}
	return nil, false
}
