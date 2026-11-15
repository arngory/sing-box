//go:build windows

package udpdesync

import (
	"net"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

// setTTL sets the IP TTL (or IPv6 hop limit) of the socket under conn and returns how to restore it (neko: the
// desktop client; Winsock has both options as Linux has).
func setTTL(conn net.Conn, ttl int) (func(), error) {
	syscallConn, ok := findSyscallConn(conn)
	if !ok {
		return func() {}, E.New("no socket")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return func() {}, err
	}
	level, option := windows.IPPROTO_IP, windows.IP_TTL
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok && addr.IP.To4() == nil {
		level, option = windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
	}
	var old int
	var opErr error
	err = raw.Control(func(fd uintptr) {
		old, opErr = windows.GetsockoptInt(windows.Handle(fd), level, option)
		if opErr == nil {
			opErr = windows.SetsockoptInt(windows.Handle(fd), level, option, ttl)
		}
	})
	if err == nil {
		err = opErr
	}
	if err != nil {
		return func() {}, err
	}
	return func() {
		raw.Control(func(fd uintptr) { windows.SetsockoptInt(windows.Handle(fd), level, option, old) })
	}, nil
}
