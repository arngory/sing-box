//go:build linux

package udpdesync

import (
	"net"

	"golang.org/x/sys/unix"
)

// quic-go's DesiredReceiveBufferSize / DesiredSendBufferSize
const socketBufferSize = 8 << 20

// tuneSocket does what quic-go does for a raw UDP socket, since it no longer sees
// one behind this wrapper: large buffers and DF for path MTU discovery
// (IP_PMTUDISC_PROBE, as quic-go sets it). Errors are ignored like in quic-go.
func tuneSocket(conn net.Conn) {
	syscallConn, ok := findSyscallConn(conn)
	if !ok {
		return
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		for _, option := range []struct{ normal, force int }{
			{unix.SO_RCVBUF, unix.SO_RCVBUFFORCE},
			{unix.SO_SNDBUF, unix.SO_SNDBUFFORCE},
		} {
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option.normal, socketBufferSize) == nil {
				if size, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option.normal); err == nil && size >= socketBufferSize {
					continue
				}
			}
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option.force, socketBufferSize)
		}
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
	})
}
