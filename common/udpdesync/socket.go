package udpdesync

import "syscall"

// findSyscallConn is the socket under conn, through the wrappers that name their Upstream.
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
