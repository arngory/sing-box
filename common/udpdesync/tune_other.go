//go:build !linux

package udpdesync

import "net"

const socketBufferSize = 8 << 20

// tuneSocket gives the socket quic-go's buffer sizes where the platform allows it.
func tuneSocket(conn net.Conn) {
	type bufferSetter interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	if setter, ok := conn.(bufferSetter); ok {
		setter.SetReadBuffer(socketBufferSize)
		setter.SetWriteBuffer(socketBufferSize)
	}
}
