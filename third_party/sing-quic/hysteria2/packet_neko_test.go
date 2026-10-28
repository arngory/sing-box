package hysteria2

import (
	"context"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

// A datagram that does not fit must be dropped: an error closes the whole UDP session.
func TestDropTooLarge(t *testing.T) {
	if dropTooLarge(&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}) != nil {
		t.Fatal("too large datagram not dropped")
	}
	if dropTooLarge(E.Cause(&quic.DatagramTooLargeError{}, "wrapped")) != nil {
		t.Fatal("wrapped too large datagram not dropped")
	}
	if dropTooLarge(E.New("closed")) == nil {
		t.Fatal("other errors must stay")
	}
}

// A received packet larger than the read buffer is skipped, the next one is read.
func TestReadPacketSkipsOversized(t *testing.T) {
	conn := newUDPPacketConn(context.Background(), nil, func() {})
	conn.data <- &udpMessage{destination: "1.1.1.1:53", data: buf.As(make([]byte, 3000))}
	conn.data <- &udpMessage{destination: "1.1.1.1:53", data: buf.As([]byte("small"))}
	buffer := buf.NewSize(1500)
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer.Bytes()) != "small" {
		t.Fatalf("read %d bytes, want the small packet", buffer.Len())
	}
	payload := make([]byte, 1500)
	conn.data <- &udpMessage{destination: "1.1.1.1:53", data: buf.As(make([]byte, 3000))}
	conn.data <- &udpMessage{destination: "1.1.1.1:53", data: buf.As([]byte("next"))}
	n, _, err := conn.ReadFrom(payload)
	if err != nil || string(payload[:n]) != "next" {
		t.Fatalf("ReadFrom: %q %v", payload[:n], err)
	}
}
