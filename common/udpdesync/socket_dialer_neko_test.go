package udpdesync

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// plainDialer dials as the core's default dialer does for a direct outbound: UDP gives a *net.UDPConn.
type plainDialer struct {
	stream net.Conn
}

func (d plainDialer) DialContext(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		return net.DialUDP("udp", nil, destination.UDPAddr())
	}
	return d.stream, nil
}

func (plainDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func socketDial(t *testing.T, r *recorder, options Options) net.Conn {
	dialer := WrapSocketDialer(plainDialer{}, options, nil)
	conn, err := dialer.DialContext(context.Background(), N.NetworkUDP, M.SocksaddrFromNet(r.conn.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// With a prelude alone the client gets the socket itself, the fakes already on the wire: cronet takes its descriptor
// and writes past the core, so nothing of ours stays in the path.
func TestNekoSocketDialerPrelude(t *testing.T) {
	r := newRecorder(t)
	conn := socketDial(t, r, Options{Prelude: 2, PreludeSNI: "allowed.example.ru", PreludeTTL: 64})
	udpConn, isSocket := N.CastReader[*net.UDPConn](conn)
	if !isSocket {
		t.Fatalf("the client cannot reach the socket: %T", conn)
	}
	packets := r.snapshot()
	if len(packets) != 2 || !isInitial(packets[0]) || !isInitial(packets[1]) {
		t.Fatalf("want two fake Initials before the client writes, got %d datagrams", len(packets))
	}
	// what the client writes to the socket afterwards goes as is, with the socket's own TTL
	real := FakeInitial("real.example")
	udpConn.Write(real)
	packets = r.snapshot()
	if len(packets) != 3 || string(packets[2]) != string(real) {
		t.Fatalf("the client's datagram: %d datagrams", len(packets))
	}
}

// Reordering needs the datagrams, so the socket is hidden: cronet finds no *net.UDPConn and relays through the
// connection, datagram by datagram.
func TestNekoSocketDialerReorder(t *testing.T) {
	r := newRecorder(t)
	conn := socketDial(t, r, Options{Prelude: 1, ReorderInitial: true})
	if _, isSocket := N.CastReader[*net.UDPConn](conn); isSocket {
		t.Fatal("the socket is reachable: the client would write past the reordering")
	}
	if _, hasUpstream := conn.(common.WithUpstream); hasUpstream {
		t.Fatal("the connection names an upstream")
	}
	first, second := FakeInitial("one.example"), FakeInitial("two.example")
	conn.Write(first)
	conn.Write(second)
	packets := r.snapshot()
	if len(packets) != 3 {
		t.Fatalf("%d datagrams, want 3", len(packets))
	}
	if isInitial(packets[0]) {
		t.Fatal("the prelude is not noise")
	}
	if string(packets[1]) != string(second) || string(packets[2]) != string(first) {
		t.Fatal("Initials not reordered")
	}
}

// TCP is not touched, and with nothing enabled the dialer is not wrapped at all.
func TestNekoSocketDialerLeavesTheRest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	inner := plainDialer{stream: client}
	dialer := WrapSocketDialer(inner, Options{Prelude: 3, ReorderInitial: true}, nil)
	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil || conn != client {
		t.Fatalf("TCP connection wrapped: %T, %v", conn, err)
	}
	if WrapSocketDialer(inner, Options{}, nil) != N.Dialer(inner) {
		t.Fatal("wrapped with nothing enabled")
	}
}
