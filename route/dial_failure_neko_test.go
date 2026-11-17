package route

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type failingOutbound struct{ tag string }

func (o failingOutbound) Type() string           { return "test" }
func (o failingOutbound) Tag() string            { return o.tag }
func (o failingOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o failingOutbound) Dependencies() []string { return nil }
func (o failingOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("no answer from the node")
}

func (o failingOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no answer from the node")
}

type heardFailure struct{ tag, destination, err string }

type failureLog []heardFailure

func (l *failureLog) DialFailed(tag string, destination string, err error) {
	*l = append(*l, heardFailure{tag, destination, err.Error()})
}

// The running core's connections that do not open are heard with their outbound and destination; a core without an
// observer in its context (a test core) says nothing.
func TestNekoDialFailureObserved(t *testing.T) {
	heard := &failureLog{}
	ctx := service.ContextWith[DialFailureObserver](context.Background(), heard)
	manager := NewConnectionManager(ctx, log.NewNOPFactory().Logger())
	destination := M.ParseSocksaddr("93.184.216.34:443")

	client, server := net.Pipe()
	defer client.Close()
	manager.NewConnection(ctx, failingOutbound{tag: "proxy"}, server, adapter.InboundContext{Destination: destination}, nil)
	packetClient, packetServer := net.Pipe()
	defer packetClient.Close()
	manager.NewPacketConnection(ctx, failingOutbound{tag: "proxy"}, bufio.NewPacketConn(&pipePacketConn{packetServer}),
		adapter.InboundContext{Destination: destination}, nil)

	if len(*heard) != 2 {
		t.Fatalf("heard %d failures: %+v", len(*heard), *heard)
	}
	for _, failure := range *heard {
		if failure.tag != "proxy" || failure.destination != "93.184.216.34:443" || failure.err != "no answer from the node" {
			t.Errorf("%+v", failure)
		}
	}

	quiet := NewConnectionManager(context.Background(), log.NewNOPFactory().Logger())
	other, otherServer := net.Pipe()
	defer other.Close()
	quiet.NewConnection(context.Background(), failingOutbound{tag: "proxy"}, otherServer, adapter.InboundContext{Destination: destination}, nil)
}

// pipePacketConn is a net.Conn as a PacketConn for NewPacketConnection's argument; nothing is read from it here.
type pipePacketConn struct{ net.Conn }

func (c *pipePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *pipePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
