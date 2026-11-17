package stun

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// plainDialer is what the direct outbound gives for an address: the socket itself, no wrapper.
type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (plainDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

// bindingServer answers a binding with the address it saw (XOR-MAPPED-ADDRESS), and nothing more: no OTHER-ADDRESS.
func bindingServer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < headerSize || binary.BigEndian.Uint16(buf[0:2]) != bindingRequest {
				continue
			}
			value := make([]byte, 8)
			value[1] = 0x01
			binary.BigEndian.PutUint16(value[2:4], uint16(from.Port)^uint16(magicCookie>>16))
			binary.BigEndian.PutUint32(value[4:8], binary.BigEndian.Uint32(from.IP.To4())^magicCookie)
			answer := make([]byte, headerSize, headerSize+4+len(value))
			binary.BigEndian.PutUint16(answer[0:2], bindingSuccessResponse)
			binary.BigEndian.PutUint16(answer[2:4], uint16(4+len(value)))
			copy(answer[4:20], buf[4:20])
			answer = binary.BigEndian.AppendUint16(answer, attrXORMappedAddress)
			answer = binary.BigEndian.AppendUint16(answer, uint16(len(value)))
			answer = append(answer, value...)
			_, _ = conn.WriteToUDP(answer, from)
		}
	}()
	return conn
}

// A server given by its address, through a dialer that hands back the plain socket: the binding goes out (it failed
// with "invalid argument" when the address went as M.Socksaddr).
func TestRunAddressThroughPlainSocket(t *testing.T) {
	server := bindingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Run(Options{Server: server.LocalAddr().String(), Dialer: plainDialer{}, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.ExternalAddr, "127.0.0.1:") {
		t.Fatalf("external address %q", result.ExternalAddr)
	}
	if result.NATTypeSupported {
		t.Fatal("a server without OTHER-ADDRESS tells the NAT's behaviour")
	}
}
