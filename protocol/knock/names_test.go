package knock

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"

	M "github.com/sagernet/sing/common/metadata"
)

func addrs(raw ...string) []netip.Addr {
	var out []netip.Addr
	for _, r := range raw {
		out = append(out, netip.MustParseAddr(r))
	}
	return out
}

// names-v1 §5: an answer is taken only for the node's addresses; a forged one, none, or a name that does not
// resolve leaves the node's own, the one that last answered on this network first
func TestNamesResolveNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	knock := []Step{{Port: 1}}
	o := newBox(t, Options{Sequence: knock, NodeAddresses: []string{"192.0.2.1", "[2001:db8::1]", "192.0.2.2"}})
	if got, ok := o.ResolveNode(ctx, "node.invalid"); !ok || !slices.Equal(got, addrs("192.0.2.1", "2001:db8::1", "192.0.2.2")) {
		t.Fatal("a name that does not resolve: ", got, ok)
	}
	if runtime.GOOS != "windows" {
		// localhost answers 127.0.0.1, none of the node's: forged
		if got, _ := o.ResolveNode(ctx, "localhost"); !slices.Equal(got, addrs("192.0.2.1", "2001:db8::1", "192.0.2.2")) {
			t.Fatal("a forged answer was taken: ", got)
		}
		node := newBox(t, Options{Sequence: knock, NodeAddresses: []string{"192.0.2.1", "127.0.0.1"}})
		if got, _ := node.ResolveNode(ctx, "localhost"); !slices.Equal(got, addrs("127.0.0.1")) {
			t.Fatal("the node's address in the answer was not taken alone: ", got)
		}
	}
	o.node.answered(netip.MustParseAddr("192.0.2.2"), o.generation.Load())
	if got, _ := o.ResolveNode(ctx, "node.invalid"); !slices.Equal(got, addrs("192.0.2.2", "192.0.2.1", "2001:db8::1")) {
		t.Fatal("the address that answered last is not first: ", got)
	}
	o.InterfaceUpdated(ctx)
	if got, _ := o.ResolveNode(ctx, "node.invalid"); !slices.Equal(got, addrs("192.0.2.1", "2001:db8::1", "192.0.2.2")) {
		t.Fatal("the last address of another network is still first: ", got)
	}
	// an address someone resolved the name to: the node's own if it is not one of them
	if targets, name := o.nodeTargets(ctx, M.ParseSocksaddrHostPort("192.0.2.2", 443)); name != "" || len(targets) != 1 || targets[0].Addr != netip.MustParseAddr("192.0.2.2") {
		t.Fatal("the node's address given: ", targets, name)
	}
	if targets, _ := o.nodeTargets(ctx, M.ParseSocksaddrHostPort("198.51.100.7", 443)); len(targets) != 3 || targets[0].Port != 443 || targets[0].Addr != netip.MustParseAddr("192.0.2.1") {
		t.Fatal("an address none of the node's: ", targets)
	}
	if _, ok := newBox(t, Options{Sequence: knock}).ResolveNode(ctx, "node.invalid"); ok {
		t.Fatal("a knock without node_addresses resolved for names-v1")
	}
	// through a detour the name is the detour's: not looked up here, where the local network would see it
	detoured := Options{Sequence: knock, NodeAddresses: []string{"192.0.2.1"}}
	detoured.Detour = "direct"
	if d, err := New(o.ctx, nil, o.logger, "knock2", detoured); err != nil || d.(*Outbound).node != nil {
		t.Fatal("node_addresses taken with a detour: ", err)
	}
	for _, bad := range []string{"node.example.com", "0.0.0.0", "fe80::1%eth0"} {
		if _, err := parseNodeAddresses([]string{bad}); err == nil {
			t.Fatal("taken as the node's address: ", bad)
		}
	}
}

// A dial goes to the next address when one does not answer in nodeDialTimeout, knocks at the one it dials, and
// starts from the one that answered next time
func TestNamesDialNextAddress(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	spaPort := uint16(spaConn.LocalAddr().(*net.UDPAddr).Port)
	packets := make(chan []byte, 8)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, err := spaConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets <- bytes.Clone(buffer[:n])
		}
	}()
	r := &recorder{}
	server := listenTCP(t, r, "server")
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: spaPort, PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Scope:     []uint16{1}, TTL: 600,
		Carriers: []string{"udp"},
	}
	// 192.0.2.1 (TEST-NET-1) answers nothing; the name does not resolve, so the node's addresses go in order
	o := newBox(t, Options{SPAv2: &options, NodeAddresses: []string{"192.0.2.1", "127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := o.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("node.invalid", server))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(start); elapsed > nodeDialTimeout+5*time.Second {
		t.Fatal("the next address took ", elapsed)
	}
	select {
	case <-packets:
	case <-time.After(2 * time.Second):
		t.Fatal("no SPA packet at the address that answered")
	}
	start = time.Now()
	conn, err = o.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("node.invalid", server))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatal("the address that answered was not tried first: ", elapsed)
	}
}

// The ClientHello carrier names the node (names-v1 §5 p. 6), never an address
func TestTLSCarrierServerName(t *testing.T) {
	packet := bytes.Repeat([]byte{0xab}, 128)
	for name, want := range map[string]string{"n3kq7p.example.com": "n3kq7p.example.com", "192.0.2.1": "", "": ""} {
		record, err := tlsCarrier(packet, name)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := fromTLSCarrier(record); !ok || !bytes.Equal(got, packet) {
			t.Fatal(name, ": the node does not find the packet")
		}
		client, server := net.Pipe()
		hello := make(chan *stdtls.ClientHelloInfo, 1)
		go func() {
			stdtls.Server(server, &stdtls.Config{GetConfigForClient: func(info *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
				hello <- info
				return nil, errors.New("enough")
			}}).Handshake()
			server.Close()
		}()
		go client.Write(record)
		select {
		case info := <-hello:
			if info.ServerName != want {
				t.Fatalf("%q: server name %q", name, info.ServerName)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("crypto/tls did not read a ClientHello")
		}
		client.Close()
	}
}
