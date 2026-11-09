//go:build with_yggdrasil

package yggdrasil

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// A seed and the 64-byte key yggdrasil-go stores give the same node; the certificate
// carries that key, so the node's address follows from it.
func TestNekoYggdrasilKey(t *testing.T) {
	seed := strings.Repeat("ab", 32)
	fromSeed, err := parsePrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	fromFull, err := parsePrivateKey(hex.EncodeToString(fromSeed))
	if err != nil {
		t.Fatal(err)
	}
	if !fromSeed.Equal(fromFull) {
		t.Fatal("seed and full key differ")
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("ab", 16)} {
		if _, err = parsePrivateKey(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	certificate, err := selfSignedCertificate(fromSeed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	publicKey := parsed.PublicKey.(ed25519.PublicKey)
	if !publicKey.Equal(fromSeed.Public()) {
		t.Fatal("certificate key differs")
	}
	nodeAddress := address.AddrForKey(publicKey)
	ip, _ := netip.AddrFromSlice(nodeAddress[:])
	if !yggdrasilPrefix.Contains(ip) {
		t.Fatalf("address %s outside 200::/7", ip)
	}
}

func TestNekoYggdrasilPeers(t *testing.T) {
	for _, good := range []string{"tls://1.2.3.4:443", "tcp://peer.example:1234", "quic://[2001:db8::1]:443",
		"tls://peer.example:443?key=" + strings.Repeat("ab", 32),
		// a link through niko-server's tcpmux names its route by SNI
		"tls://203.0.113.7:443?sni=y.example.com"} {
		if _, err := parsePeer(good); err != nil {
			t.Fatalf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{"http://peer.example:80", "tls://", "tls://peer.example:443?key=abc", "peer.example:443"} {
		if _, err := parsePeer(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// A tls:// peer with ?sni= sends that name in its ClientHello, also when the
// peer address is an IP: niko-server routes Yggdrasil links by it.
func TestNekoYggdrasilPeerSNI(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverName := make(chan string, 1)
	hello := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tls.Server(conn, &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName <- info.ServerName
			hello <- info
			return nil, errors.New("captured")
		}}).Handshake()
	}()
	privateKey, err := parsePrivateKey(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := selfSignedCertificate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	node, err := core.New(certificate, &coreLogger{log.NewNOPFactory().Logger()}, core.LinkDialer{
		DialContext: (&net.Dialer{}).DialContext,
		TLSClient:   chromeTLSClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Stop()
	peer, err := parsePeer("tls://" + listener.Addr().String() + "?sni=y.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err = node.AddPeer(peer, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-serverName:
		if name != "y.example.com" {
			t.Fatalf("SNI %q, want y.example.com", name)
		}
		// a browser ClientHello: GREASE cipher suites and the hybrid group, not crypto/tls
		info := <-hello
		grease, hybrid := false, false
		for _, suite := range info.CipherSuites {
			grease = grease || suite&0x0f0f == 0x0a0a
		}
		for _, curve := range info.SupportedCurves {
			hybrid = hybrid || curve == tls.X25519MLKEM768
		}
		if !grease || !hybrid {
			t.Fatalf("not a Chrome ClientHello: grease %v, X25519MLKEM768 %v", grease, hybrid)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no ClientHello")
	}
}

// Two nodes peer over a tls:// link with the Chrome ClientHello (ed25519 node certificates).
func TestNekoYggdrasilChromeLink(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	newNode := func(seed string, setup ...core.SetupOption) *core.Core {
		privateKey, err := parsePrivateKey(strings.Repeat(seed, 32))
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := selfSignedCertificate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		node, err := core.New(certificate, &coreLogger{log.NewNOPFactory().Logger()}, setup...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(node.Stop)
		return node
	}
	newNode("a1", core.ListenAddress("tls://"+address))
	client := newNode("b2", core.LinkDialer{DialContext: (&net.Dialer{}).DialContext, TLSClient: chromeTLSClient})
	peer, err := parsePeer("tls://" + address)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.AddPeer(peer, ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, info := range client.GetPeers() {
			if info.Up {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no link up: %+v", client.GetPeers())
}

// inbound_listed: off takes every flow to this node's address for the route rules; on, a flow from an address
// inbound_sources does not list is dropped before its handshake (no reset), and with no sources every one. A flow
// from a listed address to any other address is refused as before.
func TestNekoYggdrasilInboundSources(t *testing.T) {
	self := netip.MustParseAddr("200:1111::1")
	neighbour := netip.MustParseAddr("201:2222::2")
	stranger := netip.MustParseAddr("202:3333::3")
	verdict := func(options string, source, destination netip.Addr) tun.FlowAction {
		t.Helper()
		var parsed option.YggdrasilEndpointOptions
		if err := json.Unmarshal([]byte(options), &parsed); err != nil {
			t.Fatal(err)
		}
		e := &Endpoint{address: self, inboundListed: parsed.InboundListed, inboundSources: parsed.InboundSources}
		return e.JudgeFlow(6, netip.AddrPortFrom(source, 40000), netip.AddrPortFrom(destination, 22), nil).Action
	}
	for _, c := range []struct {
		options             string
		source, destination netip.Addr
		want                tun.FlowAction
	}{
		{`{}`, stranger, self, tun.ActionAccept},
		{`{}`, neighbour, stranger, tun.ActionReject},
		{`{"inbound_listed": true}`, neighbour, self, tun.ActionDrop},
		{`{"inbound_listed": true, "inbound_sources": ["201:2222::2/128"]}`, neighbour, self, tun.ActionAccept},
		{`{"inbound_listed": true, "inbound_sources": ["201:2222::2/128"]}`, stranger, self, tun.ActionDrop},
		{`{"inbound_listed": true, "inbound_sources": "201:2222::2/128"}`, neighbour, self, tun.ActionAccept},
		{`{"inbound_listed": true, "inbound_sources": ["201:2222::2/128"]}`, neighbour, stranger, tun.ActionReject},
		// an unlisted sender gets nothing, also at another address of this node (its /64): no reject to tell it apart
		{`{"inbound_listed": true, "inbound_sources": ["201:2222::2/128"]}`, stranger, stranger, tun.ActionDrop},
		{`{"inbound_listed": true, "inbound_sources": []}`, stranger, stranger, tun.ActionDrop},
		// sources without the flag: taken as before, the route rules decide
		{`{"inbound_sources": ["201:2222::2/128"]}`, stranger, self, tun.ActionAccept},
	} {
		if got := verdict(c.options, c.source, c.destination); got != c.want {
			t.Errorf("%s, %s → %s: %v, want %v", c.options, c.source, c.destination, got, c.want)
		}
	}
	var parsed option.YggdrasilEndpointOptions
	if err := json.Unmarshal([]byte(`{"inbound_sources": ["201:2222::2"]}`), &parsed); err == nil {
		t.Fatal("an address without its prefix length taken")
	}
}

// With inbound_sources, the mesh's packets reach the stack only from a listed address or one this node dialled: an
// unlisted sender's ACK or echo request gets no reset or reply from the stack, a dialled one's answers come in.
func TestNekoYggdrasilAdmits(t *testing.T) {
	neighbour := netip.MustParseAddr("201:2222::2")
	server := netip.MustParseAddr("202:4444::4")
	stranger := netip.MustParseAddr("202:3333::3")
	packet := func(source netip.Addr) []byte {
		p := make([]byte, 60)
		p[0] = 0x60
		p[6] = 6
		copy(p[8:24], source.AsSlice())
		return p
	}
	open := &Endpoint{}
	if !open.admits(packet(stranger)) || !open.admits([]byte{0x45}) {
		t.Fatal("without inbound_sources every packet goes to the stack")
	}
	e := &Endpoint{inboundListed: true, inboundSources: []netip.Prefix{netip.PrefixFrom(neighbour, 128)}}
	if !e.admits(packet(neighbour)) {
		t.Fatal("a listed neighbour's packet dropped")
	}
	if e.admits(packet(server)) || e.admits(packet(stranger)) || e.admits(packet(neighbour)[:20]) {
		t.Fatal("an unlisted sender's packet (or a broken one) admitted")
	}
	e.noteDialed(server)
	if !e.admits(packet(server)) || e.admits(packet(stranger)) {
		t.Fatal("the answers of what this node dialled, and only those")
	}
	// a dialled address does not open flows itself
	if e.JudgeFlow(6, netip.AddrPortFrom(server, 443), netip.AddrPortFrom(netip.MustParseAddr("200:1111::1"), 22), nil).Action != tun.ActionDrop {
		t.Fatal("a dialled address opened a flow")
	}
}
