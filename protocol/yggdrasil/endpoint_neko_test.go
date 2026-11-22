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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
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

// A dialled address answers while this node still talks to it, and no longer once it has been quiet for dialedFor;
// the list holds at most dialedMax.
func TestNekoYggdrasilDialedBounded(t *testing.T) {
	server := netip.MustParseAddr("202:4444::4")
	e := &Endpoint{inboundListed: true}
	e.noteDialed(server)
	if !e.answering(server) {
		t.Fatal("a dialled address not answered")
	}
	e.dialed[server] = time.Now().Add(-dialedFor - time.Second)
	out := make([]byte, 60)
	out[0] = 0x60
	copy(out[24:40], server.AsSlice())
	e.sending(out)
	if !e.answering(server) {
		t.Fatal("a packet out did not renew it")
	}
	e.dialed[server] = time.Now().Add(-dialedFor - time.Second)
	if e.answering(server) {
		t.Fatal("quiet past dialedFor and still answered")
	}
	for i := 0; i < dialedMax+100; i++ {
		e.noteDialed(netip.AddrFrom16([16]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)}))
	}
	if len(e.dialed) > dialedMax {
		t.Fatalf("%d dialled addresses held", len(e.dialed))
	}
	// full, the newest dial is still answered (the longest quiet one went)
	newest := netip.MustParseAddr("203:ffff::1")
	e.noteDialed(newest)
	if !e.answering(newest) || len(e.dialed) > dialedMax {
		t.Fatal("a dial into a full list not answered")
	}
}

// A packet read from the mesh as the endpoint closes is dropped, not written to the closing device: gVisor's stack
// has no dispatcher then and panics (neko)
func TestNekoYggdrasilDeliverAfterClose(t *testing.T) {
	device := &countingDevice{}
	e := &Endpoint{device: device, closed: make(chan struct{}), logger: log.NewNOPFactory().Logger()}
	if !e.deliver([][]byte{{0x60}}) || device.writes != 1 {
		t.Fatal("an open endpoint did not deliver")
	}
	close(e.closed)
	if e.deliver([][]byte{{0x60}}) || device.writes != 1 {
		t.Fatal("a closing endpoint wrote to its device")
	}
}

type countingDevice struct {
	wireguard.Device
	writes int
}

func (d *countingDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.writes++
	return len(bufs), nil
}

// Close waits for a delivery in flight while the stack's answers to it keep leaving through pumpOut (dropped, the
// mesh is gone), so answers that fill the stack's queue cannot hold Close forever (neko)
func TestNekoYggdrasilCloseWhileDelivering(t *testing.T) {
	privateKey, err := parsePrivateKey(strings.Repeat("ef", 32))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := selfSignedCertificate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	node, err := core.New(certificate, &coreLogger{log.NewNOPFactory().Logger()})
	if err != nil {
		t.Fatal(err)
	}
	device := &answeringDevice{
		entered:  make(chan struct{}),
		proceed:  make(chan struct{}),
		outbound: make(chan []byte),
		done:     make(chan struct{}),
	}
	e := &Endpoint{
		core:   node,
		rwc:    ipv6rwc.NewReadWriteCloser(node),
		device: device,
		closed: make(chan struct{}),
		logger: log.NewNOPFactory().Logger(),
	}
	go e.pumpOut()
	delivered := make(chan bool, 1)
	go func() { delivered <- e.deliver([][]byte{{0x60}}) }()
	<-device.entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	// the endpoint is closing before the stack answers the packet it is taking
	<-e.closed
	close(device.proceed)
	select {
	case <-closeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Close held by a delivery whose answers nobody reads")
	}
	if !<-delivered {
		t.Fatal("the delivery begun before the close was refused")
	}
}

// answeringDevice is a stack that answers a packet as it takes it, through the queue pumpOut reads; the answers
// are not IPv6, so the mesh refuses each.
type answeringDevice struct {
	wireguard.Device
	entered, proceed, done chan struct{}
	outbound               chan []byte
	closeOnce              sync.Once
}

func (d *answeringDevice) Write(bufs [][]byte, offset int) (int, error) {
	close(d.entered)
	<-d.proceed
	for i := 0; i < 3; i++ {
		select {
		case d.outbound <- []byte{0x45}:
		case <-d.done:
			return 0, os.ErrClosed
		}
	}
	return len(bufs), nil
}

func (d *answeringDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-d.outbound:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}

func (d *answeringDevice) Close() error {
	d.closeOnce.Do(func() { close(d.done) })
	return nil
}

// pq: off (or none) leaves the core's sessions classic, answer and on give ironwood's PQ sessions their mode.
func TestNekoYggdrasilPQSetup(t *testing.T) {
	for _, off := range []string{"", "off"} {
		if pq, err := pqSetup(off); err != nil || pq != nil {
			t.Fatalf("%q: %v %v", off, pq, err)
		}
	}
	if pq, err := pqSetup("answer"); err != nil || pq == nil || !pq.AnswerOnly {
		t.Fatalf("answer: %+v %v", pq, err)
	}
	if pq, err := pqSetup("on"); err != nil || pq == nil || pq.AnswerOnly {
		t.Fatalf("on: %+v %v", pq, err)
	}
	if _, err := pqSetup("yes"); err == nil {
		t.Fatal("yes taken")
	}
}
