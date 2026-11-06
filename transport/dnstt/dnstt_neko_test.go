package dnstt

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/chacha20"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// testServer is a minimal dnstt server on the library packages: it answers TXT queries
// for its domain directly (acting as the resolver too) and echoes every stream.
type testServer struct {
	domain  dns.Name
	conn    net.PacketConn
	tunnel  *turbotunnel.QueuePacketConn
	privkey []byte
	// dnsseal-v1 as the node does it (Ku, Kd and their tag keys from K), nil: open dnstt
	sealUp, sealDown, sealUpTag, sealDownTag []byte
	// the next sessions whose handshake is never answered: KCP acknowledges their segments, Noise stays silent, as
	// a node that forgot the ClientID after the first segment
	silent atomic.Int32
}

func startTestServer(t *testing.T, domain string) (*testServer, string) {
	return startTestServerSealed(t, domain, nil)
}

// startTestServerSealed is the test server taking and giving sealed dnstt (dnsseal-v1) with K = sealKey, written from
// the spec apart from the client's code.
func startTestServerSealed(t *testing.T, domain string, sealKey []byte) (*testServer, string) {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	name, err := dns.ParseName(domain)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testServer{
		domain:  name,
		conn:    conn,
		tunnel:  turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
		privkey: privkey,
	}
	if sealKey != nil {
		server.sealUp, server.sealDown = testSealKey(sealKey, "dnsseal-v1 up"), testSealKey(sealKey, "dnsseal-v1 down")
		server.sealUpTag, server.sealDownTag = testSealKey(sealKey, "dnsseal-v1 up tag"), testSealKey(sealKey, "dnsseal-v1 down tag")
	}
	listener, err := kcp.ServeConn(nil, 0, 0, server.tunnel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		listener.Close()
		conn.Close()
		server.tunnel.Close()
	})
	go server.serveDNS()
	go server.acceptSessions(listener, dnsNameCapacity(name)-8-1-numPadding-1)
	return server, noise.EncodeKey(noise.PubkeyFromPrivkey(privkey))
}

func (s *testServer) serveDNS() {
	var buf [4096]byte
	for {
		n, addr, err := s.conn.ReadFrom(buf[:])
		if err != nil {
			return
		}
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil || len(query.Question) != 1 {
			continue
		}
		prefix, ok := query.Question[0].Name.TrimSuffix(s.domain)
		if !ok {
			continue
		}
		encoded := bytes.ToUpper(bytes.Join(prefix, nil))
		payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
		n, err = base32Encoding.Decode(payload, encoded)
		if err != nil || n < 8+1 {
			continue
		}
		payload = payload[:n]
		if s.sealUp != nil {
			// N || T || C, C = ChaCha20(Ku, N || 0^4)(ClientID || frames), T = HMAC(Kut, N || C)[:4]
			if len(payload) < 12+8 {
				continue
			}
			n, tag, ciphertext := payload[:8], payload[8:12], payload[12:]
			if !hmac.Equal(tag, testSealKey(s.sealUpTag, string(n)+string(ciphertext))[:4]) {
				continue
			}
			payload = testChaCha(s.sealUp, n, ciphertext)
		}
		var clientID turbotunnel.ClientID
		copy(clientID[:], payload[:8])
		r := bytes.NewReader(payload[8:])
		// padding, then length-prefixed packets
		for {
			prefixByte, err := r.ReadByte()
			if err != nil {
				break
			}
			if prefixByte >= 224 {
				io.CopyN(io.Discard, r, int64(prefixByte-224))
				continue
			}
			packet := make([]byte, prefixByte)
			if _, err = io.ReadFull(r, packet); err != nil {
				break
			}
			s.tunnel.QueueIncoming(packet, clientID)
		}
		go s.respond(query, clientID, addr)
	}
}

// respond answers with whatever the client has queued, waiting briefly for some.
func (s *testServer) respond(query dns.Message, clientID turbotunnel.ClientID, addr net.Addr) {
	var body bytes.Buffer
	outgoing := s.tunnel.OutgoingQueue(clientID)
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	for body.Len() < 900 {
		select {
		case p := <-outgoing:
			binary.Write(&body, binary.BigEndian, uint16(len(p)))
			body.Write(p)
			continue
		case <-timer.C:
		}
		break
	}
	data := body.Bytes()
	if s.sealDown != nil {
		// R || T || C, C = ChaCha20(Kd, R || 0^4)(packets || 00 00 || zeros to a multiple of 64 with R and T)
		frames := append(data, 0, 0)
		frames = append(frames, make([]byte, (64-(12+len(frames))%64)%64)...)
		r := make([]byte, 8)
		rand.Read(r)
		ciphertext := testChaCha(s.sealDown, r, frames)
		data = append(append(r, testSealKey(s.sealDownTag, string(r)+string(ciphertext))[:4]...), ciphertext...)
	}
	response := &dns.Message{
		ID:       query.ID,
		Flags:    0x8400, // QR, AA, NOERROR
		Question: query.Question,
		Answer: []dns.RR{{
			Name:  query.Question[0].Name,
			Type:  dns.RRTypeTXT,
			Class: dns.ClassIN,
			TTL:   60,
			Data:  dns.EncodeRDataTXT(data),
		}},
	}
	wire, err := response.WireFormat()
	if err == nil {
		s.conn.WriteTo(wire, addr)
	}
}

func (s *testServer) acceptSessions(listener *kcp.Listener, mtu int) {
	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			return
		}
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		conn.SetMtu(mtu)
		if s.silent.Add(-1) >= 0 {
			go io.Copy(io.Discard, conn)
			continue
		}
		go func() {
			defer conn.Close()
			noiseConn, err := noise.NewServer(conn, s.privkey)
			if err != nil {
				return
			}
			config := smux.DefaultConfig()
			config.Version = 2
			session, err := smux.Server(noiseConn, config)
			if err != nil {
				return
			}
			for {
				stream, err := session.AcceptStream()
				if err != nil {
					return
				}
				go func() {
					defer stream.Close()
					io.Copy(stream, stream)
				}()
			}
		}()
	}
}

type udpDialer struct{}

func (udpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return net.Dial(network, destination.String())
}

func (udpDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

var _ N.Dialer = udpDialer{}

// Streams through the client reach the server's upstream and back, over plain UDP DNS.
func TestNekoDNSTTEcho(t *testing.T) {
	server, pubkey := startTestServer(t, "t.example.com")
	echoThrough(t, "udp://"+server.conn.LocalAddr().String(), pubkey, nil)
}

// The same sealed (dnsseal-v1): the client seals its queries and opens the answers of a server that does it as the
// spec says.
func TestNekoDNSTTEchoSealed(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	server, pubkey := startTestServerSealed(t, "t.example.com", key)
	echoThrough(t, "udp://"+server.conn.LocalAddr().String(), pubkey, key)
}

// The same over DNS over TCP (RFC 7766): a resolver that takes length-prefixed messages on TCP and asks the server
// over UDP, as a public resolver reached on TCP 53 does.
func TestNekoDNSTTEchoTCP(t *testing.T) {
	server, pubkey := startTestServer(t, "t.example.com")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go tcpToUDP(conn, server.conn.LocalAddr())
		}
	}()
	echoThrough(t, "tcp://"+listener.Addr().String(), pubkey, nil)
}

// tcpToUDP relays one TCP DNS connection to a UDP DNS server and its answers back, framed by their length.
func tcpToUDP(conn net.Conn, server net.Addr) {
	defer conn.Close()
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(n)), buf[:n]...)); err != nil {
				return
			}
		}
	}()
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		message := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, message); err != nil {
			return
		}
		upstream.WriteTo(message, server)
	}
}

func newTestClient(t *testing.T, resolverURL, pubkey string, sealKey []byte, handshakeTimeout time.Duration) *Client {
	resolver, err := ParseResolver(resolverURL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{
		Context:          context.Background(),
		Logger:           logger.NOP(),
		Dialer:           udpDialer{},
		Domain:           "t.example.com",
		PubKey:           pubkey,
		Resolver:         resolver,
		SealKey:          sealKey,
		HandshakeTimeout: handshakeTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func echoThrough(t *testing.T, resolverURL, pubkey string, sealKey []byte) {
	client := newTestClient(t, resolverURL, pubkey, sealKey, 0)
	defer client.Close()
	for round := 0; round < 2; round++ {
		echoOnce(t, client, round)
	}
}

func echoOnce(t *testing.T, client *Client, round int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	conn, err := client.DialConn(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	message := make([]byte, 20000)
	rand.Read(message)
	go conn.Write(message)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	echo := make([]byte, len(message))
	if _, err = io.ReadFull(conn, echo); err != nil {
		t.Fatalf("round %d: %v", round, err)
	}
	if !bytes.Equal(echo, message) {
		t.Fatalf("round %d: echo differs", round)
	}
}

// A session whose handshake is never answered (the node acknowledged its first segment and forgot the ClientID):
// the client gives it up after its handshake timeout, and the next dial sets up a new session, a new ClientID, that
// works. Before, the dial waited forever and held every other dial and Close with it.
func TestNekoDNSTTHandshakeRetry(t *testing.T) {
	server, pubkey := startTestServer(t, "t.example.com")
	server.silent.Store(1)
	client := newTestClient(t, "udp://"+server.conn.LocalAddr().String(), pubkey, nil, time.Second)
	defer client.Close()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, err := client.DialConn(ctx)
	cancel()
	if err == nil {
		t.Fatal("a stream through a session whose handshake was never answered")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("gave up after %v", elapsed)
	}
	echoOnce(t, client, 1)
}

// Close while a handshake hangs returns at once, and the dial waiting for it ends too.
func TestNekoDNSTTCloseDuringHandshake(t *testing.T) {
	server, pubkey := startTestServer(t, "t.example.com")
	server.silent.Store(100)
	client := newTestClient(t, "udp://"+server.conn.LocalAddr().String(), pubkey, nil, time.Minute)
	dialed := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := client.DialConn(context.Background())
			dialed <- err
		}()
	}
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	client.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v", elapsed)
	}
	for range 2 {
		select {
		case err := <-dialed:
			if err == nil {
				t.Fatal("a dial went through")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a dial still waits after Close")
		}
	}
	if _, err := client.DialConn(context.Background()); err == nil {
		t.Fatal("a dial after Close")
	}
}

func TestNekoDNSTTParseResolver(t *testing.T) {
	for raw, want := range map[string]ResolverKind{
		"https://dns.example/dns-query": ResolverDoH,
		"tls://1.1.1.1":                 ResolverDoT,
		"udp://8.8.8.8:5353":            ResolverUDP,
		"8.8.8.8":                       ResolverUDP,
		"tcp://9.9.9.9":                 ResolverTCP,
	} {
		resolver, err := ParseResolver(raw)
		if err != nil || resolver.Kind != want {
			t.Fatalf("%s: %v %v", raw, resolver.Kind, err)
		}
	}
	if resolver, _ := ParseResolver("tls://1.1.1.1"); resolver.Address.Port != 853 {
		t.Fatal("DoT default port")
	}
	if resolver, _ := ParseResolver("tcp://[2001:db8::53]"); resolver.Address.Port != 53 || resolver.Address.AddrString() != "2001:db8::53" {
		t.Fatal("TCP default port")
	}
	if _, err := ParseResolver("ftp://x"); err == nil {
		t.Fatal("accepted ftp")
	}
}

func testSealKey(key []byte, label string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

func testChaCha(key, prefix, data []byte) []byte {
	stream, err := chacha20.NewUnauthenticatedCipher(key, append(append([]byte{}, prefix...), 0, 0, 0, 0))
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return out
}

// dnsseal-v1 vectors with the tag (encrypt-then-MAC), computed in Python (hmac, ChaCha20 of cryptography) apart from
// this code: K = 00..1f; the query N = a0..a7, inner = ClientID c0..c7 || a packet 01 ff; the answer R = b0..b7, a
// packet aa bb, then 00 00 and zeros to 64 bytes of TXT data.
func TestNekoSealVectors(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	seal, err := newSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	inner := []byte{0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0x01, 0xff}
	query := seal.sealQueryWith([8]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}, inner)
	if got := hex.EncodeToString(query); got != "a0a1a2a3a4a5a6a70c56c1a39145fd1ffc3688be16c2" {
		t.Fatalf("query %s", got)
	}
	answer, _ := hex.DecodeString("b0b1b2b3b4b5b6b7d119c872f77002e5cc82e741ca69b3f568b5facff046fa764c1646d7395735e3f34ca5e0f2082aeae570f04304a4571256c325042f0d9dd5")
	// a byte changed anywhere, its tag no longer holds: the answer is dropped
	for i := range answer {
		tampered := append([]byte{}, answer...)
		tampered[i] ^= 1
		if _, ok := seal.openResponse(tampered); ok {
			t.Fatalf("byte %d changed, the answer still opened", i)
		}
	}
	frames, ok := seal.openResponse(answer)
	if !ok {
		t.Fatal("the answer did not open")
	}
	r := bytes.NewReader(frames)
	if p, err := nextPacket(r); err != nil || !bytes.Equal(p, []byte{0xaa, 0xbb}) {
		t.Fatalf("first packet %x %v", p, err)
	}
	if p, err := nextPacket(r); err != nil || len(p) != 0 {
		t.Fatalf("the end of the packets: %x %v", p, err)
	}
}

// A sealed query at its largest fits its name whatever the labels' lengths (32-63, drawn at random).
func TestNekoSealedNameFits(t *testing.T) {
	domain, _ := dns.ParseName("a-rather-long-tunnel-zone.subdomain.example.com")
	seal, _ := newSealer(make([]byte, 32))
	inner := make([]byte, dnsNameCapacitySealed(domain)-sealOverhead)
	for i := 0; i < 500; i++ {
		encoded := make([]byte, base32Encoding.EncodedLen(len(inner)+sealOverhead))
		base32Encoding.Encode(encoded, seal.sealQuery(inner))
		labels := sealLabels(bytes.ToLower(encoded))
		for j, label := range labels {
			if len(label) > sealLabelMax || (j < len(labels)-1 && len(label) < sealLabelMin) {
				t.Fatalf("label of %d", len(label))
			}
		}
		if _, err := dns.NewName(append(labels, domain...)); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	// the padding frame never takes more than the room left, nor more than 31 bytes
	for room := 0; room < 40; room++ {
		frame := sealPadding(room)
		if len(frame) > room || (len(frame) > 0 && (int(frame[0])-224 != len(frame)-1 || len(frame)-1 > sealMaxPadding)) {
			t.Fatalf("room %d: frame of %d", room, len(frame))
		}
	}
}
