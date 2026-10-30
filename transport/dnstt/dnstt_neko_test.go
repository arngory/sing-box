package dnstt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
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
}

func startTestServer(t *testing.T, domain string) (*testServer, string) {
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
	response := &dns.Message{
		ID:       query.ID,
		Flags:    0x8400, // QR, AA, NOERROR
		Question: query.Question,
		Answer: []dns.RR{{
			Name:  query.Question[0].Name,
			Type:  dns.RRTypeTXT,
			Class: dns.ClassIN,
			TTL:   60,
			Data:  dns.EncodeRDataTXT(body.Bytes()),
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
	resolver, err := ParseResolver("udp://" + server.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{
		Context:  context.Background(),
		Logger:   logger.NOP(),
		Dialer:   udpDialer{},
		Domain:   "t.example.com",
		PubKey:   pubkey,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for round := 0; round < 2; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		conn, err := client.DialConn(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
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
		conn.Close()
	}
}

func TestNekoDNSTTParseResolver(t *testing.T) {
	for raw, want := range map[string]ResolverKind{
		"https://dns.example/dns-query": ResolverDoH,
		"tls://1.1.1.1":                 ResolverDoT,
		"udp://8.8.8.8:5353":            ResolverUDP,
		"8.8.8.8":                       ResolverUDP,
	} {
		resolver, err := ParseResolver(raw)
		if err != nil || resolver.Kind != want {
			t.Fatalf("%s: %v %v", raw, resolver.Kind, err)
		}
	}
	if resolver, _ := ParseResolver("tls://1.1.1.1"); resolver.Address.Port != 853 {
		t.Fatal("DoT default port")
	}
	if _, err := ParseResolver("ftp://x"); err == nil {
		t.Fatal("accepted ftp")
	}
}
