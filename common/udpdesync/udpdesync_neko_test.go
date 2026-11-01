package udpdesync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/bufio"
)

// The fake Initial is a real QUIC Initial to a DPI box: the sniffer decrypts it and reads the SNI.
func TestNekoFakeInitialSNI(t *testing.T) {
	packet := FakeInitial("allowed.example.ru")
	if len(packet) != initialSize {
		t.Fatalf("size %d, want %d", len(packet), initialSize)
	}
	if !isInitial(packet) {
		t.Fatal("not an Initial")
	}
	var metadata adapter.InboundContext
	if err := sniff.QUICClientHello(context.Background(), &metadata, packet); err != nil {
		t.Fatal(err)
	}
	if metadata.Domain != "allowed.example.ru" {
		t.Fatalf("sniffed %q", metadata.Domain)
	}
}

// recorder is a UDP server that records datagrams in order.
type recorder struct {
	conn    *net.UDPConn
	access  sync.Mutex
	packets [][]byte
}

func newRecorder(t *testing.T) *recorder {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{conn: conn}
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}
			r.access.Lock()
			r.packets = append(r.packets, append([]byte(nil), buffer[:n]...))
			r.access.Unlock()
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return r
}

func (r *recorder) snapshot() [][]byte {
	time.Sleep(100 * time.Millisecond)
	r.access.Lock()
	defer r.access.Unlock()
	return r.packets
}

func dial(t *testing.T, r *recorder, options Options) *Conn {
	conn, err := net.DialUDP("udp", nil, r.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	c := NewConn(conn, options, nil)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNekoPreludeAndReorder(t *testing.T) {
	r := newRecorder(t)
	c := dial(t, r, Options{Prelude: 2, ReorderInitial: true})
	first, second := FakeInitial("one.example"), FakeInitial("two.example")
	c.Write(first)
	c.Write(second)
	c.Write([]byte{0x40, 1, 2, 3})
	packets := r.snapshot()
	if len(packets) != 5 {
		t.Fatalf("%d datagrams, want 5", len(packets))
	}
	for i := 0; i < 2; i++ {
		if isInitial(packets[i]) || packets[i][0]&0xc0 == 0xc0 {
			t.Fatalf("prelude %d looks like a QUIC long header", i)
		}
	}
	if string(packets[2]) != string(second) || string(packets[3]) != string(first) {
		t.Fatal("Initials not reordered")
	}
	if packets[4][0] != 0x40 {
		t.Fatal("short header packet out of place")
	}
}

func TestNekoReorderLoneInitial(t *testing.T) {
	r := newRecorder(t)
	c := dial(t, r, Options{ReorderInitial: true})
	c.Write(FakeInitial("only.example"))
	if packets := r.snapshot(); len(packets) != 1 {
		t.Fatalf("lone Initial not flushed: %d datagrams", len(packets))
	}
}

func TestNekoPreludeQUICWithTTL(t *testing.T) {
	r := newRecorder(t)
	c := dial(t, r, Options{Prelude: 1, PreludeSNI: "allowed.example.ru", PreludeTTL: 64})
	c.Write([]byte{0x40, 9})
	packets := r.snapshot()
	if len(packets) != 2 || !isInitial(packets[0]) {
		t.Fatalf("want a fake Initial then the packet, got %d", len(packets))
	}
	// the TTL is restored after the prelude
	restore, err := setTTL(c.Conn, 64)
	if err != nil {
		t.Fatal(err)
	}
	restore()
}

// A QUIC handshake with a post-quantum ClientHello (two Initials, sent in reverse) and a prelude completes.
func TestNekoQUICHandshakeThroughDesync(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"node.example"}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"test"},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept(context.Background())
		if err == nil {
			<-conn.Context().Done()
		}
	}()

	udpConn, err := net.DialUDP("udp", nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	desync := NewConn(udpConn, Options{Prelude: 3, PreludeSNI: "allowed.example.ru", ReorderInitial: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, bufio.NewUnbindPacketConn(desync), listener.Addr(), &tls.Config{
		ServerName: "node.example", InsecureSkipVerify: true, NextProtos: []string{"test"},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	conn.CloseWithError(0, "")
	if !desync.reordered.Load() {
		t.Fatal("the post-quantum ClientHello did not take two Initials, nothing was reordered")
	}
}

func TestNekoSocketTuned(t *testing.T) {
	r := newRecorder(t)
	c := dial(t, r, Options{Prelude: 1})
	raw, err := c.Conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	raw.Control(func(fd uintptr) { checkTuned(t, fd) })
}
