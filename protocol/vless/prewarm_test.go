package vless

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// fakeConn is one end of a pipe: its peer is the server, which closes or writes to it
type fakeConn struct {
	net.Conn
	peer   net.Conn
	closed atomic.Bool
}

func (c *fakeConn) Close() error {
	c.closed.Store(true)
	c.peer.Close()
	return c.Conn.Close()
}

type fakeDialer struct {
	access sync.Mutex
	conns  []*fakeConn
	fail   bool
	gate   chan struct{}
}

func (d *fakeDialer) dial(ctx context.Context) (net.Conn, error) {
	if d.gate != nil {
		<-d.gate
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.fail {
		return nil, errors.New("refused")
	}
	client, server := net.Pipe()
	conn := &fakeConn{Conn: client, peer: server}
	d.conns = append(d.conns, conn)
	return conn, nil
}

func (d *fakeDialer) count() int {
	d.access.Lock()
	defer d.access.Unlock()
	return len(d.conns)
}

func newTestPrewarm(d *fakeDialer, idle time.Duration) *prewarm {
	return newPrewarm(context.Background(), log.NewNOPFactory().Logger(), idle, d.dial)
}

// waitSpare waits for warm's goroutine to settle: a spare, or no dial in flight
func waitSettled(t *testing.T, p *prewarm) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.access.Lock()
		warming := p.warming
		p.access.Unlock()
		if !warming {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the spare's dial did not settle")
}

// One spare after a request, handed to the next; one dial however often warm is called
func TestPrewarmOneSpare(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	defer p.Close()
	if p.take() != nil {
		t.Fatal("a spare before any warm")
	}
	for i := 0; i < 5; i++ {
		p.warm()
	}
	waitSettled(t, p)
	p.warm()
	waitSettled(t, p)
	if d.count() != 1 {
		t.Fatal("dials: ", d.count())
	}
	conn := p.take()
	if conn == nil || conn != d.conns[0] {
		t.Fatal("the spare was not handed out")
	}
	if p.take() != nil {
		t.Fatal("the spare handed out twice")
	}
	if d.conns[0].closed.Load() {
		t.Fatal("the spare handed out was closed")
	}
}

// Unused, the spare is closed after idle and not opened again until the next request
func TestPrewarmIdle(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, 50*time.Millisecond)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	time.Sleep(200 * time.Millisecond)
	if !d.conns[0].closed.Load() {
		t.Fatal("the idle spare was kept")
	}
	if p.take() != nil || d.count() != 1 {
		t.Fatal("a spare after idle: dials ", d.count())
	}
}

// A spare taken just before its expiry is not closed under the request that took it
func TestPrewarmTakenBeforeExpiry(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, 30*time.Millisecond)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	conn := p.take().(*fakeConn)
	time.Sleep(100 * time.Millisecond)
	if conn.closed.Load() {
		t.Fatal("the expiry closed a spare in use")
	}
}

// A network change drops the spare and the one being dialled on the old network
func TestPrewarmReset(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	p.reset()
	if !d.conns[0].closed.Load() || p.take() != nil {
		t.Fatal("the spare outlived the reset")
	}
	d.gate = make(chan struct{})
	p.warm()
	p.reset()
	close(d.gate)
	waitSettled(t, p)
	if p.take() != nil || !d.conns[1].closed.Load() {
		t.Fatal("a spare of the old network was kept")
	}
}

// Off while the outbound is not in use; closed for good with the outbound; a failed dial leaves nothing
func TestPrewarmOffClosedFailed(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	p.warm()
	waitSettled(t, p)
	p.setOn(false)
	if !d.conns[0].closed.Load() {
		t.Fatal("the spare outlived setOn(false)")
	}
	p.warm()
	waitSettled(t, p)
	if d.count() != 1 {
		t.Fatal("warmed while off")
	}
	p.setOn(true)
	d.fail = true
	p.warm()
	waitSettled(t, p)
	if p.take() != nil {
		t.Fatal("a spare from a failed dial")
	}
	d.fail = false
	p.warm()
	waitSettled(t, p)
	if d.count() != 2 {
		t.Fatal("no warm after a failed one: dials ", d.count())
	}
	p.Close()
	if !d.conns[1].closed.Load() {
		t.Fatal("the spare outlived Close")
	}
	p.warm()
	waitSettled(t, p)
	if d.count() != 2 {
		t.Fatal("warmed after Close")
	}
}

// A spare the server closed or wrote to while it waited is not handed out: the request dials anew
func TestPrewarmSpareClosedMeanwhile(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	d.conns[0].peer.Close()
	if p.take() != nil || !d.conns[0].closed.Load() {
		t.Fatal("a spare its server closed was handed out")
	}
	p.warm()
	waitSettled(t, p)
	go d.conns[1].peer.Write([]byte{0x17})
	time.Sleep(10 * time.Millisecond)
	if p.take() != nil || !d.conns[1].closed.Load() {
		t.Fatal("a spare with bytes before its request was handed out")
	}
	p.warm()
	waitSettled(t, p)
	conn := p.take()
	if conn == nil || d.conns[2].closed.Load() {
		t.Fatal("an open spare was not handed out")
	}
	// the peek leaves no deadline behind
	go d.conns[2].peer.Write([]byte{1})
	var one [1]byte
	if n, err := conn.Read(one[:]); n != 1 || err != nil {
		t.Fatal("the spare after the peek: ", n, err)
	}
}

// The peek's timeout leaves a TLS connection whole: the request and the answer after it go through
func TestPrewarmPeekKeepsTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"node.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		server := stdtls.Server(raw, &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		defer server.Close()
		request := make([]byte, 7)
		if _, err := io.ReadFull(server, request); err != nil {
			return
		}
		server.Write(append([]byte("answer:"), request...))
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := stdtls.Client(raw, &stdtls.Config{ServerName: "node.example", InsecureSkipVerify: true})
	defer client.Close()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if !stillOpen(client) {
		t.Fatal("an open TLS connection taken as closed")
	}
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal("write after the peek: ", err)
	}
	answer := make([]byte, 14)
	if _, err := io.ReadFull(client, answer); err != nil || string(answer) != "answer:request" {
		t.Fatal("read after the peek: ", string(answer), err)
	}
}
