package knock

import (
	"context"
	"net"
	"testing"
	"time"
)

func shortContext(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancel)
	return c
}

func openGated(t *testing.T, g *handshakeGate, key string, count int) (conns []*gatedConn, peers []net.Conn) {
	for range count {
		release, err := g.acquire(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		a, b := net.Pipe()
		conns = append(conns, &gatedConn{Conn: a, release: release})
		peers = append(peers, b)
	}
	return conns, peers
}

func answer(t *testing.T, conn *gatedConn, peer net.Conn) {
	go peer.Write([]byte{0x16})
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

// a burst's first eight go at once; the ninth waits until no more than two of them wait for the node (variant б, R5)
func TestHandshakeGateBurst(t *testing.T) {
	var g handshakeGate
	conns, peers := openGated(t, &g, "node:443", burstHandshakes)
	if _, err := g.acquire(shortContext(t), "node:443"); err == nil {
		t.Fatal("a ninth handshake went at once")
	}
	// another node is not held back
	if release, err := g.acquire(shortContext(t), "other:443"); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	// five answered: three still wait, still no slot
	for i := range 5 {
		answer(t, conns[i], peers[i])
	}
	if _, err := g.acquire(shortContext(t), "node:443"); err == nil {
		t.Fatal("a handshake went with three waiting after the burst")
	}
	// the sixth answers: two wait, one goes; its release again (a later read, its close) frees nothing more
	answer(t, conns[5], peers[5])
	conns[5].release()
	release, err := g.acquire(shortContext(t), "node:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.acquire(shortContext(t), "node:443"); err == nil {
		t.Fatal("a slot freed twice")
	}
	// closing a waiting one frees its slot
	conns[6].Close()
	if _, err := g.acquire(shortContext(t), "node:443"); err != nil {
		t.Fatal(err)
	}
	release()
	release()
}

// once none waits for the node, the next connections are a new burst: eight at once again
func TestHandshakeGateNewBurst(t *testing.T) {
	var g handshakeGate
	conns, peers := openGated(t, &g, "node:443", burstHandshakes)
	for i := range conns {
		answer(t, conns[i], peers[i])
	}
	more, _ := openGated(t, &g, "node:443", burstHandshakes)
	if _, err := g.acquire(shortContext(t), "node:443"); err == nil {
		t.Fatal("a ninth handshake of the second burst went at once")
	}
	for _, c := range more {
		c.Close()
	}
	if len(g.nodes) != 0 {
		t.Fatal("a node with none waiting is still kept")
	}
}

// a slot held past handshakeHold frees by itself: a node that never answers does not hold the next ones for good
func TestHandshakeGateWaiterWakes(t *testing.T) {
	var g handshakeGate
	conns, _ := openGated(t, &g, "node:443", burstHandshakes)
	got := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		release, err := g.acquire(ctx, "node:443")
		if err == nil {
			release()
		}
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	for i := range 6 {
		conns[i].Close()
	}
	if err := <-got; err != nil {
		t.Fatal("a waiting handshake not woken by the slots freed: ", err)
	}
}
