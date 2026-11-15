package knock

import (
	"context"
	"net"
	"testing"
	"time"
)

// the fourth connection to a node waits until one of the first three hears from it, or closes (R5)
func TestHandshakeGate(t *testing.T) {
	var g handshakeGate
	ctx := context.Background()
	var conns []*gatedConn
	var peers []net.Conn
	for range maxHandshakes {
		release, err := g.acquire(ctx, "node:443")
		if err != nil {
			t.Fatal(err)
		}
		a, b := net.Pipe()
		conns = append(conns, &gatedConn{Conn: a, release: release})
		peers = append(peers, b)
	}
	short := func() context.Context {
		c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		t.Cleanup(cancel)
		return c
	}
	if _, err := g.acquire(short(), "node:443"); err == nil {
		t.Fatal("a fourth handshake went at once")
	}
	// another node is not held back
	if release, err := g.acquire(short(), "other:443"); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	// the node answers the first: its slot frees, and reading again does not free another
	go peers[0].Write([]byte{0x16})
	buf := make([]byte, 1)
	if _, err := conns[0].Read(buf); err != nil {
		t.Fatal(err)
	}
	release, err := g.acquire(ctx, "node:443")
	if err != nil {
		t.Fatal(err)
	}
	conns[0].Close()
	if _, err := g.acquire(short(), "node:443"); err == nil {
		t.Fatal("a slot freed twice")
	}
	// closing a waiting one frees its slot
	conns[1].Close()
	if _, err := g.acquire(ctx, "node:443"); err != nil {
		t.Fatal(err)
	}
	release()
	release()
}
