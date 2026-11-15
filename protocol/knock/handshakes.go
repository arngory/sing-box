package knock

import (
	"context"
	"net"
	"sync"
	"time"
)

// A burst of new TCP connections to a node (an app opening many at once, a group test) is a volley of
// ClientHellos to one port, a pattern of its own (review R5). At most maxHandshakes connections to a node wait
// for its first bytes at a time; the next one, connected already, waits for a slot before it is handed up to send
// its hello. A slot frees on the node's first bytes, on close, or after handshakeHold.
//
// naive (cronet) takes the socket itself (a dup of the TCP fd) and closes this wrapper at once, so its connections
// are not held here. It carries every stream of the node over one HTTP/2 or QUIC session, or over as many as
// insecure_concurrency asks: those open at once and are not limited.
const (
	maxHandshakes = 3
	handshakeHold = 10 * time.Second
)

type handshakeGate struct {
	access sync.Mutex
	slots  map[string]chan struct{}
}

func (g *handshakeGate) slot(key string) chan struct{} {
	g.access.Lock()
	defer g.access.Unlock()
	if g.slots == nil {
		g.slots = map[string]chan struct{}{}
	}
	s := g.slots[key]
	if s == nil {
		s = make(chan struct{}, maxHandshakes)
		g.slots[key] = s
	}
	return s
}

// acquire waits for a slot to key; release gives it back (once, whatever calls it).
func (g *handshakeGate) acquire(ctx context.Context, key string) (release func(), err error) {
	s := g.slot(key)
	select {
	case s <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var once sync.Once
	timer := time.AfterFunc(handshakeHold, func() { once.Do(func() { <-s }) })
	return func() {
		once.Do(func() {
			timer.Stop()
			<-s
		})
	}, nil
}

// gatedConn holds its slot until the node's first bytes come.
type gatedConn struct {
	net.Conn
	release func()
}

func (c *gatedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 || err != nil {
		c.release()
	}
	return n, err
}

func (c *gatedConn) Close() error {
	c.release()
	return c.Conn.Close()
}

func (c *gatedConn) Upstream() any { return c.Conn }
