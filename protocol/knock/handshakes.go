package knock

import (
	"context"
	"net"
	"sync"
	"time"
)

// A burst of new TCP connections to a node (an app opening many at once, a group test) is a volley of
// ClientHellos to one port, a pattern of its own (review R5). The owner's choice (variant б): a burst's first
// burstHandshakes connections go at once, as a browser's first page does; after them at most maxHandshakes wait for
// the node's first bytes at a time, and the next one, connected already, waits for a slot before it is handed up to
// send its hello. A burst ends when none to the node waits any more. A slot frees on the node's first bytes, on
// close, or after handshakeHold.
//
// naive (cronet) takes the socket itself (a dup of the TCP fd) and closes this wrapper at once, so its connections
// are not held here. It carries every stream of the node over one HTTP/2 or QUIC session, or over as many as
// insecure_concurrency asks: those open at once and are not limited.
const (
	burstHandshakes = 8
	maxHandshakes   = 3
	handshakeHold   = 10 * time.Second
)

type handshakeGate struct {
	access sync.Mutex
	nodes  map[string]*nodeHandshakes
}

// nodeHandshakes: one node's connections waiting for its first bytes, those taken since it last had none, and a
// channel closed (and made anew) on every release, for the ones waiting for a slot.
type nodeHandshakes struct {
	pending int
	taken   int
	freed   chan struct{}
}

// acquire waits for a slot to key; release gives it back (once, whatever calls it).
func (g *handshakeGate) acquire(ctx context.Context, key string) (release func(), err error) {
	var held *nodeHandshakes
	for {
		g.access.Lock()
		if g.nodes == nil {
			g.nodes = map[string]*nodeHandshakes{}
		}
		n := g.nodes[key]
		if n == nil {
			n = &nodeHandshakes{freed: make(chan struct{})}
			g.nodes[key] = n
		}
		if n.taken < burstHandshakes || n.pending < maxHandshakes {
			n.pending++
			n.taken++
			held = n
			g.access.Unlock()
			break
		}
		freed := n.freed
		g.access.Unlock()
		select {
		case <-freed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var once sync.Once
	free := func() {
		g.access.Lock()
		defer g.access.Unlock()
		n := held
		n.pending--
		if n.pending == 0 {
			// the burst is over: the node's state goes, the next connection starts a new one
			delete(g.nodes, key)
		}
		close(n.freed)
		n.freed = make(chan struct{})
	}
	timer := time.AfterFunc(handshakeHold, func() { once.Do(free) })
	return func() {
		once.Do(func() {
			timer.Stop()
			free()
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
