package vless

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
)

// prewarm, niko: one connection to the server opened ahead, through TCP and the TLS (REALITY) handshake, so that the
// next request goes out with its VLESS header at once instead of after two round trips. One spare at most: it is
// opened after a request of the outbound's own went through, and closed after idle without being opened again, as a
// browser's preconnect (raycontrol's decision of 2026-11-19: one connection, 10-15 s; the node's Xray waits for the
// request 60 s after the handshake). It goes through the outbound's dialer, so a knock and the R5 gate take it as any
// other connection. Off while the outbound is not in use (SetKeepIdleConnections) and dropped on a network change.
type prewarm struct {
	ctx    context.Context
	logger log.ContextLogger
	idle   time.Duration
	dial   func(ctx context.Context) (net.Conn, error)

	access     sync.Mutex
	spare      net.Conn
	expiry     *time.Timer
	warming    bool
	off        bool
	closed     bool
	generation uint64
}

// prewarmDialTimeout bounds the spare's dial and handshake: past it the spare is not worth having
const prewarmDialTimeout = 15 * time.Second

func newPrewarm(ctx context.Context, logger log.ContextLogger, idle time.Duration, dial func(ctx context.Context) (net.Conn, error)) *prewarm {
	return &prewarm{ctx: ctx, logger: logger, idle: idle, dial: dial}
}

// take hands out the spare, if one is ready and still open: one the server closed or reset while it waited is left
// for a new connection rather than failing the request it would carry. A connection a NAT dropped from its table
// without a word looks open here and is not caught (only a retry after its first read could, and a VLESS request
// may be retried only before the server answered)
func (p *prewarm) take() net.Conn {
	p.access.Lock()
	conn := p.spare
	if conn != nil {
		p.spare = nil
		p.expiry.Stop()
	}
	p.access.Unlock()
	if conn == nil {
		return nil
	}
	if !stillOpen(conn) {
		conn.Close()
		p.logger.Debug("prewarm: a spare closed meanwhile, dialling anew")
		return nil
	}
	return conn
}

// prewarmPeek is how long take looks for the spare's end: a closed connection answers at once
const prewarmPeek = time.Millisecond

// stillOpen reads the spare for prewarmPeek: nothing comes before the request, so the read runs out of time on an
// open connection. An end (EOF, a reset) or bytes of any kind (which the read would have taken) mean it is not to
// be used. A TLS connection keeps its state after a read timeout (crypto/tls and uTLS treat it as temporary).
func stillOpen(conn net.Conn) bool {
	if conn.SetReadDeadline(time.Now().Add(prewarmPeek)) != nil {
		return false
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	if conn.SetReadDeadline(time.Time{}) != nil || n > 0 {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// warm opens a spare in the background unless one is ready or on its way
func (p *prewarm) warm() {
	p.access.Lock()
	if p.closed || p.off || p.spare != nil || p.warming {
		p.access.Unlock()
		return
	}
	p.warming = true
	generation := p.generation
	p.access.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(p.ctx, prewarmDialTimeout)
		conn, err := p.dial(ctx)
		cancel()
		if err != nil {
			p.logger.Debug("prewarm: ", err)
			p.settle()
			return
		}
		p.access.Lock()
		if p.closed || p.off || generation != p.generation || p.spare != nil {
			p.access.Unlock()
			// closed before the warming ends: once it has, nothing of this attempt is left open
			conn.Close()
			p.settle()
			return
		}
		p.warming = false
		p.spare = conn
		p.expiry = time.AfterFunc(p.idle, func() { p.expire(conn) })
		p.access.Unlock()
	}()
}

func (p *prewarm) settle() {
	p.access.Lock()
	p.warming = false
	p.access.Unlock()
}

func (p *prewarm) expire(conn net.Conn) {
	p.access.Lock()
	idle := p.spare == conn
	if idle {
		p.spare = nil
	}
	p.access.Unlock()
	if idle {
		conn.Close()
	}
}

// reset drops the spare and any being opened (a network change: their sockets belong to the old one)
func (p *prewarm) reset() {
	p.access.Lock()
	p.generation++
	conn := p.spare
	if conn != nil {
		p.spare = nil
		p.expiry.Stop()
	}
	p.access.Unlock()
	common.Close(conn)
}

// setOn turns the warming on and off: off while no route uses the outbound
func (p *prewarm) setOn(on bool) {
	p.access.Lock()
	p.off = !on
	p.access.Unlock()
	if !on {
		p.reset()
	}
}

func (p *prewarm) Close() error {
	p.access.Lock()
	p.closed = true
	p.access.Unlock()
	p.reset()
	return nil
}
