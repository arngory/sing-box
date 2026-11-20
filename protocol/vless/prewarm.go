package vless

import (
	"context"
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

// take hands out the spare, if one is ready
func (p *prewarm) take() net.Conn {
	p.access.Lock()
	defer p.access.Unlock()
	conn := p.spare
	if conn != nil {
		p.spare = nil
		p.expiry.Stop()
	}
	return conn
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
		p.access.Lock()
		p.warming = false
		if err != nil {
			p.access.Unlock()
			p.logger.Debug("prewarm: ", err)
			return
		}
		if p.closed || p.off || generation != p.generation || p.spare != nil {
			p.access.Unlock()
			conn.Close()
			return
		}
		p.spare = conn
		p.expiry = time.AfterFunc(p.idle, func() { p.expire(conn) })
		p.access.Unlock()
	}()
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
