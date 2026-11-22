package tcpdesync

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// BufferTimeout is how long the first write waits for the rest of its ClientHello record.
const BufferTimeout = 200 * time.Millisecond

// test hooks: every TTL the Linux sender sets, every plan sent
var (
	testHookTTL    func(ttl int)
	testHookPieces func(pieces []Piece)
)

const (
	stateFirst uint32 = iota
	stateBuffering
	stateDone
)

// SocketOf returns the TCP socket under conn when what is written to conn reaches the socket unchanged: a direct
// outbound connection, not one inside a proxy protocol.
func SocketOf(conn net.Conn) (*net.TCPConn, bool) {
	tcpConn, ok := N.UnwrapWriter(conn).(*net.TCPConn)
	return tcpConn, ok
}

// Conn applies a strategy to the first write. A first write that starts a ClientHello record but does not hold it
// whole is held until the record is complete (at most 16 KiB + 5 bytes and BufferTimeout); then it is cut. Later
// writes pass through.
type Conn struct {
	net.Conn
	ctx      context.Context
	strategy *Strategy
	logger   logger.ContextLogger
	socket   *net.TCPConn

	state   atomic.Uint32
	access  sync.Mutex
	pending []byte
	need    int
	timer   *time.Timer
	// a held ClientHello the timer could not send: the stream has a hole, every later write fails with err
	err    error
	failed atomic.Bool
}

// NewConn wraps conn. Without a TCP socket under it (SocketOf) only tlsrec applies.
func NewConn(ctx context.Context, conn net.Conn, strategy *Strategy, contextLogger logger.ContextLogger) *Conn {
	if contextLogger == nil {
		contextLogger = logger.NOP()
	}
	socket, _ := SocketOf(conn)
	return &Conn{
		Conn:     conn,
		ctx:      ctx,
		strategy: strategy,
		logger:   contextLogger,
		socket:   socket,
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.state.Load() == stateDone {
		if c.failed.Load() {
			return 0, c.err
		}
		return c.Conn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	switch c.state.Load() {
	case stateDone:
		if c.err != nil {
			return 0, c.err
		}
		return c.Conn.Write(b)
	case stateBuffering:
		c.pending = append(c.pending, b...)
		if len(c.pending) < c.need {
			return len(b), nil
		}
		c.timer.Stop()
		data := c.pending
		c.pending = nil
		// done only once sent: a write that skips the lock must not overtake the first one
		err := c.send(data)
		c.state.Store(stateDone)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}
	if len(b) == 0 {
		return c.Conn.Write(b)
	}
	if need, ok := recordLength(b); ok && len(b) < need {
		c.pending = append(make([]byte, 0, need), b...)
		c.need = need
		c.state.Store(stateBuffering)
		c.timer = time.AfterFunc(BufferTimeout, c.bufferTimeout)
		return len(b), nil
	}
	err := c.send(b)
	c.state.Store(stateDone)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) bufferTimeout() {
	c.access.Lock()
	defer c.access.Unlock()
	if c.state.Load() != stateBuffering {
		return
	}
	data := c.pending
	c.pending = nil
	c.logger.DebugContext(c.ctx, "tcp_desync: no whole ClientHello record in ", BufferTimeout, " (", len(data), " of ", c.need, " bytes), sent as is")
	if _, err := c.Conn.Write(data); err != nil {
		c.err = err
		c.failed.Store(true)
	}
	c.state.Store(stateDone)
}

func (c *Conn) send(data []byte) error {
	pieces := c.strategy.Plan(data)
	if len(pieces) == 0 {
		_, err := c.Conn.Write(data)
		return err
	}
	if len(pieces) == 1 || c.socket == nil {
		if len(pieces) > 1 {
			c.logger.DebugContext(c.ctx, "tcp_desync: no TCP socket under the connection, TLS records cut only")
		}
		_, err := c.Conn.Write(Stream(pieces))
		return err
	}
	c.logger.DebugContext(c.ctx, "tcp_desync: ", describe(pieces))
	if testHookPieces != nil {
		testHookPieces(pieces)
	}
	return sendPieces(c.ctx, c.socket, pieces, c.logger)
}

// describe is the pieces' sizes and modes for the debug log: "517 bytes: 1 split, 99 disoob, 417".
func describe(pieces []Piece) string {
	var total int
	parts := make([]string, 0, len(pieces))
	for i, piece := range pieces {
		total += len(piece.Data)
		part := strconv.Itoa(len(piece.Data))
		if i < len(pieces)-1 {
			part += " " + piece.Mode.String()
		}
		parts = append(parts, part)
	}
	return strconv.Itoa(total) + " bytes: " + strings.Join(parts, ", ")
}

// Close sends what is held for a ClientHello first.
func (c *Conn) Close() error {
	if c.state.Load() == stateBuffering && c.access.TryLock() {
		if c.state.Load() == stateBuffering {
			c.timer.Stop()
			_, _ = c.Conn.Write(c.pending)
			c.pending = nil
			c.state.Store(stateDone)
		}
		c.access.Unlock()
	}
	return c.Conn.Close()
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.state.Load() == stateDone
}

func (c *Conn) Upstream() any {
	return c.Conn
}
