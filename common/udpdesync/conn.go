// Package udpdesync shapes the first datagrams of a QUIC client flow so that a
// DPI box classifying the flow by its first packets misses it (neko, see
// arngory/niko docs/research/anti-dpi.md §3):
//
//   - a prelude: fake datagrams sent before the first real one, random bytes or
//     a QUIC Initial carrying an allowed SNI, optionally with a low TTL so they
//     die before the server. niko-server drops them anyway: they do not pass its
//     classification and do not pin the flow.
//   - Initial reordering: a post-quantum ClientHello spans two Initial packets;
//     the second one goes first. QUIC reassembles CRYPTO data by offset, so any
//     server accepts it, while a box reading the first Initial misses the SNI.
package udpdesync

import (
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const (
	MaxPrelude = 8
	// how long the first Initial waits for the second one
	reorderWait = 15 * time.Millisecond
)

type Options struct {
	// Prelude is the number of fake datagrams before the first real one.
	Prelude int
	// PreludeSNI makes the fakes QUIC Initials with this server name; empty = random bytes.
	PreludeSNI string
	// PreludeTTL sends the fakes with this IP TTL / hop limit; 0 = the system default.
	PreludeTTL int
	// ReorderInitial sends the second QUIC Initial before the first.
	ReorderInitial bool
}

func (o Options) Enabled() bool { return o.Prelude > 0 || o.ReorderInitial }

type Conn struct {
	net.Conn
	options Options
	logger  logger.Logger

	prelude sync.Once

	access      sync.Mutex
	reorderDone bool
	held        []byte
	timer       *time.Timer
	// reordered reports that two Initials went out swapped (tests)
	reordered atomic.Bool
}

// NewConn wraps a connected UDP socket. quic-go cannot tune a socket it does not
// see, so the wrapper gives it the buffers and DF quic-go would set.
func NewConn(conn net.Conn, options Options, logger logger.Logger) *Conn {
	tuneSocket(conn)
	return &Conn{Conn: conn, options: options, logger: logger, reorderDone: !options.ReorderInitial}
}

func (c *Conn) Upstream() any { return c.Conn }

func (c *Conn) Write(b []byte) (int, error) {
	c.prelude.Do(c.sendPrelude)
	c.access.Lock()
	if c.reorderDone {
		c.access.Unlock()
		return c.Conn.Write(b)
	}
	defer c.access.Unlock()
	if c.held == nil {
		if !isInitial(b) {
			c.reorderDone = true
			return c.Conn.Write(b)
		}
		c.held = append([]byte(nil), b...)
		c.timer = time.AfterFunc(reorderWait, c.flushHeld)
		return len(b), nil
	}
	// the second datagram: an Initial goes before the held one, anything else after it
	c.reorderDone = true
	c.timer.Stop()
	held := c.held
	c.held = nil
	if isInitial(b) {
		n, err := c.Conn.Write(b)
		if err != nil {
			return n, err
		}
		_, err = c.Conn.Write(held)
		c.reordered.Store(true)
		return n, err
	}
	if _, err := c.Conn.Write(held); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// flushHeld sends a lone first Initial (a ClientHello that fits one packet).
func (c *Conn) flushHeld() {
	c.access.Lock()
	defer c.access.Unlock()
	if c.held == nil {
		return
	}
	c.reorderDone = true
	c.Conn.Write(c.held)
	c.held = nil
}

func (c *Conn) Close() error {
	c.access.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.held = nil
	c.access.Unlock()
	return c.Conn.Close()
}

func (c *Conn) sendPrelude() {
	if c.options.Prelude <= 0 {
		return
	}
	restore := func() {}
	if c.options.PreludeTTL > 0 {
		var err error
		restore, err = setTTL(c.Conn, c.options.PreludeTTL)
		if err != nil && c.logger != nil {
			c.logger.Warn("udp prelude: cannot set TTL, sending with the default: ", err)
		}
	}
	defer restore()
	for i := 0; i < min(c.options.Prelude, MaxPrelude); i++ {
		var packet []byte
		if c.options.PreludeSNI != "" {
			packet = FakeInitial(c.options.PreludeSNI)
		} else {
			packet = make([]byte, 100+randomInt(1101))
			rand.Read(packet)
			// not a QUIC long header, so no server takes it for a connection attempt
			packet[0] &= 0x3f
		}
		c.Conn.Write(packet)
	}
}

// isInitial matches a QUIC v1 or v2 long-header Initial packet.
func isInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	version := uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
	packetType := (b[0] >> 4) & 0x03
	switch version {
	case 1:
		return packetType == 0
	case 0x6b3343cf: // QUIC v2: Initial is type 1
		return packetType == 1
	}
	return false
}

func randomInt(n int64) int {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
