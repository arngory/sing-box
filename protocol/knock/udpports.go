package knock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

// UDPPortSchedule is a UDP service of a raycontrol node whose port rotates
// (spa-v2.md §11): besides its own port it is reachable on a port that changes
// every slot, so a flow does not stay on one port for longer than a slot.
type UDPPortSchedule struct {
	// Port is the service's port in the profile (e.g. 443); a UDP flow to it is
	// sent to the slot port instead.
	Port      uint16 `json:"port"`
	PortKey   string `json:"port_key"`
	PortBase  uint16 `json:"port_base"`
	PortRange uint16 `json:"port_range"`
}

type portSchedule struct {
	key     [spa2KeySize]byte
	base    uint16
	span    uint16
	slotLen uint64

	// the port of the last slot asked for: the HMAC runs once a slot, not once a datagram
	cache atomic.Uint64 // slot << 16 | port, 0 = none
}

func parseUDPPorts(list []UDPPortSchedule, spa2 *spa2Params) (map[uint16]*portSchedule, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if spa2 == nil {
		return nil, E.New("knock: udp_ports needs spa_v2 (the slot length is the node's)")
	}
	schedules := make(map[uint16]*portSchedule, len(list))
	for _, s := range list {
		p := &portSchedule{base: s.PortBase, span: s.PortRange, slotLen: spa2.slotLen}
		if err := decodeHexInto(p.key[:], s.PortKey, "udp_ports.port_key"); err != nil {
			return nil, err
		}
		if s.Port == 0 || p.span == 0 || int(p.base)+int(p.span) > 65536 {
			return nil, E.New("knock: invalid udp_ports entry for port ", s.Port)
		}
		schedules[s.Port] = p
	}
	return schedules, nil
}

// slotPort is the formula of SPA ports (spa-v2.md §3) with the service's key and range.
func slotPort(key []byte, base, span uint16, slot uint64) uint16 {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(spa2PortInfo))
	mac.Write(be64(slot))
	v := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	return base + uint16(v%uint64(span))
}

func (s *portSchedule) port(now time.Time) uint16 {
	slot := uint64(now.Unix()) / s.slotLen
	// slots are far below 2^48 (unix time / slot length); the cache holds slot+1 to tell slot 0 from none
	if c := s.cache.Load(); c != 0 && c>>16 == slot+1 {
		return uint16(c)
	}
	port := slotPort(s.key[:], s.base, s.span, slot)
	s.cache.Store((slot+1)<<16 | uint64(port))
	return port
}

// rotatingQuiet is how long an earlier socket of a rotating flow may hear
// nothing before it is closed: longer than any QUIC idle timeout, so a live
// connection has had a packet on it if the server still answers there.
const rotatingQuiet = 2 * time.Minute

// rotatingUDPConn is a connected-looking UDP flow to a service whose port
// rotates (spa-v2.md §11). Datagrams go to the port of the current slot; at a
// slot's turn the flow moves to a socket of its own, a new client port. The
// node redirects slot ports to the service with NAT, and a second redirect of
// the same client address and port has the reply tuple of the first, which
// conntrack drops while the first lives: one socket across a turn went silent
// for a minute and more. The earlier sockets are still read, since the server
// answers the address it knows until it moves to the new one (to QUIC the move
// is a NAT rebinding); one that has heard nothing for rotatingQuiet is closed,
// though never the last one heard from. Replies are reported as coming from
// the service's own address, so the protocol above never sees it change.
type rotatingUDPConn struct {
	// listen opens the socket of a new slot
	listen func() (net.PacketConn, error)
	remote *net.UDPAddr
	nodeIP netip.Addr
	// the slot port at a time
	portAt func(time.Time) uint16
	now    func() time.Time
	quiet  time.Duration
	// a slot turned: err says why the flow stayed on its socket
	onTurn func(from, to uint16, err error)

	access        sync.Mutex
	port          uint16
	target        *net.UDPAddr
	current       *rotatingSocket
	sockets       []*rotatingSocket // every open one, the current last
	writeDeadline time.Time
	closed        bool

	start        sync.Once
	reads        chan []byte
	failed       chan error
	done         chan struct{}
	readDeadline pipe.Deadline
}

type rotatingSocket struct {
	net.PacketConn
	// when it last heard from the node (opening counts), unix nanoseconds
	heard   atomic.Int64
	retired atomic.Bool
}

func newRotatingUDPConn(conn net.PacketConn, destination M.Socksaddr, schedule *portSchedule, listen func() (net.PacketConn, error)) *rotatingUDPConn {
	c := &rotatingUDPConn{
		listen:       listen,
		remote:       destination.UDPAddr(),
		nodeIP:       destination.Addr.Unmap(),
		portAt:       schedule.port,
		now:          time.Now,
		quiet:        rotatingQuiet,
		reads:        make(chan []byte),
		failed:       make(chan error, 1),
		done:         make(chan struct{}),
		readDeadline: pipe.MakeDeadline(),
	}
	c.current = &rotatingSocket{PacketConn: conn}
	c.sockets = []*rotatingSocket{c.current}
	return c
}

// begin starts reading the first socket; the fields stay as set until then.
func (c *rotatingUDPConn) begin() {
	c.start.Do(func() {
		c.access.Lock()
		defer c.access.Unlock()
		if !c.closed {
			c.current.heard.Store(c.now().UnixNano())
			go c.readLoop(c.current)
		}
	})
}

// next returns the socket and the address the next datagram goes to,
// moving the flow to a new socket when the slot turned.
func (c *rotatingUDPConn) next() (*rotatingSocket, *net.UDPAddr, error) {
	now := c.now()
	port := c.portAt(now)
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil, nil, net.ErrClosed
	}
	if c.target == nil || port != c.port {
		if c.target != nil {
			// without a new socket the flow stays on its own one, as it was before the move
			conn, err := c.listen()
			if err == nil {
				s := &rotatingSocket{PacketConn: conn}
				s.heard.Store(now.UnixNano())
				if !c.writeDeadline.IsZero() {
					conn.SetWriteDeadline(c.writeDeadline)
				}
				c.current = s
				c.sockets = append(c.sockets, s)
				go c.readLoop(s)
			}
			if c.onTurn != nil {
				c.onTurn(c.port, port, err)
			}
			c.retireQuiet(now)
		}
		c.port = port
		c.target = &net.UDPAddr{IP: c.remote.IP, Port: int(port), Zone: c.remote.Zone}
	}
	return c.current, c.target, nil
}

// retireQuiet closes the earlier sockets that heard nothing for c.quiet, but
// not the last one heard from; c.access is held.
func (c *rotatingUDPConn) retireQuiet(now time.Time) {
	var latest *rotatingSocket
	for _, s := range c.sockets {
		if s != c.current && (latest == nil || s.heard.Load() > latest.heard.Load()) {
			latest = s
		}
	}
	kept := c.sockets[:0]
	for _, s := range c.sockets {
		if s != c.current && s != latest && now.Sub(time.Unix(0, s.heard.Load())) > c.quiet {
			s.retired.Store(true)
			s.Close()
			continue
		}
		kept = append(kept, s)
	}
	clear(c.sockets[len(kept):])
	c.sockets = kept
}

func (c *rotatingUDPConn) readLoop(s *rotatingSocket) {
	scratch := make([]byte, 65535)
	for {
		n, from, err := s.ReadFrom(scratch)
		if err != nil {
			c.access.Lock()
			fatal := !s.retired.Load() && !c.closed && s == c.current
			if !fatal && !s.retired.Load() {
				// an earlier socket that broke: the others go on
				s.retired.Store(true)
				s.Close()
				c.sockets = slices.DeleteFunc(c.sockets, func(v *rotatingSocket) bool { return v == s })
			}
			c.access.Unlock()
			if fatal {
				select {
				case c.failed <- err:
				default:
				}
			}
			return
		}
		if !c.fromNode(from) {
			continue
		}
		s.heard.Store(c.now().UnixNano())
		data := buf.Get(n)
		copy(data, scratch[:n])
		select {
		case c.reads <- data:
		case <-c.done:
			buf.Put(data)
			return
		}
	}
}

func (c *rotatingUDPConn) Write(p []byte) (int, error) {
	c.begin()
	s, target, err := c.next()
	if err != nil {
		return 0, err
	}
	return s.WriteTo(p, target)
}

// Read returns datagrams from the node's address only, whatever port and socket they come from.
func (c *rotatingUDPConn) Read(p []byte) (int, error) {
	c.begin()
	select {
	case data := <-c.reads:
		n := copy(p, data)
		buf.Put(data)
		return n, nil
	case err := <-c.failed:
		return 0, err
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *rotatingUDPConn) fromNode(addr net.Addr) bool {
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ok && ip.Unmap() == c.nodeIP
	default:
		return M.SocksaddrFromNet(addr).Addr.Unmap() == c.nodeIP
	}
}

func (c *rotatingUDPConn) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	var err error
	for _, s := range c.sockets {
		s.retired.Store(true)
		err = E.Errors(err, s.Close())
	}
	c.sockets = nil
	return err
}

func (c *rotatingUDPConn) LocalAddr() net.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	return c.current.LocalAddr()
}

func (c *rotatingUDPConn) RemoteAddr() net.Addr { return c.remote }

func (c *rotatingUDPConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *rotatingUDPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *rotatingUDPConn) SetWriteDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.writeDeadline = t
	for _, s := range c.sockets {
		s.SetWriteDeadline(t)
	}
	return nil
}
