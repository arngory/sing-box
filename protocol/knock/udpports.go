package knock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
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

// rotatingUDPConn is a connected-looking UDP flow to a service whose port
// rotates. One socket sends every datagram to the port of the current slot, so
// the node (which maps slot ports to the service, NAT keeps the client's
// address) sees one flow and QUIC goes on across slots. Replies come from the
// slot port; they are reported as coming from the service's own address, so
// the protocol above never sees the remote address change.
type rotatingUDPConn struct {
	conn   net.PacketConn
	remote *net.UDPAddr
	nodeIP netip.Addr
	// the slot port at a time
	portAt func(time.Time) uint16
	now    func() time.Time

	access sync.Mutex
	port   uint16
	target *net.UDPAddr
	onTurn func(from, to uint16)
}

func newRotatingUDPConn(conn net.PacketConn, destination M.Socksaddr, schedule *portSchedule) *rotatingUDPConn {
	return &rotatingUDPConn{
		conn:   conn,
		remote: destination.UDPAddr(),
		nodeIP: destination.Addr.Unmap(),
		portAt: schedule.port,
		now:    time.Now,
	}
}

func (c *rotatingUDPConn) current() *net.UDPAddr {
	port := c.portAt(c.now())
	c.access.Lock()
	defer c.access.Unlock()
	if c.target == nil || port != c.port {
		if c.target != nil && c.onTurn != nil {
			c.onTurn(c.port, port)
		}
		c.port = port
		c.target = &net.UDPAddr{IP: c.remote.IP, Port: int(port), Zone: c.remote.Zone}
	}
	return c.target
}

func (c *rotatingUDPConn) Write(p []byte) (int, error) {
	return c.conn.WriteTo(p, c.current())
}

// Read returns datagrams from the node's address only, whatever port they come from.
func (c *rotatingUDPConn) Read(p []byte) (int, error) {
	for {
		n, from, err := c.conn.ReadFrom(p)
		if err != nil {
			return n, err
		}
		if c.fromNode(from) {
			return n, nil
		}
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

func (c *rotatingUDPConn) Close() error                       { return c.conn.Close() }
func (c *rotatingUDPConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *rotatingUDPConn) RemoteAddr() net.Addr               { return c.remote }
func (c *rotatingUDPConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *rotatingUDPConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *rotatingUDPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *rotatingUDPConn) Upstream() any                      { return c.conn }
