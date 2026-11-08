package nikoicmp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

// Dialer opens the tunnel's stream to Name:0 (naive: a CONNECT, as for UDP over TCP).
type Dialer func(ctx context.Context) (net.Conn, error)

const (
	queueSize = 64
	// the node forgets an echo after 5 s; so does this side
	pendingFor = 5 * time.Second
	pendingMax = 256
	// the stream ended before any answer, at once: ICMP is off on the node (or not there): the TUN answers locally
	// for this long
	refusedFor    = 5 * time.Minute
	refusedWithin = 3 * time.Second
	// the stream could not be opened
	failedFor    = 30 * time.Second
	dialTimeout  = 15 * time.Second
	writeTimeout = 5 * time.Second
)

// Port is a tun.Port: the TUN hands it the app's ICMP echo requests (raw IP packets) of a flow routed to the tunnel;
// it sends them to the node on one stream and returns the node's answers to the app as IP packets: echo replies, and
// time exceeded and unreachable from the routers on the way, quoting the app's packet.
type Port struct {
	ctx    context.Context
	logger logger.ContextLogger
	dial   Dialer

	returnAccess sync.Mutex
	returnPaths  []tun.Return

	queue chan echoRequest

	access      sync.Mutex
	conn        net.Conn
	opened      time.Time
	answered    bool
	unavailable time.Time
	pending     map[pendingKey]pendingEcho
	closed      bool
}

type pendingKey struct {
	v6      bool
	id, seq uint16
}

type pendingEcho struct {
	source, destination netip.Addr
	quote               []byte
	at                  time.Time
}

func NewPort(ctx context.Context, logger logger.ContextLogger, dial Dialer) *Port {
	p := &Port{
		ctx:     ctx,
		logger:  logger,
		dial:    dial,
		queue:   make(chan echoRequest, queueSize),
		pending: make(map[pendingKey]pendingEcho),
	}
	go p.loop()
	return p
}

// Available reports whether echo goes to the node now: not after it refused the stream or could not be reached,
// for a while. The outbound routes ICMP to the port only then; else the TUN answers as without it.
func (p *Port) Available() bool {
	p.access.Lock()
	defer p.access.Unlock()
	return !p.closed && time.Now().After(p.unavailable)
}

func (p *Port) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.IPv4Unspecified(), netip.IPv6Unspecified()
}

func (p *Port) PortMTU() uint32 {
	return 0
}

func (p *Port) AttachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	if !slices.Contains(p.returnPaths, returnPath) {
		p.returnPaths = append(p.returnPaths[:len(p.returnPaths):len(p.returnPaths)], returnPath)
	}
	return nil
}

func (p *Port) DetachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	p.returnPaths = slices.DeleteFunc(slices.Clone(p.returnPaths), func(r tun.Return) bool { return r == returnPath })
	return nil
}

// WritePackets takes the app's packets without waiting: the stream is opened and written to by the port's own loop.
func (p *Port) WritePackets(packets [][]byte) error {
	for _, packet := range packets {
		echo, ok := parseEcho(packet)
		if !ok {
			continue
		}
		if len(echo.payload) > maxPayload {
			// the node answers a longer echo with too big at its own largest packet, whatever the path: answered here,
			// without its data on the stream (ping -s 1473 -M do finds 1480). An IPv4 echo without DF may not be
			// answered so: it goes unanswered, as on a path that drops it
			if !echo.df {
				continue
			}
			mtu := uint16(maxPacket4)
			if echo.destination.Is6() {
				mtu = maxPacket6
			}
			p.write(errorMessage(echo.destination, echo.source, kindTooBig, 0, mtu, slices.Clone(echo.quote)))
			continue
		}
		// the TUN reuses the packet's buffer
		echo.payload = slices.Clone(echo.payload)
		echo.quote = slices.Clone(echo.quote)
		// the node takes 1..64, 0 for its own 64
		if echo.ttl > 64 {
			echo.ttl = 0
		}
		select {
		case p.queue <- echo:
		default:
			// a burst beyond the queue: dropped, as the node would drop it beyond its rate
		}
	}
	return nil
}

func (p *Port) loop() {
	for {
		select {
		case <-p.ctx.Done():
			p.Close()
			return
		case echo := <-p.queue:
			p.send(echo)
		}
	}
}

func (p *Port) send(echo echoRequest) {
	conn := p.connection()
	if conn == nil {
		return
	}
	now := time.Now()
	p.access.Lock()
	if len(p.pending) >= pendingMax {
		for key, old := range p.pending {
			if now.Sub(old.at) > pendingFor {
				delete(p.pending, key)
			}
		}
	}
	if len(p.pending) < pendingMax {
		p.pending[pendingKey{echo.destination.Is6(), echo.id, echo.seq}] = pendingEcho{
			source: echo.source, destination: echo.destination, quote: echo.quote, at: now,
		}
	}
	p.access.Unlock()
	_ = conn.SetWriteDeadline(now.Add(writeTimeout))
	if _, err := conn.Write(clientFrame(echo)); err != nil {
		p.lost(conn)
	}
}

// connection is the stream to the node, opened when there is none; nil while the node is unavailable.
func (p *Port) connection() net.Conn {
	p.access.Lock()
	if p.conn != nil || p.closed || time.Now().Before(p.unavailable) {
		conn := p.conn
		p.access.Unlock()
		return conn
	}
	p.access.Unlock()
	ctx, cancel := context.WithTimeout(p.ctx, dialTimeout)
	conn, err := p.dial(ctx)
	cancel()
	if err == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err = conn.Write([]byte{version})
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		p.logger.Debug("icmp: the stream to the node did not open: ", err)
		p.access.Lock()
		p.unavailable = time.Now().Add(failedFor)
		p.access.Unlock()
		return nil
	}
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		conn.Close()
		return nil
	}
	p.conn = conn
	p.opened = time.Now()
	p.answered = false
	p.access.Unlock()
	go p.read(conn)
	return conn
}

func (p *Port) read(conn net.Conn) {
	for {
		frame, err := readServerFrame(conn)
		if err != nil {
			p.lost(conn)
			return
		}
		p.access.Lock()
		if p.conn == conn {
			p.answered = true
		}
		p.access.Unlock()
		p.answer(frame)
	}
}

// lost ends a stream, whichever side noticed first; one the node ended right away, with no answer at all, means ICMP
// is not there for this user.
func (p *Port) lost(conn net.Conn) {
	conn.Close()
	p.access.Lock()
	defer p.access.Unlock()
	if p.conn != conn {
		return
	}
	p.conn = nil
	if !p.answered && time.Since(p.opened) < refusedWithin {
		p.logger.Info("icmp: the node refused the stream, ping is answered locally for ", refusedFor)
		p.unavailable = time.Now().Add(refusedFor)
	}
}

func (p *Port) answer(frame serverFrame) {
	key := pendingKey{frame.from.Is6(), frame.id, frame.seq}
	p.access.Lock()
	echo, ok := p.pending[key]
	if ok {
		delete(p.pending, key)
	}
	p.access.Unlock()
	if !ok || time.Since(echo.at) > pendingFor || echo.source.Is6() != frame.from.Is6() {
		return
	}
	var packet []byte
	switch frame.kind {
	case kindEcho:
		// from the address the app pinged, as the TUN gave it
		packet = echoReply(echo.destination, echo.source, frame.id, frame.seq, frame.payload)
	case kindTimeExceeded:
		packet = errorMessage(frame.from, echo.source, kindTimeExceeded, frame.code, 0, echo.quote)
	case kindUnreachable:
		packet = errorMessage(frame.from, echo.source, kindUnreachable, frame.code, 0, echo.quote)
	case kindTooBig:
		if len(frame.payload) != 2 {
			return
		}
		packet = errorMessage(frame.from, echo.source, kindTooBig, 0, binary.BigEndian.Uint16(frame.payload), echo.quote)
	default:
		return
	}
	p.write(packet)
}

func (p *Port) write(packet []byte) {
	p.returnAccess.Lock()
	returnPaths := p.returnPaths
	p.returnAccess.Unlock()
	for _, returnPath := range returnPaths {
		headroom := returnPath.ReturnHeadroom()
		buffer := make([]byte, headroom+len(packet))
		copy(buffer[headroom:], packet)
		if len(returnPath.ReturnPackets([][]byte{buffer})) == 0 {
			return
		}
	}
}

func (p *Port) Close() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.closed = true
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	return nil
}
