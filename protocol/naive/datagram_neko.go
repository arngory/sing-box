//go:build with_naive_outbound

package naive

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// UDP as HTTP/3 datagrams (raycontrol docs/spec/naive-udp-v1.md, udp=1 in a node's naive line; neko). One request
// per UDP socket of the app: an extended CONNECT with :protocol connect-udp on a second engine whose sessions are
// QUIC, the TCP engine untouched. Each datagram carries its destination (to the node) or its source (from it) in
// front of the payload, so one socket of the node serves every destination of the app's socket, as UoT does.

const (
	// the request's path: RFC 9298's template with the target * (naive-udp-v1 §3.2)
	datagramPath = "/.well-known/masque/udp/%2A/%2A/"
	// the request header that registers Context ID 2 with the format below, and the answer's that confirms it
	datagramVersionHeader = "niko-udp"
	datagramVersion       = "1"
	// the longest UDP payload the app can hand over, as UoT takes
	datagramMaxPayload = 65507
	// a pair that began with QUIC sends a datagram as a capsule only up to this many bytes (1280 − 28): its MTU
	// probes above what fits a QUIC datagram are lost as on a real path (§4.4)
	quicPairCapsuleLimit = 1252
	// the destinations a socket remembers for the QUIC rule; past this a new one counts as not QUIC
	maxDatagramPairs = 1024
	// the longest address in front of a payload: the type, a name's length and 255 bytes, the port
	datagramMaxHeader = 1 + 1 + 255 + 2
)

const (
	datagramAddressIPv4 = 4
	datagramAddressIPv6 = 6
	datagramAddressName = 3
)

var errDatagramAddress = errors.New("naive: no address a datagram can carry")

// appendDatagramAddress appends the address in front of a datagram's payload (§3.2): its type (4, 6 or 3 for a
// name), the address or the name's length and the name, the port big-endian. Port 0 and an empty or longer name
// have no form.
func appendDatagramAddress(b []byte, destination M.Socksaddr) ([]byte, error) {
	if destination.Port == 0 {
		return b, errDatagramAddress
	}
	switch {
	case destination.Addr.IsValid():
		addr := destination.Addr.Unmap()
		if addr.Is4() {
			a := addr.As4()
			b = append(b, datagramAddressIPv4)
			b = append(b, a[:]...)
		} else {
			a := addr.As16()
			b = append(b, datagramAddressIPv6)
			b = append(b, a[:]...)
		}
	case destination.Fqdn != "" && len(destination.Fqdn) <= 255:
		b = append(b, datagramAddressName, byte(len(destination.Fqdn)))
		b = append(b, destination.Fqdn...)
	default:
		return b, errDatagramAddress
	}
	return binary.BigEndian.AppendUint16(b, destination.Port), nil
}

// parseDatagramAddress reads the source in front of a datagram from the node: type 4 or 6 only, a nonzero port.
// It returns the source and the header's length; a datagram that has none is dropped by the caller (§3.2).
func parseDatagramAddress(b []byte) (M.Socksaddr, int, error) {
	if len(b) < 1 {
		return M.Socksaddr{}, 0, errDatagramAddress
	}
	var addr netip.Addr
	var n int
	switch b[0] {
	case datagramAddressIPv4:
		if len(b) < 1+4+2 {
			return M.Socksaddr{}, 0, errDatagramAddress
		}
		addr = netip.AddrFrom4([4]byte(b[1:5]))
		n = 1 + 4
	case datagramAddressIPv6:
		if len(b) < 1+16+2 {
			return M.Socksaddr{}, 0, errDatagramAddress
		}
		addr = netip.AddrFrom16([16]byte(b[1:17])).Unmap()
		n = 1 + 16
	default:
		return M.Socksaddr{}, 0, errDatagramAddress
	}
	port := binary.BigEndian.Uint16(b[n:])
	if port == 0 {
		return M.Socksaddr{}, 0, errDatagramAddress
	}
	return M.SocksaddrFrom(addr, port), n + 2, nil
}

// isQUICLongHeader tells a QUIC packet with a long header of version 1 or 2: the first datagram of a pair that
// makes it a QUIC pair (§4.4).
func isQUICLongHeader(p []byte) bool {
	if len(p) < 5 || p[0]&0x80 == 0 {
		return false
	}
	switch binary.BigEndian.Uint32(p[1:5]) {
	case 0x00000001, 0x6b3343cf:
		return true
	}
	return false
}

// datagramConn is what the packet connection needs of cronet's DatagramConn (a fake in the tests).
type datagramConn interface {
	WaitReady(ctx context.Context) (status int, headers map[string]string, err error)
	ReadDatagram(ctx context.Context, b []byte) (int, error)
	WriteDatagram(b []byte) error
	MaxPayload() int
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Done() <-chan struct{}
	Err() error
	Close() error
}

// datagramPacketConn is one UDP socket of the app over one connect-udp request.
type datagramPacketConn struct {
	conn datagramConn
	// the destinations this socket has sent to, as the app addressed them, and whether the first datagram to each
	// was QUIC
	access sync.Mutex
	pairs  map[string]bool
}

var (
	_ N.PacketConn            = (*datagramPacketConn)(nil)
	_ net.PacketConn          = (*datagramPacketConn)(nil)
	_ N.FrontHeadroom         = (*datagramPacketConn)(nil)
	_ N.PacketReadWaitCreator = (*datagramPacketConn)(nil)
	_ N.PacketReadWaiter      = (*datagramReadWaiter)(nil)
)

func newDatagramPacketConn(conn datagramConn) *datagramPacketConn {
	return &datagramPacketConn{conn: conn, pairs: make(map[string]bool)}
}

// quicPair tells whether the pair began with QUIC, remembering the first datagram's kind for a new one.
func (c *datagramPacketConn) quicPair(destination M.Socksaddr, payload []byte) bool {
	key := destination.String()
	c.access.Lock()
	defer c.access.Unlock()
	quic, known := c.pairs[key]
	if !known {
		quic = isQUICLongHeader(payload)
		if len(c.pairs) < maxDatagramPairs {
			c.pairs[key] = quic
		}
	}
	return quic
}

// write sends one datagram whose frame (the address, then the payload) build makes. A datagram the rules drop, or
// the library has no room for, is lost as UDP is: no error.
func (c *datagramPacketConn) write(destination M.Socksaddr, payload []byte, frame func(header []byte) []byte) error {
	if len(payload) > datagramMaxPayload {
		return nil
	}
	var headerArray [datagramMaxHeader]byte
	header, err := appendDatagramAddress(headerArray[:0], destination)
	if err != nil {
		return E.Cause(err, destination)
	}
	if c.quicPair(destination, payload) && len(payload) > quicPairCapsuleLimit {
		// a datagram that does not fit the QUIC datagram goes as a capsule (or, before the node's answer, every one
		// does): a QUIC pair's longer one is dropped instead
		if maxPayload := c.conn.MaxPayload(); maxPayload == 0 || len(header)+len(payload) > maxPayload {
			return nil
		}
	}
	err = c.conn.WriteDatagram(frame(header))
	if errors.Is(err, errDatagramClosed) {
		select {
		case <-c.conn.Done():
			// the request has ended: its error is for watch to read, which a close here could hide
		default:
			// the node stopped reading the request (STOP_SENDING) while it may go on sending: the socket ends here,
			// so its reads end too and the app's next packet opens a new request, instead of one that only reads
			c.conn.Close()
		}
	}
	switch {
	case err == nil,
		errors.Is(err, errDatagramQueueFull),
		errors.Is(err, errDatagramCapsuleTimeout),
		errors.Is(err, errDatagramTooLarge):
		return nil
	default:
		return err
	}
}

func (c *datagramPacketConn) FrontHeadroom() int {
	return datagramMaxHeader
}

func (c *datagramPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	payload := buffer.Bytes()
	return c.write(destination, payload, func(header []byte) []byte {
		if buffer.Start() >= len(header) {
			copy(buffer.ExtendHeader(len(header)), header)
			return buffer.Bytes()
		}
		return append(append(make([]byte, 0, len(header)+len(payload)), header...), payload...)
	})
}

func (c *datagramPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	err := c.write(M.SocksaddrFromNet(addr), p, func(header []byte) []byte {
		return append(append(make([]byte, 0, len(header)+len(p)), header...), p...)
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// readFrame reads the next datagram the node sent into b and the length of its address in front: one the library
// cut short is taken as it is, as UDP cuts it; one without a readable address is skipped.
func (c *datagramPacketConn) readFrame(b []byte) (source M.Socksaddr, header, n int, err error) {
	for {
		n, err = c.conn.ReadDatagram(context.Background(), b)
		if errors.Is(err, errDatagramTruncated) {
			err = nil
		}
		if err != nil {
			return M.Socksaddr{}, 0, 0, err
		}
		source, header, err = parseDatagramAddress(b[:n])
		if err == nil {
			return source, header, n, nil
		}
	}
}

func (c *datagramPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	source, header, n, err := c.readFrame(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	buffer.Advance(header)
	return source, nil
}

func (c *datagramPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	source, header, n, err := c.readFrame(p)
	if err != nil {
		return 0, nil, err
	}
	return copy(p, p[header:n]), source.UDPAddr(), nil
}

func (c *datagramPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	return &datagramReadWaiter{conn: c}, true
}

func (c *datagramPacketConn) Close() error {
	return c.conn.Close()
}

func (c *datagramPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *datagramPacketConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *datagramPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *datagramPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *datagramPacketConn) Upstream() any {
	return c.conn
}

// datagramReadWaiter reads into a buffer of the caller's options, the headroom included.
type datagramReadWaiter struct {
	conn    *datagramPacketConn
	options N.ReadWaitOptions
}

func (w *datagramReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *datagramReadWaiter) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	buffer := w.options.NewPacketBuffer()
	source, err := w.conn.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	w.options.PostReturn(buffer)
	return buffer, source, nil
}

// datagramPadding is the Padding header of a request, as naive's: 30 to 61 characters, 16 random of a printable
// set, the rest ~ (cronet-go's generatePaddingHeader).
func datagramPadding() string {
	length := rand.Intn(32) + 30
	padding := make([]byte, length)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < length; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

// datagramAccepted tells the node's answer that takes the request: 200 and niko-udp: 1 (§3.2). A 200 without it is
// a node that took the request for a TCP CONNECT (§3.3): not taken either.
func datagramAccepted(status int, headers map[string]string) bool {
	if status != 200 {
		return false
	}
	for key, value := range headers {
		if strings.EqualFold(key, datagramVersionHeader) {
			return strings.TrimSpace(value) == datagramVersion
		}
	}
	return false
}

// datagramRefusedOnce tells an answer that refuses this request only: 429 (the places of the user or the service,
// §7) and 503 (the node's socket did not open, try later). Any other answer that is not the request's acceptance is
// the site's: the service's flag is off or the node is old, and the network stays on UoT (§9.4 step 4).
func datagramRefusedOnce(status int) bool {
	return status == 429 || status == 503
}

// datagramRefusalsInARow 429s and 503s with no request taken between them send the network back over UoT: the node
// keeps refusing, and every UDP socket of the app would end at its first answer.
const datagramRefusalsInARow = 3

// datagramClient opens the requests on a second naive client whose engine is QUIC, started at the first socket.
// The app decides per network whether UDP goes this way (SetDatagramAllowed, after its probe: naive-udp-v1 §9.4);
// a refusal, a node without datagrams or a QUIC connection that broke sends new sockets back over UoT until the
// next network.
type datagramClient struct {
	ctx           context.Context
	logger        logger.ContextLogger
	options       cronet.NaiveClientOptions
	url           string
	authorization string
	// the user's extra_headers: they go with every request, as with the tunnel's
	extraHeaders map[string]string

	access sync.Mutex
	client *cronet.NaiveClient
	// the outbound has closed: no engine is started again
	closed bool
	// the library cannot do datagrams at all (an old libcronet): never again
	unsupported atomic.Bool

	allowed atomic.Bool
	refused atomic.Bool
	// allowed from the start and after every network change (udp_datagram_allowed): no app probes
	allowedAlways bool
	// counts the networks: a request of an earlier one that fails (its connections are closed on the change) says
	// nothing about this one
	generation atomic.Uint64
	// 429s and 503s since the last request the node took, on this network
	refusedInARow atomic.Int32
}

func newDatagramClient(ctx context.Context, logger logger.ContextLogger, options cronet.NaiveClientOptions, serverName string, authorization string) *datagramClient {
	options.QUIC = true
	// one QUIC connection carries every request: one congestion controller, one path MTU (§2.4)
	options.InsecureConcurrency = 0
	d := &datagramClient{
		ctx:           ctx,
		logger:        logger,
		options:       options,
		url:           "https://" + net.JoinHostPort(serverName, F.ToString(options.ServerAddress.Port)) + datagramPath,
		authorization: authorization,
		extraHeaders:  options.ExtraHeaders,
	}
	if !datagramBuilt {
		// a core without the datagram API: the app's state says so from the start, and no probe is spent on it
		d.unsupported.Store(true)
		logger.WarnContext(ctx, "naive: UDP stays over TCP: ", errDatagramUnsupported)
	}
	return d
}

// usable tells whether a new socket goes as datagrams now.
func (d *datagramClient) usable() bool {
	return d != nil && d.allowed.Load() && !d.refused.Load() && !d.unsupported.Load()
}

func (d *datagramClient) start() (*cronet.NaiveClient, error) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if d.client != nil {
		return d.client, nil
	}
	if err := checkDatagramSupport(); err != nil {
		d.unsupported.Store(true)
		d.logger.WarnContext(d.ctx, "naive: UDP stays over TCP, the library has no datagrams: ", err)
		return nil, err
	}
	client, err := cronet.NewNaiveClient(d.options)
	if err == nil {
		err = client.Start()
	}
	if err != nil {
		if client != nil {
			client.Close()
		}
		return nil, E.Cause(err, "start the QUIC engine for UDP")
	}
	d.client = client
	return client, nil
}

// refuse sends new sockets back over UoT until the next network, saying why once; a request of an earlier network
// (generation) does not count.
func (d *datagramClient) refuse(generation uint64, reason string) {
	if d.generation.Load() != generation {
		return
	}
	if d.refused.CompareAndSwap(false, true) {
		d.logger.WarnContext(d.ctx, "naive: UDP back over TCP on this network: ", reason)
	}
}

func (d *datagramClient) listenPacket(ctx context.Context) (net.PacketConn, error) {
	generation := d.generation.Load()
	client, err := d.start()
	if err != nil {
		return nil, err
	}
	conn, err := openDatagram(ctx, client, d.url, d.headers())
	if err != nil {
		return nil, err
	}
	go d.watch(ctx, conn, generation)
	return newDatagramPacketConn(conn), nil
}

// headers are a request's (§3.2), as the tunnel's: Padding, the authorization, QUIC forced, the user's extra
// headers last; niko-udp: 1 registers the datagram format. The library adds :protocol and capsule-protocol.
func (d *datagramClient) headers() map[string]string {
	headers := map[string]string{
		"padding":     datagramPadding(),
		"-force-quic": "true",
	}
	if d.authorization != "" {
		headers["proxy-authorization"] = d.authorization
	}
	for key, value := range d.extraHeaders {
		headers[key] = value
	}
	headers[datagramVersionHeader] = datagramVersion
	return headers
}

// watch checks the node's answer to a request and how the request ends: a refusal or a broken connection turns
// new sockets back to UoT (§9.4 step 4). A socket the app closed, or one the node ended cleanly, says nothing.
func (d *datagramClient) watch(ctx context.Context, conn datagramConn, generation uint64) {
	status, headers, err := conn.WaitReady(ctx)
	if errors.Is(err, net.ErrClosed) {
		// a request that ended before it was closed: its own end is the answer, not the close
		select {
		case <-conn.Done():
			if ended := conn.Err(); ended != nil && !errors.Is(ended, net.ErrClosed) {
				err = ended
			}
		default:
		}
	}
	switch {
	case err == nil && datagramAccepted(status, headers):
	case err == nil && datagramRefusedOnce(status):
		// the places of the user or the service (shared with UoT, which a 429 would reach as well) or a socket the
		// node could not open: this socket ends, the next one asks again. A node that keeps refusing (no UDP out,
		// no descriptors left) sends the network back over UoT after a few in a row
		conn.Close()
		if d.generation.Load() != generation {
			return
		}
		inARow := d.refusedInARow.Add(1)
		if inARow == 1 {
			d.logger.WarnContext(ctx, "naive: the node refused a UDP request (", status, "), the next socket asks again")
		}
		if inARow >= datagramRefusalsInARow {
			d.refuse(generation, F.ToString("the node refused ", inARow, " UDP requests in a row, the last ", status))
		}
		return
	case err == nil:
		d.refuse(generation, "the node answered "+F.ToString(status))
		conn.Close()
		return
	default:
		if !quietEnd(err) {
			d.refuse(generation, err.Error())
		}
		conn.Close()
		return
	}
	if d.generation.Load() == generation {
		d.refusedInARow.Store(0)
	}
	<-conn.Done()
	if err = conn.Err(); err != nil && !quietEnd(err) {
		d.refuse(generation, err.Error())
	}
}

// quietEnd tells an end that is no fault of the path: the app's close, its context, the node's clean end.
func quietEnd(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// networkChanged drops what the last network decided: the app probes the new one before it allows datagrams.
func (d *datagramClient) networkChanged() {
	if d == nil {
		return
	}
	d.generation.Add(1)
	d.allowed.Store(d.allowedAlways)
	d.refused.Store(false)
	d.refusedInARow.Store(0)
	d.access.Lock()
	client := d.client
	d.access.Unlock()
	if client != nil {
		client.CloseAllConnections()
	}
}

func (d *datagramClient) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	client := d.client
	d.client = nil
	d.closed = true
	d.access.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}
