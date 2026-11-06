// Package dnstt is a client for dnstt (https://www.bamsoftware.com/software/dnstt/),
// a TCP tunnel through DNS resolvers: KCP and a Noise channel over DNS queries sent by
// DoH, DoT or plain UDP, with smux streams on top. The server forwards every stream to
// one fixed upstream (an SSH, SOCKS or proxy server), so the destination of a dial is
// not sent. Adapted from dnstt-client, which is in the public domain.
package dnstt

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams close after this long without data, as in dnstt-client
const idleTimeout = 2 * time.Minute

type ResolverKind int

const (
	ResolverDoH ResolverKind = iota
	ResolverDoT
	ResolverUDP
	// DNS over TCP (RFC 7766), length-prefixed as DoT without TLS: where UDP 53 is redirected and TCP 53 is not
	ResolverTCP
)

// Resolver is where the DNS queries go: a DoH URL, or a DoT, TCP or UDP host:port.
type Resolver struct {
	Kind    ResolverKind
	URL     string // DoH
	Address M.Socksaddr
}

// ParseResolver reads "https://host/dns-query", "tls://host[:853]", "tcp://host[:53]" or "udp://host[:53]"
// ("host[:53]" alone is UDP).
func ParseResolver(raw string) (Resolver, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Resolver{}, E.New("missing resolver")
	}
	if !strings.Contains(raw, "://") {
		raw = "udp://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return Resolver{}, E.Cause(err, "parse resolver")
	}
	if parsed.Hostname() == "" {
		return Resolver{}, E.New("resolver without host: ", raw)
	}
	port := func(defaultPort uint16) uint16 {
		if parsed.Port() == "" {
			return defaultPort
		}
		return M.ParseSocksaddrHostPortStr(parsed.Hostname(), parsed.Port()).Port
	}
	switch parsed.Scheme {
	case "https":
		return Resolver{Kind: ResolverDoH, URL: raw, Address: M.ParseSocksaddrHostPort(parsed.Hostname(), port(443))}, nil
	case "tls":
		return Resolver{Kind: ResolverDoT, Address: M.ParseSocksaddrHostPort(parsed.Hostname(), port(853))}, nil
	case "udp":
		return Resolver{Kind: ResolverUDP, Address: M.ParseSocksaddrHostPort(parsed.Hostname(), port(53))}, nil
	case "tcp":
		return Resolver{Kind: ResolverTCP, Address: M.ParseSocksaddrHostPort(parsed.Hostname(), port(53))}, nil
	default:
		return Resolver{}, E.New("unknown resolver scheme ", parsed.Scheme, " (expected https, tls, tcp or udp)")
	}
}

type ClientOptions struct {
	Context  context.Context
	Logger   logger.ContextLogger
	Dialer   N.Dialer
	Domain   string
	PubKey   string // the server's Noise public key, 64 hex digits
	Resolver Resolver
	// TLS for DoH and DoT; nil uses the resolver host as server name
	TLSConfig tls.Config
	// raycontrol dnsauth-v1 tag key (AuthKey); nil sends queries without a tag
	AuthKey []byte
	// raycontrol dnsseal-v1: the zone's key K (32 bytes) to seal the framing with; nil sends it open
	SealKey []byte
	// how long a session's Noise handshake may take before a new session (a new ClientID) is tried; 0 is 30 s
	HandshakeTimeout time.Duration
}

// defaultHandshakeTimeout bounds a session's Noise handshake. The node acknowledges the first KCP segment at once;
// when the handshake message after it does not reach the node before its own deadline (a resolver dropping a
// session's first queries, queues full in a flood), the node forgets the ClientID and takes no other segment of it,
// and the client would wait for an answer forever.
const defaultHandshakeTimeout = 30 * time.Second

type Client struct {
	ctx      context.Context
	logger   logger.ContextLogger
	dialer   N.Dialer
	domain   dns.Name
	pubkey   []byte
	resolver Resolver
	tls      tls.Config
	mtu      int
	authKey  []byte
	seal     *sealer

	cancel           context.CancelFunc
	handshakeTimeout time.Duration

	access  sync.Mutex
	session *session
	// the session being set up: dials wait for it without holding access
	pending *pendingSession
	closed  bool
}

type pendingSession struct {
	done    chan struct{}
	session *session
	err     error
}

type session struct {
	packetConn net.PacketConn
	kcpConn    *kcp.UDPSession
	smux       *smux.Session
}

func (s *session) close() {
	s.smux.Close()
	s.kcpConn.Close()
	s.packetConn.Close()
}

func NewClient(options ClientOptions) (*Client, error) {
	domain, err := dns.ParseName(options.Domain)
	if err != nil {
		return nil, E.Cause(err, "parse domain")
	}
	pubkey, err := noise.DecodeKey(options.PubKey)
	if err != nil {
		return nil, E.Cause(err, "parse public key")
	}
	// clientid + padding length prefix + padding + data length prefix (+ the dnsauth tag); sealed (dnsseal-v1): N and
	// the tag + clientid + data length prefix in a name whose labels may be at their shortest, the padding frame
	// only where it fits
	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	var seal *sealer
	if options.SealKey != nil {
		if seal, err = newSealer(options.SealKey); err != nil {
			return nil, err
		}
		mtu = dnsNameCapacitySealed(domain) - sealOverhead - 8 - 1
	}
	if options.AuthKey != nil {
		mtu -= authTagLen
	}
	if mtu < 80 {
		return nil, E.New("domain ", options.Domain, " leaves only ", mtu, " bytes for the payload")
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	return &Client{
		ctx:              ctx,
		cancel:           cancel,
		handshakeTimeout: handshakeTimeout,
		logger:           options.Logger,
		dialer:           options.Dialer,
		domain:           domain,
		pubkey:           pubkey,
		resolver:         options.Resolver,
		tls:              options.TLSConfig,
		mtu:              mtu,
		authKey:          options.AuthKey,
		seal:             seal,
	}, nil
}

// dnsNameCapacity is the number of payload bytes a query name under domain can carry.
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255 - 1 // names are up to 255 octets, minus the null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64 // each label holds 63 bytes and a length octet
	capacity = capacity * 5 / 8   // base32
	return capacity
}

// DialConn opens a stream to the server's upstream.
func (c *Client) DialConn(ctx context.Context) (net.Conn, error) {
	session, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := session.smux.OpenStream()
	if err != nil {
		// a dead session is replaced on the next dial
		c.dropSession(session)
		return nil, E.Cause(err, "open dnstt stream")
	}
	return stream, nil
}

func (c *Client) getSession(ctx context.Context) (*session, error) {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil, net.ErrClosed
	}
	if c.session != nil && !c.session.smux.IsClosed() {
		session := c.session
		c.access.Unlock()
		return session, nil
	}
	if c.session != nil {
		c.session.close()
		c.session = nil
	}
	// one session set up at a time, apart from the dials: a handshake that hangs holds neither them nor Close
	pending := c.pending
	if pending == nil {
		pending = &pendingSession{done: make(chan struct{})}
		c.pending = pending
		go c.establish(pending)
	}
	c.access.Unlock()
	select {
	case <-pending.done:
		return pending.session, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// establish sets up a session within the handshake timeout; one that fails leaves the next dial a new one, with a
// new ClientID.
func (c *Client) establish(pending *pendingSession) {
	ctx, cancel := context.WithTimeout(c.ctx, c.handshakeTimeout)
	defer cancel()
	session, err := c.newSession(ctx)
	c.access.Lock()
	c.pending = nil
	if err == nil && c.closed {
		session.close()
		session, err = nil, net.ErrClosed
	}
	if err == nil {
		c.session = session
	}
	pending.session, pending.err = session, err
	c.access.Unlock()
	close(pending.done)
}

func (c *Client) dropSession(dead *session) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.session == dead {
		c.session.close()
		c.session = nil
	}
}

func (c *Client) newSession(ctx context.Context) (*session, error) {
	transport, remoteAddr, err := c.openTransport(ctx)
	if err != nil {
		return nil, err
	}
	packetConn := newDNSPacketConn(transport, remoteAddr, c.domain, c.logger, c.authKey, c.seal)
	kcpConn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, packetConn)
	if err != nil {
		packetConn.Close()
		return nil, E.Cause(err, "open KCP")
	}
	// coalesce small writes; no congestion window, only the static windows
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1)
	kcpConn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !kcpConn.SetMtu(c.mtu) {
		kcpConn.Close()
		packetConn.Close()
		return nil, E.New("set KCP MTU ", c.mtu)
	}
	// the handshake within ctx (its timeout, or the client closing): the KCP conn is closed when ctx ends first,
	// which ends the handshake's read. Not a deadline on it: noise reads it from its own goroutine after the
	// handshake, and kcp-go's SetDeadline races with a Read
	stop := context.AfterFunc(ctx, func() { kcpConn.Close() })
	noiseConn, err := noise.NewClient(kcpConn, c.pubkey)
	if !stop() && err == nil {
		// ctx ended as the handshake did: the conn is closed or about to be
		err = context.Cause(ctx)
	}
	if err != nil {
		kcpConn.Close()
		packetConn.Close()
		if ctx.Err() != nil {
			err = E.Cause(ctx.Err(), err.Error())
		}
		return nil, E.Cause(err, "noise handshake")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 << 20
	smuxSession, err := smux.Client(noiseConn, smuxConfig)
	if err != nil {
		kcpConn.Close()
		packetConn.Close()
		return nil, E.Cause(err, "open smux")
	}
	c.logger.Debug("dnstt: session ", kcpConn.GetConv(), " started, MTU ", c.mtu)
	return &session{packetConn: packetConn, kcpConn: kcpConn, smux: smuxSession}, nil
}

// openTransport returns the packet conn that carries DNS messages to the resolver.
func (c *Client) openTransport(ctx context.Context) (net.PacketConn, net.Addr, error) {
	switch c.resolver.Kind {
	case ResolverUDP:
		packetConn, err := c.dialer.ListenPacket(ctx, c.resolver.Address)
		if err != nil {
			return nil, nil, E.Cause(err, "listen for the DNS resolver")
		}
		return packetConn, c.resolver.Address.UDPAddr(), nil
	case ResolverDoT:
		packetConn, err := newTLSPacketConn(c.ctx, c.dialTLS, c.logger)
		if err != nil {
			return nil, nil, E.Cause(err, "connect to the DoT resolver")
		}
		return packetConn, turbotunnel.DummyAddr{}, nil
	case ResolverTCP:
		// the same stream of length-prefixed messages as DoT, over the bare TCP connection
		packetConn, err := newTLSPacketConn(c.ctx, c.dialTCP, c.logger)
		if err != nil {
			return nil, nil, E.Cause(err, "connect to the DNS resolver over TCP")
		}
		return packetConn, turbotunnel.DummyAddr{}, nil
	default:
		transport := &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return c.dialTLS(ctx)
			},
			MaxIdleConnsPerHost: dohSenders,
			IdleConnTimeout:     90 * time.Second,
			Proxy:               nil,
		}
		return newHTTPPacketConn(transport, c.resolver.URL, c.logger), turbotunnel.DummyAddr{}, nil
	}
}

func (c *Client) dialTCP(ctx context.Context) (net.Conn, error) {
	return c.dialer.DialContext(ctx, N.NetworkTCP, c.resolver.Address)
}

func (c *Client) dialTLS(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.resolver.Address)
	if err != nil {
		return nil, err
	}
	tlsConn, err := tls.ClientHandshake(ctx, conn, c.tls)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (c *Client) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	c.closed = true
	// a handshake under way ends now
	c.cancel()
	if c.session != nil {
		c.session.close()
		c.session = nil
	}
	return nil
}
