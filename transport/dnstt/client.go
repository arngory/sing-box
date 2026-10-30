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
)

// Resolver is where the DNS queries go: a DoH URL, or a DoT or UDP host:port.
type Resolver struct {
	Kind    ResolverKind
	URL     string // DoH
	Address M.Socksaddr
}

// ParseResolver reads "https://host/dns-query", "tls://host[:853]" or "udp://host[:53]"
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
	default:
		return Resolver{}, E.New("unknown resolver scheme ", parsed.Scheme, " (expected https, tls or udp)")
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
}

type Client struct {
	ctx      context.Context
	logger   logger.ContextLogger
	dialer   N.Dialer
	domain   dns.Name
	pubkey   []byte
	resolver Resolver
	tls      tls.Config
	mtu      int

	access  sync.Mutex
	session *session
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
	// clientid + padding length prefix + padding + data length prefix
	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return nil, E.New("domain ", options.Domain, " leaves only ", mtu, " bytes for the payload")
	}
	return &Client{
		ctx:      options.Context,
		logger:   options.Logger,
		dialer:   options.Dialer,
		domain:   domain,
		pubkey:   pubkey,
		resolver: options.Resolver,
		tls:      options.TLSConfig,
		mtu:      mtu,
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
	defer c.access.Unlock()
	if c.session != nil && !c.session.smux.IsClosed() {
		return c.session, nil
	}
	if c.session != nil {
		c.session.close()
		c.session = nil
	}
	session, err := c.newSession(ctx)
	if err != nil {
		return nil, err
	}
	c.session = session
	return session, nil
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
	packetConn := newDNSPacketConn(transport, remoteAddr, c.domain, c.logger)
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
	noiseConn, err := noise.NewClient(kcpConn, c.pubkey)
	if err != nil {
		kcpConn.Close()
		packetConn.Close()
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
	if c.session != nil {
		c.session.close()
		c.session = nil
	}
	return nil
}
