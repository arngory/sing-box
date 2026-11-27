package slipstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/sagernet/quic-go"
)

// ClientOptions configures the native Go Slipstream (QUIC-over-DNS) client (Variant B).
type ClientOptions struct {
	Domain     string
	Resolvers  []string
	Pin        string
	ALPN       string
	ServerName string
	Auth       *AuthConfig
}

// Client manages a native Go QUIC session tunneled over DNS TXT packets.
type Client struct {
	opts ClientOptions
	pc   *DNSPacketConn
	tr   *quic.Transport
	conn *quic.Conn
}

// Dial establishes a pinned QUIC connection tunneled over DNS resolvers.
func Dial(ctx context.Context, opts ClientOptions) (*Client, error) {
	if opts.Domain == "" || len(opts.Resolvers) == 0 || opts.Pin == "" || opts.ALPN == "" || opts.ServerName == "" {
		return nil, errors.New("slipstream: incomplete client options")
	}
	addrs := make([]*net.UDPAddr, 0, len(opts.Resolvers))
	for _, r := range opts.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, "53")
		}
		addr, err := net.ResolveUDPAddr("udp", r)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	udpConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	dnsPC, err := NewDNSPacketConn(udpConn, addrs, opts.Domain, opts.Auth)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName:         opts.ServerName,
		NextProtos:         []string{opts.ALPN},
		InsecureSkipVerify: true, // Pinning replaces WebPKI chain validation per slipstream-v1.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("slipstream: server sent no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			return VerifySPKIPin(cert, opts.Pin)
		},
	}

	tr := &quic.Transport{Conn: dnsPC}
	qCfg := &quic.Config{
		InitialPacketSize: 1200,
		MaxIdleTimeout:    30 * time.Second,
		KeepAlivePeriod:   10 * time.Second,
	}
	qConn, err := tr.Dial(ctx, addrs[0], tlsCfg, qCfg)
	if err != nil {
		_ = tr.Close()
		_ = dnsPC.Close()
		return nil, err
	}
	return &Client{opts: opts, pc: dnsPC, tr: tr, conn: qConn}, nil
}

// OpenStream opens a bidirectional stream inside the QUIC-over-DNS tunnel.
func (c *Client) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return c.conn.OpenStreamSync(ctx)
}

// Close tears down the QUIC session and underlying DNS packet transport.
func (c *Client) Close() error {
	var firstErr error
	if c.conn != nil {
		firstErr = c.conn.CloseWithError(0, "closed")
	}
	if c.tr != nil {
		if err := c.tr.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.pc != nil {
		if err := c.pc.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
