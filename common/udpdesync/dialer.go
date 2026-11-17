package udpdesync

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func OptionsFrom(o *option.UDPDesyncOptions) (Options, error) {
	if o == nil {
		return Options{}, nil
	}
	if o.Prelude < 0 || o.Prelude > MaxPrelude {
		return Options{}, E.New("udp_desync: prelude must be 0-", MaxPrelude)
	}
	if o.PreludeTTL < 0 || o.PreludeTTL > 255 {
		return Options{}, E.New("udp_desync: prelude_ttl must be 0-255")
	}
	return Options{Prelude: o.Prelude, PreludeSNI: o.PreludeSNI, PreludeTTL: o.PreludeTTL, ReorderInitial: o.ReorderInitial}, nil
}

// Dialer wraps the UDP connections of a QUIC client.
type Dialer struct {
	N.Dialer
	options Options
	logger  logger.Logger
}

// WrapDialer returns dialer itself when nothing is enabled.
func WrapDialer(dialer N.Dialer, options Options, logger logger.Logger) N.Dialer {
	if !options.Enabled() {
		return dialer
	}
	return &Dialer{Dialer: dialer, options: options, logger: logger}
}

func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil || N.NetworkName(network) != N.NetworkUDP {
		return conn, err
	}
	return NewConn(conn, d.options, d.logger), nil
}

func (d *Dialer) Upstream() any { return d.Dialer }

// SocketDialer is for a QUIC client that takes the socket itself and writes to it past the core (Chromium through
// cronet, the naive outbound): no wrapper sees its datagrams. The prelude is sent on the socket before it is
// handed over, and the socket goes on as dialed. Reordering the Initials needs the datagrams themselves, so with it
// the connection returned hides its socket: the client is then left to relay through it.
type SocketDialer struct {
	N.Dialer
	options Options
	logger  logger.Logger
}

// WrapSocketDialer returns dialer itself when nothing is enabled.
func WrapSocketDialer(dialer N.Dialer, options Options, logger logger.Logger) N.Dialer {
	if !options.Enabled() {
		return dialer
	}
	return &SocketDialer{Dialer: dialer, options: options, logger: logger}
}

func (d *SocketDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil || N.NetworkName(network) != N.NetworkUDP {
		return conn, err
	}
	if d.options.ReorderInitial {
		return opaqueConn{NewConn(conn, d.options, d.logger)}, nil
	}
	sendPrelude(conn, d.options, d.logger)
	return conn, nil
}

func (d *SocketDialer) Upstream() any { return d.Dialer }

// opaqueConn has net.Conn's methods and no Upstream: who looks for the socket under it finds none.
type opaqueConn struct {
	net.Conn
}
