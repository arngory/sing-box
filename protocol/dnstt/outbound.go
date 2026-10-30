//go:build with_dnstt

package dnstt

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DNSTTOutboundOptions](registry, C.TypeDNSTT, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound opens a dnstt stream for every TCP connection. The dnstt server decides
// where streams go, so the destination is not sent: put the real proxy protocol of
// that upstream on top with a detour to this outbound.
type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *dnstt.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DNSTTOutboundOptions) (adapter.Outbound, error) {
	resolver, err := dnstt.ParseResolver(options.Resolver)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, resolver.Address.IsDomain())
	if err != nil {
		return nil, err
	}
	var tlsConfig tls.Config
	if resolver.Kind != dnstt.ResolverUDP {
		tlsOptions := common.PtrValueOrDefault(options.TLS)
		tlsOptions.Enabled = true
		if tlsOptions.ServerName == "" && resolver.Address.IsDomain() {
			tlsOptions.ServerName = resolver.Address.Fqdn
		}
		tlsConfig, err = tls.NewClient(ctx, logger, resolver.Address.AddrString(), tlsOptions)
		if err != nil {
			return nil, E.Cause(err, "resolver TLS")
		}
		if resolver.Kind == dnstt.ResolverDoH {
			// net/http here speaks HTTP/1.1 over the dialed TLS conn
			tlsConfig.SetNextProtos([]string{"http/1.1"})
		}
	}
	client, err := dnstt.NewClient(dnstt.ClientOptions{
		Context:   ctx,
		Logger:    logger,
		Dialer:    outboundDialer,
		Domain:    options.Domain,
		PubKey:    options.PublicKey,
		Resolver:  resolver,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDNSTT, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("dnstt: ", network, " is not supported")
	}
	h.logger.InfoContext(ctx, "outbound connection through the dnstt upstream (requested ", destination, ")")
	return h.client.DialConn(ctx)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("dnstt: UDP is not supported")
}

func (h *Outbound) Close() error {
	return h.client.Close()
}
