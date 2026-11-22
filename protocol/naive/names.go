//go:build with_naive_outbound

package naive

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// nodeResolver is protocol/knock.NodeResolver (names-v1)
type nodeResolver interface {
	ResolveNode(ctx context.Context, name string) (addresses []netip.Addr, ok bool)
	HasNode() bool
}

// nodeDialer: the server's name dialled through the knock outbound (detour) as it is, when that knock has the node's
// addresses: the knock resolves it (names-v1), the node's own addresses when the name does not resolve. Through the
// resolving dialer the name was looked up first, and a lookup that failed failed the dial, the knock never asked
// (neko: naive alone of the node's ways went down on a network where the node's name did not resolve). Anything else,
// and a detour that is not such a knock, through the resolving dialer as before.
type nodeDialer struct {
	N.Dialer
	outbounds adapter.OutboundManager
	detour    string
	name      string
}

func newNodeDialer(ctx context.Context, resolving N.Dialer, detour string, server M.Socksaddr) N.Dialer {
	outbounds := service.FromContext[adapter.OutboundManager](ctx)
	if detour == "" || !server.IsFqdn() || outbounds == nil {
		return resolving
	}
	return &nodeDialer{resolving, outbounds, detour, strings.ToLower(strings.TrimSuffix(server.Fqdn, "."))}
}

// knock: the detour, when it is a knock with the node's addresses and destination is the node's name; looked up for
// each dial (the outbounds start after this one is made)
func (d *nodeDialer) knock(destination M.Socksaddr) N.Dialer {
	if !destination.IsFqdn() || strings.ToLower(strings.TrimSuffix(destination.Fqdn, ".")) != d.name {
		return nil
	}
	outbound, loaded := d.outbounds.Outbound(d.detour)
	if !loaded {
		return nil
	}
	if resolver, isResolver := outbound.(nodeResolver); !isResolver || !resolver.HasNode() {
		return nil
	}
	return outbound
}

func (d *nodeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if knock := d.knock(destination); knock != nil {
		return knock.DialContext(ctx, network, destination)
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d *nodeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if knock := d.knock(destination); knock != nil {
		return knock.ListenPacket(ctx, destination)
	}
	return d.Dialer.ListenPacket(ctx, destination)
}

// nodeAnswerTTL: Chromium keeps the answer for an attempt's connection, the next attempt resolves again
const nodeAnswerTTL = 1

// nodeResolverFor answers Chromium's A and AAAA queries for the server's name from the knock outbound it is dialled
// through (detour), when that knock has the node's addresses (neko); nil for any other query
func nodeResolverFor(ctx context.Context, detour string, server M.Socksaddr) func(context.Context, *mDNS.Msg) *mDNS.Msg {
	if detour == "" || !server.IsFqdn() {
		return func(context.Context, *mDNS.Msg) *mDNS.Msg { return nil }
	}
	name := strings.ToLower(strings.TrimSuffix(server.Fqdn, "."))
	outboundManager := service.FromContext[adapter.OutboundManager](ctx)
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		if outboundManager == nil || len(request.Question) != 1 {
			return nil
		}
		question := request.Question[0]
		if question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA ||
			strings.ToLower(strings.TrimSuffix(question.Name, ".")) != name {
			return nil
		}
		// looked up for each query: the outbounds start after this one is made
		outbound, loaded := outboundManager.Outbound(detour)
		if !loaded {
			return nil
		}
		resolver, isResolver := outbound.(nodeResolver)
		if !isResolver {
			return nil
		}
		addresses, ok := resolver.ResolveNode(ctx, name)
		if !ok {
			return nil
		}
		return dns.FixedResponse(request.Id, question, addresses, nodeAnswerTTL)
	}
}
