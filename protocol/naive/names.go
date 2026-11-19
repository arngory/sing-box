//go:build with_naive_outbound

package naive

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// nodeResolver is protocol/knock.NodeResolver (names-v1)
type nodeResolver interface {
	ResolveNode(ctx context.Context, name string) (addresses []netip.Addr, ok bool)
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
