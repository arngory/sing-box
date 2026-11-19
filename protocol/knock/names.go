package knock

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// names-v1 (raycontrol docs/spec/names-v1.md §5), neko: the node is reached by its name, as a browser reaches a
// site, and its addresses are the fallback. The outbound resolves the name once per attempt and knocks and dials
// the same address. It knocks only at an address the node's signed data names (Options.NodeAddresses): a DNS answer
// outside them is taken as forged, since whoever forged it would get the knock and could replay it at the node
// (spa-v2 binds it to neither address), and the node's own addresses are used instead. So are they when the name
// does not resolve in time, the one that last answered on this network first.

const (
	// a lookup of the node's name holds an attempt this long at most (§5 p. 3)
	nodeLookupTimeout = 3 * time.Second
	// a dial to one of the node's addresses gives up after this long when another is left to try
	nodeDialTimeout = 5 * time.Second
)

// NodeResolver is a knock outbound with the node's addresses: what an outbound dialling through it (naive, whose
// Chromium resolves the name itself) takes for the node's name. ok is false without node_addresses.
type NodeResolver interface {
	ResolveNode(ctx context.Context, name string) (addresses []netip.Addr, ok bool)
}

var _ NodeResolver = (*Outbound)(nil)

type nodeAddresses struct {
	known []netip.Addr
	set   map[netip.Addr]bool

	access sync.Mutex
	// the address a dial last went through, and the network it was on (Outbound.generation)
	lastGood           netip.Addr
	lastGoodGeneration uint64
	// the name last resolved: the knock's server_name for a destination given as an address (naive)
	name string
}

func parseNodeAddresses(addresses []string) (*nodeAddresses, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	n := &nodeAddresses{set: map[netip.Addr]bool{}}
	for _, raw := range addresses {
		addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(raw), "[]"))
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
			return nil, E.New("knock: node_addresses: not an address: ", raw)
		}
		addr = addr.Unmap()
		if !n.set[addr] {
			n.set[addr] = true
			n.known = append(n.known, addr)
		}
	}
	return n, nil
}

// fallback: the node's own addresses, the one that last answered on this network first
func (n *nodeAddresses) fallback(generation uint64) []netip.Addr {
	n.access.Lock()
	last, lastGeneration := n.lastGood, n.lastGoodGeneration
	n.access.Unlock()
	if !last.IsValid() || lastGeneration != generation {
		return slices.Clone(n.known)
	}
	return append([]netip.Addr{last}, slices.DeleteFunc(slices.Clone(n.known), func(addr netip.Addr) bool {
		return addr == last
	})...)
}

func (n *nodeAddresses) answered(addr netip.Addr, generation uint64) {
	n.access.Lock()
	n.lastGood, n.lastGoodGeneration = addr.Unmap(), generation
	n.access.Unlock()
}

func (n *nodeAddresses) resolved(name string) {
	n.access.Lock()
	n.name = name
	n.access.Unlock()
}

func (n *nodeAddresses) serverName() string {
	n.access.Lock()
	defer n.access.Unlock()
	return n.name
}

// ResolveNode resolves the node's name once for an attempt: the addresses of the answer that are the node's, in
// the answer's order; else the node's own (§5 p. 3–5).
func (o *Outbound) ResolveNode(ctx context.Context, name string) ([]netip.Addr, bool) {
	n := o.node
	if n == nil {
		return nil, false
	}
	name = strings.TrimSuffix(name, ".")
	n.resolved(name)
	lookupCtx, cancel := context.WithTimeout(ctx, nodeLookupTimeout)
	answer, err := o.lookup(lookupCtx, name)
	cancel()
	var addresses []netip.Addr
	for _, addr := range answer {
		addr = addr.Unmap()
		if n.set[addr] && !slices.Contains(addresses, addr) {
			addresses = append(addresses, addr)
		}
	}
	if len(addresses) > 0 {
		return addresses, true
	}
	switch {
	case err != nil:
		o.logger.WarnContext(ctx, "names: ", name, " did not resolve (", err, "), the node's own addresses instead")
	case len(answer) == 0:
		o.logger.WarnContext(ctx, "names: no address for ", name, ", the node's own addresses instead")
	default:
		o.logger.WarnContext(ctx, "names: DNS answered ", answer, " for ", name,
			", none of the node's addresses: taken as forged, the knock goes to the node's own")
	}
	return n.fallback(o.generation.Load()), true
}

// nodeTargets: the addresses of one attempt at the node, and the name they are for ("" for an address). An address
// given by whoever resolved the name before (a DNS server's domain_resolver) is taken when it is the node's.
func (o *Outbound) nodeTargets(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, string) {
	var addresses []netip.Addr
	name := ""
	if destination.IsFqdn() {
		name = strings.TrimSuffix(destination.Fqdn, ".")
		addresses, _ = o.ResolveNode(ctx, name)
	} else if addr := destination.Addr.Unmap(); o.node.set[addr] {
		addresses = []netip.Addr{addr}
	} else {
		o.logger.WarnContext(ctx, "names: ", addr, " is none of the node's addresses (a forged answer to whoever "+
			"resolved its name): the knock goes to the node's own")
		addresses = o.node.fallback(o.generation.Load())
	}
	targets := make([]M.Socksaddr, 0, len(addresses))
	for _, addr := range addresses {
		targets = append(targets, M.SocksaddrFrom(addr, destination.Port))
	}
	return targets, name
}

// dialNode dials the node's addresses of this attempt in turn, each but the last for nodeDialTimeout at most
func (o *Outbound) dialNode(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	targets, name := o.nodeTargets(ctx, destination)
	ctx = o.withServerName(ctx, name)
	var lastErr error
	for i, target := range targets {
		dialCtx, cancel := ctx, context.CancelFunc(func() {})
		if i < len(targets)-1 {
			dialCtx, cancel = context.WithTimeout(ctx, nodeDialTimeout)
		}
		conn, err := o.dialResolved(dialCtx, network, target)
		cancel()
		if err == nil {
			// a UDP socket says nothing of the node: only a TCP connection marks the address that answers
			if N.NetworkName(network) == N.NetworkTCP {
				o.node.answered(target.Addr, o.generation.Load())
			}
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
		if i < len(targets)-1 {
			o.logger.DebugContext(ctx, "names: ", target.AddrString(), " did not answer, the next address: ", err)
		}
	}
	if lastErr == nil {
		lastErr = E.New("knock: no address for ", destination)
	}
	return nil, lastErr
}

type serverNameKey struct{}

// withServerName: the name the knock's ClientHello carries (§5 p. 6); the name last resolved for an address
func (o *Outbound) withServerName(ctx context.Context, name string) context.Context {
	if name == "" && o.node != nil {
		name = o.node.serverName()
	}
	if name == "" {
		return ctx
	}
	return context.WithValue(ctx, serverNameKey{}, name)
}

func serverNameFrom(ctx context.Context) string {
	name, _ := ctx.Value(serverNameKey{}).(string)
	return name
}
