package knock

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// SPA v3 (raycontrol docs/spec/spa-v3.md), neko: the address a knock goes to is under the tag (dst), and the node
// opens only for its own. The client:
//   - knocks v3 at any address of the node, a DNS answer included (§6 p. 1, 2): a knock caught at a forged address
//     opens nothing at the node (names.go takes such answers then);
//   - when v3 at an address of the node's signed data did not open it, sends v2 once more there (§6 p. 3: a node
//     rolled back to a version before v0.35.0), and keeps v2 for that address after it worked;
//   - never v2 at an address known only from DNS (§6 p. 4).

var (
	// the NAT64 prefix of the network in use, from the app (Android's LinkProperties.getNat64Prefix); nil: none
	nat64Prefix atomic.Pointer[netip.Prefix]
	// RFC 6052's well-known prefix, the one a node takes (spa-v3 §3)
	wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")
)

// SetNAT64Prefix sets the NAT64 prefix of the network in use ("" or an invalid one: none). An address in it, or in
// 64:ff9b::/96, is written to dst as the IPv4 it embeds (spa-v3 §3).
func SetNAT64Prefix(prefix string) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		nat64Prefix.Store(nil)
		return
	}
	p = p.Masked()
	nat64Prefix.Store(&p)
}

// DstOf is the address a v3 knock at addr names: the IPv4 a NAT64 address embeds, else addr without its zone.
func DstOf(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if !addr.Is6() {
		return addr
	}
	if wellKnownNAT64.Contains(addr) {
		v4, _ := embeddedIPv4(addr, 96)
		return v4
	}
	if p := nat64Prefix.Load(); p != nil && p.Contains(addr) {
		if v4, ok := embeddedIPv4(addr, p.Bits()); ok {
			return v4
		}
	}
	return addr
}

// embeddedIPv4 is the IPv4 address in an IPv4-embedded IPv6 address with a prefix of bits (RFC 6052 §2.2: bits
// 64-71 are left out).
func embeddedIPv4(addr netip.Addr, bits int) (netip.Addr, bool) {
	a := addr.As16()
	var v4 [4]byte
	switch bits {
	case 32:
		copy(v4[:], a[4:8])
	case 40:
		copy(v4[:3], a[5:8])
		v4[3] = a[9]
	case 48:
		copy(v4[:2], a[6:8])
		copy(v4[2:], a[9:11])
	case 56:
		v4[0] = a[7]
		copy(v4[1:], a[9:12])
	case 64:
		copy(v4[:], a[9:13])
	case 96:
		copy(v4[:], a[12:16])
	default:
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(v4), true
}

func spaVersionOf(dst netip.Addr) int {
	if dst.IsValid() {
		return 3
	}
	return 2
}

type spaV2Key struct{}

// withSPAv2: the knocks of this dial are v2 (the fallback of §6 p. 3)
func withSPAv2(ctx context.Context) context.Context {
	return context.WithValue(ctx, spaV2Key{}, true)
}

func spaV2From(ctx context.Context) bool {
	v2, _ := ctx.Value(spaV2Key{}).(bool)
	return v2
}

// signed reports whether addr is one of the node's signed addresses (node_addresses), the only ones v2 may follow a
// v3 that opened nothing at (§6 p. 3, 4). Without them nothing is: a node known by its name alone, whose addresses
// come from DNS (spa-v3 §5).
func (o *Outbound) signed(addr netip.Addr) bool {
	return o.signedAddrs != nil && o.signedAddrs.set[addr.Unmap()]
}

// detourTargets: SPA v3 through a detour knocks at the node's signed addresses, naming them, and never v2 at its
// name, which the detour's resolver would answer (spa-v3 §6, "the knock through a detour"); nil otherwise.
func (o *Outbound) detourTargets(destination M.Socksaddr) []M.Socksaddr {
	if !o.hasDetour || o.signedAddrs == nil || o.spa2 == nil || !o.spa2.v3 || !destination.IsFqdn() {
		return nil
	}
	targets := make([]M.Socksaddr, 0, len(o.signedAddrs.known))
	for _, addr := range o.signedAddrs.fallback(o.generation.Load()) {
		targets = append(targets, M.SocksaddrFrom(addr, destination.Port))
	}
	return targets
}

// spaDst is the dst of a knock at destination: none (v2) without v3, at a name, in a v2 dial, or at an address
// where only v2 opened.
func (o *Outbound) spaDst(ctx context.Context, destination M.Socksaddr) netip.Addr {
	if o.spa2 == nil || !o.spa2.v3 || !destination.IsIP() || spaV2From(ctx) {
		return netip.Addr{}
	}
	t := o.target(destination.AddrString())
	t.access.Lock()
	v2 := t.v2
	t.access.Unlock()
	if v2 {
		return netip.Addr{}
	}
	return DstOf(destination.Addr)
}

func (o *Outbound) setV2(destination M.Socksaddr, v2 bool) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	t.v2 = v2
	t.access.Unlock()
}

// dialSPA2 dials after SPA (dialSPA2Once); a v3 knock at an address of the signed data that opened nothing is
// followed by v2 at the same address, with the same carriers (spa-v3 §6 p. 3). An attempt with a deadline (one
// address of several) gives v3 half of it, so that a node rolled back is reached in the other half. v2 stays for
// that address only when v3 had its time and opened nothing; v3 that ran out of it (a slow network, the TCP
// carriers) is followed by v2 for this dial alone, and the next one knocks v3 again.
func (o *Outbound) dialSPA2(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !o.spaDst(ctx, destination).IsValid() || !o.signed(destination.Addr) {
		return o.dialSPA2Once(ctx, network, destination)
	}
	v3ctx, cancel := ctx, context.CancelFunc(func() {})
	if deadline, ok := ctx.Deadline(); ok {
		v3ctx, cancel = context.WithTimeout(ctx, time.Until(deadline)/2)
	}
	conn, err := o.dialSPA2Once(v3ctx, network, destination)
	outOfTime := v3ctx.Err() != nil
	cancel()
	if err == nil || ctx.Err() != nil {
		return conn, err
	}
	if outOfTime {
		o.logger.DebugContext(ctx, "SPA v3 ran out of its time at ", destination.AddrString(), ", v2 for this dial: ", err)
	} else {
		o.logger.InfoContext(ctx, "SPA v3 did not open ", destination.AddrString(), ", v2 once more (a node before raycontrol v0.35.0?): ", err)
		o.setV2(destination, true)
	}
	conn, v2err := o.dialSPA2Once(withSPAv2(ctx), network, destination)
	if v2err != nil {
		// neither: the next dial tries v3 again
		o.setV2(destination, false)
		return nil, err
	}
	if !outOfTime {
		o.logger.InfoContext(ctx, "SPA v2 opened ", destination.AddrString(), ": v2 there from now on")
	}
	return conn, nil
}

// TakesV3 reports whether the node of options takes SPA v3 (its versions, and lengths that fit the address): a
// request to it by name resolves the name and knocks at each address, never v2 at the name (SPAv2Packet).
func TakesV3(options SPAv2Options) bool {
	if !slices.Contains(options.Versions, 3) {
		return false
	}
	p, err := parseSPAv2(options)
	return err == nil && p.v3
}

// KnocksV3 reports whether a knock with options at host, outside an outbound (libcore's requests), is v3: the node
// takes it and host is an address.
func KnocksV3(options SPAv2Options, host string) bool {
	if !slices.Contains(options.Versions, 3) {
		return false
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil {
		return false
	}
	p, err := parseSPAv2(options)
	return err == nil && p.v3
}

// V2 is options that knock v2 alone: a request that v3 did not open at an address of the signed data tries it once
// (spa-v3 §6 p. 3).
func (o SPAv2Options) V2() SPAv2Options {
	o.Versions = nil
	return o
}
