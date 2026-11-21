package knock

import (
	"context"
	"errors"
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

// v2 at an address of the signed data costs nothing v3 would keep: whoever is on the path to that address can
// replay a knock there either way (spa-v3 §8), and a node takes v2 always (§4). So where v2 opened after v3 did not,
// the address keeps it for a while, the attempt's time saved. After that a dial knocks v3 alone again (and a v3 that
// opens clears the mark), while renewals of access in use send v2 beside v3, which they cannot check (hadV2).
const (
	// how long v2 stays at an address where v3 had its time and opened nothing, and v2 then did (a node rolled back)
	spa3V2Hold = time.Hour
	// the same where v3 ran out of its time first: a node that drops the SYN looks like a slow network, so the
	// evidence is weaker and v3 is tried again sooner
	spa3V2HoldShort = 10 * time.Minute
)

// spaDst is the dst of a knock at destination: none (v2) without v3, at a name, in a v2 dial, or at an address
// where v2 opened lately on this network.
func (o *Outbound) spaDst(ctx context.Context, destination M.Socksaddr) netip.Addr {
	if o.spa2 == nil || !o.spa2.v3 || !destination.IsIP() || spaV2From(ctx) {
		return netip.Addr{}
	}
	t := o.target(destination.AddrString())
	t.access.Lock()
	v2 := time.Now().Before(t.v2Until) && t.v2Generation == o.generation.Load()
	t.access.Unlock()
	if v2 {
		return netip.Addr{}
	}
	return DstOf(destination.Addr)
}

type renewalKey struct{}

// withRenewal: a knock that renews access in use (spa2.go scheduleRenewal, renewInUse), not one before a dial
func withRenewal(ctx context.Context) context.Context {
	return context.WithValue(ctx, renewalKey{}, true)
}

func renewalFrom(ctx context.Context) bool {
	renewal, _ := ctx.Value(renewalKey{}).(bool)
	return renewal
}

// sentV2 records a v2 packet sent at destination on a node that takes v3.
func (o *Outbound) sentV2(destination M.Socksaddr) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	t.lastV2At, t.lastV2Generation = time.Now(), o.generation.Load()
	t.access.Unlock()
}

// v3Alone clears destination's v2 mark after a dial on the v3 path opened: only when no v2 packet went there on this
// network within the access time, so that the access it used was v3's alone (a dial on access a v2 knock opened,
// cached, proves nothing), and the node takes v3 again.
func (o *Outbound) v3Alone(destination M.Socksaddr) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	recentV2 := t.lastV2Generation == o.generation.Load() && time.Since(t.lastV2At) < o.ttl
	if !t.v2Until.IsZero() && !recentV2 {
		t.v2Until = time.Time{}
	}
	t.access.Unlock()
}

// hadV2 reports whether v2 opened destination before on this network (its hold may have run out since).
func (o *Outbound) hadV2(destination M.Socksaddr) bool {
	t := o.target(destination.AddrString())
	t.access.Lock()
	defer t.access.Unlock()
	return !t.v2Until.IsZero() && t.v2Generation == o.generation.Load()
}

// markV2 keeps v2 at destination for hold (0: v3 again).
func (o *Outbound) markV2(destination M.Socksaddr, hold time.Duration) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	if hold > 0 {
		t.v2Until, t.v2Generation = time.Now().Add(hold), o.generation.Load()
	} else {
		t.v2Until = time.Time{}
	}
	t.access.Unlock()
}

// dialSPA2 dials after SPA (dialSPA2Once); a v3 knock at an address of the signed data that opened nothing is
// followed by v2 at the same address, with the same carriers (spa-v3 §6 p. 3). An attempt with a deadline (one
// address of several) gives v3 half of it, so that a node rolled back is reached in the other half. Where v2 then
// opens, the address keeps it for a while (spa3V2Hold, shorter when v3 only ran out of time), then v3 again.
func (o *Outbound) dialSPA2(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !o.spaDst(ctx, destination).IsValid() || !o.signed(destination.Addr) {
		return o.dialSPA2Once(ctx, network, destination)
	}
	// one attempt of two halves: a failed v3 half is not a failed round of its own (v2 goes on from it)
	v3ctx, cancel := withRoundGoesOn(ctx), context.CancelFunc(func() {})
	if deadline, ok := ctx.Deadline(); ok {
		v3ctx, cancel = context.WithTimeout(v3ctx, time.Until(deadline)/2)
	}
	conn, err := o.dialSPA2Once(v3ctx, network, destination)
	outOfTime := v3ctx.Err() != nil
	cancel()
	if err == nil {
		o.v3Alone(destination)
		return conn, nil
	}
	if ctx.Err() != nil {
		// no v2 half after it: the v3 half was the attempt, and it counts as forgetBefore would count it
		if !errors.Is(ctx.Err(), context.Canceled) {
			o.rounds.failed(destination.AddrString(), time.Now(), time.Now())
		}
		return nil, err
	}
	o.logger.InfoContext(ctx, "SPA v3 did not open ", destination.AddrString(), ", v2 once more (a node before raycontrol v0.35.0?): ", err)
	// the dial's own v2 (withSPAv2); the mark, for the dials meanwhile and after, only once v2 has opened
	conn, v2err := o.dialSPA2Once(withSPAv2(ctx), network, destination)
	if v2err != nil {
		return nil, err
	}
	hold := spa3V2Hold
	if outOfTime {
		hold = spa3V2HoldShort
	}
	o.markV2(destination, hold)
	o.logger.InfoContext(ctx, "SPA v2 opened ", destination.AddrString(), ": v2 there for ", hold)
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
