// Package knock implements a port knocking outbound.
//
// The outbound is used as the `detour` of a proxy outbound. Before dialing the
// proxy server it sends a sequence of TCP SYNs / UDP datagrams to the same host,
// so a knockd-style firewall opens the real port for this client. A "spa" step
// sends one authenticated, non-replayable datagram instead (spa.go); "spa1m" the same with the
// time masked.
//
// A knock is repeated when the session breaks: after a default network change
// (new client address), when a dial fails on a cached knock, and once per
// silence episode when a connection gets no reply for `silence` after sending.
package knock

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const TypeKnock = "knock"

const (
	maxSteps        = 32
	defaultInterval = 200 * time.Millisecond
	defaultTTL      = 10 * time.Second
	maxPayload      = 1024
	// lower bound between forced knocks to the same host
	minReknockGap = 2 * time.Second
	// After a round of knocks that a dial did not get through (the node down, its port shut, the access refused), the
	// next round to that address waits: 2 s, then twice as long each time, at most 30 s. It spares the node's quotas
	// and the neighbours behind one CGNAT address, who share its rate limit. A dial through, another network or a
	// quiet minute starts it over (roundBook).
	minRoundGap = 2 * time.Second
	maxRoundGap = 30 * time.Second
	roundQuiet  = time.Minute
	// A TCP knock is abandoned before the kernel retransmits its SYN (initial
	// RTO is 1s): knockd counts any TCP packet, and a late SYN to the previous
	// port resets the sequence. The floor leaves time for protect() + connect().
	minTCPAttempt = 100 * time.Millisecond
	maxTCPAttempt = 800 * time.Millisecond
	// time for the server to run its start command before the real connection
	minSettle = 150 * time.Millisecond
)

// what the reference `knock` client sends to a UDP port
var defaultUDPPayload = []byte{0}

type Step struct {
	Port    uint16 `json:"port"`
	Network string `json:"network,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type Options struct {
	option.DialerOptions
	Sequence []Step             `json:"sequence"`
	Interval badoption.Duration `json:"interval,omitempty"`
	TTL      badoption.Duration `json:"ttl,omitempty"`
	// Silence re-knocks once when a connection gets no reply this long after
	// sending. Zero disables it.
	Silence badoption.Duration `json:"silence,omitempty"`
	// SPAv2 replaces the sequence with raycontrol SPA v2 (spa2.go).
	SPAv2 *SPAv2Options `json:"spa_v2,omitempty"`
	// UDPPorts: UDP services of the node whose port rotates (udpports.go), SPA v2 only.
	UDPPorts []UDPPortSchedule `json:"udp_ports,omitempty"`
	// Hosts, when set, are the only ones knocked at (names or addresses); everything else is dialled plainly. A
	// name also covers the addresses it resolves to with this outbound's resolver, since a caller may resolve it
	// before dialling (a DNS server's domain_resolver, yggdrasil-go's quic://). A Yggdrasil endpoint dials the node
	// and, as a fallback, the node's public peers through this outbound: the peers must never get its SPA.
	Hosts []string `json:"hosts,omitempty"`
	// NodeAddresses: names-v1 (names.go), the node's addresses from its signed data. A name dialled through this
	// outbound is resolved once per attempt and knocked and dialled at an address of the answer only if it is one of
	// them; else, and when the name does not resolve, at these. Ignored with a detour, which resolves the name.
	NodeAddresses []string `json:"node_addresses,omitempty"`
}

func Register(registry *outbound.Registry) {
	outbound.Register[Options](registry, TypeKnock, New)
}

type step struct {
	port    uint16
	udp     bool
	payload []byte
	// a Niko SPA v1 key: the datagram is built for each knock (spa.go)
	spaKey []byte
	// spaMasked: SPA v1m, the time masked (spa.go)
	spaMasked bool
}

// target is the knock state of one server address. The lock only guards the
// fields; it is never held while knocking.
type target struct {
	access    sync.Mutex
	lastKnock time.Time
	// the last knock over each SPA v2 carrier (reknock)
	lastByCarrier [3]time.Time
	generation    uint64
	inflight      chan struct{}
	// SPA v2: the access is renewed while the host is in use
	lastUse time.Time
	active  int
	renew   *time.Timer
	// SPA v3: v2 opened this address of the signed data after v3 did not (spa-v3 §6 p. 3): its knocks are v2 until
	// v2Until on that network (v2Generation), then v3 is tried again
	v2Until      time.Time
	v2Generation uint64
	// the last v2 packet sent here on a node that takes v3 (alone in a hold, beside v3 after it, a fallback's) and
	// its network: access it opened is v2's, so a dial on it proves nothing of v3 (v3Alone)
	lastV2At         time.Time
	lastV2Generation uint64
	// the last dial through after a knock of this outbound (passed)
	passedAt time.Time
}

// roundBook holds the failed rounds of knocks to each address for all the knock outbounds of a box: the node's quota
// of knocks per device and its rate limit count every outbound's knocks, the profiles' and the tests' alike. Locked
// after a target's lock, never before. A nil book keeps nothing.
type roundBook struct {
	access sync.Mutex
	hosts  map[string]*rounds
	// a network change (any outbound's) starts every count over
	network uint64
}

// rounds: the rounds that failed in a row to one address on one network, the last at lastFailed; the next starts no
// sooner than next.
type rounds struct {
	failed     int
	network    uint64
	lastFailed time.Time
	next       time.Time
}

// roundBookAccess orders the outbounds of a box looking for their book.
var roundBookAccess sync.Mutex

// roundBookFrom is the box's book, made by its first knock outbound; without a registry in ctx, a book of its own.
func roundBookFrom(ctx context.Context) *roundBook {
	roundBookAccess.Lock()
	defer roundBookAccess.Unlock()
	if book := service.PtrFromContext[roundBook](ctx); book != nil {
		return book
	}
	book := &roundBook{hosts: make(map[string]*rounds)}
	if service.RegistryFromContext(ctx) != nil {
		service.MustRegisterPtr(ctx, book)
	}
	return book
}

// failed counts a round to host, its knock sent at knockedAt, as failed and sets when the next may start.
func (b *roundBook) failed(host string, knockedAt, now time.Time) {
	if b == nil {
		return
	}
	b.access.Lock()
	defer b.access.Unlock()
	r := b.hosts[host]
	if r == nil {
		r = &rounds{}
		b.hosts[host] = r
	}
	if r.network != b.network || now.Sub(r.lastFailed) > roundQuiet {
		r.failed = 0
	}
	r.network, r.lastFailed = b.network, now
	r.failed++
	gap := maxRoundGap
	if r.failed <= 5 {
		gap = min(minRoundGap<<(r.failed-1), maxRoundGap)
	}
	r.next = knockedAt.Add(gap)
}

// passed: a dial to host got through after a knock; its next failure counts from one.
func (b *roundBook) passed(host string) {
	if b == nil {
		return
	}
	b.access.Lock()
	delete(b.hosts, host)
	b.access.Unlock()
}

// wait is how long a new round to host must wait, and how many failed before it.
func (b *roundBook) wait(host string, now time.Time) (time.Duration, int) {
	if b == nil {
		return 0, 0
	}
	b.access.Lock()
	defer b.access.Unlock()
	r := b.hosts[host]
	if r == nil || r.network != b.network {
		return 0, 0
	}
	return r.next.Sub(now), r.failed
}

// newNetwork starts every count over.
func (b *roundBook) newNetwork() {
	if b == nil {
		return
	}
	b.access.Lock()
	b.network++
	clear(b.hosts)
	b.access.Unlock()
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	logger         logger.ContextLogger
	dialer         N.Dialer
	hasDetour      bool
	domainResolver *option.DomainResolveOptions
	steps          []step
	spa2           *spa2Params
	udpPorts       map[uint16]*portSchedule
	// the SPA v2 carrier that opened the node on this network (spa-v2.md §10); the first of carriers again on a
	// network change
	spa2Carrier atomic.Int32
	carriers    []Carrier
	interval    time.Duration
	ttl         time.Duration
	silence     time.Duration

	// bumped on network changes, knocks of an older generation are stale
	generation atomic.Uint64

	access  sync.Mutex
	targets map[string]*target
	// the failed rounds of the box's knock outbounds (roundBook)
	rounds *roundBook
	// TCP connections to a node still waiting for its first bytes (handshakes.go)
	handshakes handshakeGate

	// the only hosts knocked at (Options.Hosts); nil: all
	hosts *knockHosts
	// the node's addresses (Options.NodeAddresses, names.go); nil: names are resolved as any other
	node *nodeAddresses
	// the node's signed addresses (node_addresses) with or without a detour: SPA v3 knocks at them through one, and
	// only at them does v2 follow a v3 that opened nothing (spa3.go)
	signedAddrs *nodeAddresses
	// tests: the dial after the knock (a node that drops the SYN until the right knock)
	testDialPeer func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

// knockHosts: Options.Hosts, names in lower case and addresses, with what the names resolved to
type knockHosts struct {
	names map[string]bool
	addrs map[netip.Addr]bool

	access  sync.Mutex
	lookups map[string]*hostLookup
}

type hostLookup struct {
	// what the name resolved to last; a failed lookup keeps them (the node's addresses stay knocked at)
	addrs []netip.Addr
	// the last successful lookup, and the last one at all
	resolved, tried time.Time
	// closed when the running lookup ends: the dials that wait take its result
	inflight chan struct{}
}

const (
	// what a listed name resolved to counts this long for an address it does not hold
	hostLookupTTL = 5 * time.Minute
	// an address matching none of them looks the names up again, at most this often
	hostLookupRetry = 10 * time.Second
	// a lookup holds a dial this long at most (the name may be what this network drops)
	hostLookupTimeout = 3 * time.Second
)

func parseHosts(hosts []string) *knockHosts {
	if len(hosts) == 0 {
		return nil
	}
	h := &knockHosts{names: map[string]bool{}, addrs: map[netip.Addr]bool{}, lookups: map[string]*hostLookup{}}
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
		if host == "" {
			continue
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			h.addrs[addr.Unmap()] = true
		} else {
			h.names[host] = true
		}
	}
	return h
}

// plain: a destination outside Options.Hosts, dialled without a knock. An address is matched against the listed
// addresses and what the listed names resolve to; a name that does not resolve covers nothing
func (o *Outbound) plain(ctx context.Context, destination M.Socksaddr) bool {
	h := o.hosts
	if h == nil {
		return false
	}
	if destination.IsFqdn() {
		return !h.names[strings.ToLower(strings.TrimSuffix(destination.Fqdn, "."))]
	}
	addr := destination.Addr.Unmap()
	// nothing to knock at (ListenPacket on 0.0.0.0) is left to the dial path, as without a list
	if !addr.IsValid() || addr.IsUnspecified() || h.addrs[addr] {
		return false
	}
	for name := range h.names {
		if slices.Contains(o.hostAddrs(ctx, name, addr), addr) {
			return false
		}
	}
	return true
}

// hostAddrs: what the listed name resolves to, from the cache while it holds [want] and is fresh, or was looked up
// less than hostLookupRetry ago; otherwise looked up again, one lookup per name at a time. A failed lookup keeps
// the addresses of the last good one
func (o *Outbound) hostAddrs(ctx context.Context, name string, want netip.Addr) []netip.Addr {
	h := o.hosts
	h.access.Lock()
	l := h.lookups[name]
	if l == nil {
		l = &hostLookup{}
		h.lookups[name] = l
	}
	if !l.tried.IsZero() && (time.Since(l.tried) < hostLookupRetry ||
		time.Since(l.resolved) < hostLookupTTL && slices.Contains(l.addrs, want)) {
		addrs := l.addrs
		h.access.Unlock()
		return addrs
	}
	if wait := l.inflight; wait != nil {
		h.access.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
		}
		h.access.Lock()
		addrs := l.addrs
		h.access.Unlock()
		return addrs
	}
	done := make(chan struct{})
	l.inflight = done
	h.access.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, hostLookupTimeout)
	resolved, err := o.lookup(lookupCtx, name)
	cancel()
	if err != nil {
		o.logger.DebugContext(ctx, "knock: resolve ", name, ": ", err)
	}

	h.access.Lock()
	defer h.access.Unlock()
	now := time.Now()
	l.tried = now
	if err == nil && len(resolved) > 0 {
		// a copy: the resolver's slice may be its cache
		addrs := make([]netip.Addr, 0, len(resolved))
		for _, addr := range resolved {
			addrs = append(addrs, addr.Unmap())
		}
		l.addrs, l.resolved = addrs, now
	}
	l.inflight = nil
	close(done)
	return l.addrs
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	var (
		steps []step
		spa2  *spa2Params
		err   error
	)
	if options.SPAv2 != nil {
		if len(options.Sequence) > 0 {
			return nil, E.New("knock: spa_v2 and sequence are exclusive")
		}
		spa2, err = parseSPAv2(*options.SPAv2)
	} else {
		steps, err = parseSequence(options.Sequence)
	}
	if err != nil {
		return nil, err
	}
	udpPorts, err := parseUDPPorts(options.UDPPorts, spa2)
	if err != nil {
		return nil, err
	}
	node, err := parseNodeAddresses(options.NodeAddresses)
	if err != nil {
		return nil, err
	}
	signedAddrs := node
	if options.Detour != "" {
		// through a detour (a chain's later hop, a mesh) the name is the detour's to resolve, as resolve() leaves
		// it: a lookup here would ask the local network for the node behind the chain (neko)
		node = nil
	}
	interval := time.Duration(options.Interval)
	if interval <= 0 {
		interval = defaultInterval
	}
	ttl := time.Duration(options.TTL)
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if spa2 != nil {
		// the server's window; renewals (spa2.go) keep it open while in use
		ttl = spa2.access() * 9 / 10
	}
	silence := time.Duration(options.Silence)
	if silence < 0 {
		silence = 0
	}
	// Without a detour the server address is resolved here, so that the knocks
	// and the real connection go to the same IP.
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	// SPA v2: the carriers the node takes, in their order (UDP for port knocking and SPA v1)
	carriers := []Carrier{CarrierUDP}
	if options.SPAv2 != nil {
		carriers = options.SPAv2.CarrierOrder()
	}
	o := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(TypeKnock, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:            ctx,
		logger:         logger,
		dialer:         outboundDialer,
		hasDetour:      options.Detour != "",
		domainResolver: options.DomainResolver,
		steps:          steps,
		spa2:           spa2,
		udpPorts:       udpPorts,
		interval:       interval,
		ttl:            ttl,
		silence:        silence,
		hosts:          parseHosts(options.Hosts),
		node:           node,
		signedAddrs:    signedAddrs,
		targets:        make(map[string]*target),
		rounds:         roundBookFrom(ctx),
		carriers:       carriers,
	}
	o.spa2Carrier.Store(int32(carriers[0]))
	return o, nil
}

func parseSequence(sequence []Step) ([]step, error) {
	if len(sequence) == 0 {
		return nil, E.New("knock: empty sequence")
	}
	if len(sequence) > maxSteps {
		return nil, E.New("knock: too many steps: ", len(sequence))
	}
	steps := make([]step, 0, len(sequence))
	for i, s := range sequence {
		if s.Port == 0 {
			return nil, E.New("knock: step ", i+1, ": missing port")
		}
		var parsed step
		parsed.port = s.Port
		switch strings.ToLower(s.Network) {
		case "", N.NetworkTCP:
		case N.NetworkUDP:
			parsed.udp = true
		case "spa", "spa1m":
			parsed.udp = true
			key, err := hex.DecodeString(s.Payload)
			if err != nil || len(key) != spaKeySize {
				return nil, E.New("knock: step ", i+1, ": spa needs a 32-byte hex key")
			}
			parsed.spaKey = key
			parsed.spaMasked = strings.EqualFold(s.Network, "spa1m")
			steps = append(steps, parsed)
			continue
		default:
			return nil, E.New("knock: step ", i+1, ": unknown network: ", s.Network)
		}
		if s.Payload != "" {
			if !parsed.udp {
				return nil, E.New("knock: step ", i+1, ": payload is only supported for udp")
			}
			payload, err := hex.DecodeString(s.Payload)
			if err != nil {
				return nil, E.Cause(err, "knock: step ", i+1, ": decode payload")
			}
			if len(payload) > maxPayload {
				return nil, E.New("knock: step ", i+1, ": payload too large")
			}
			parsed.payload = payload
		}
		steps = append(steps, parsed)
	}
	return steps, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	plain := o.plain(ctx, destination)
	if o.node != nil && !plain {
		return o.dialNode(ctx, network, destination)
	}
	if targets := o.detourTargets(destination); targets != nil && !plain {
		return o.dialTargets(o.withServerName(ctx, destination.Fqdn), network, targets)
	}
	if destination.IsFqdn() {
		ctx = o.withServerName(ctx, destination.Fqdn)
	}
	destination, err := o.resolve(ctx, destination)
	if err != nil {
		return nil, err
	}
	if plain {
		return o.dialer.DialContext(ctx, network, destination)
	}
	return o.dialResolved(ctx, network, destination)
}

// dialResolved knocks at an address and dials it
func (o *Outbound) dialResolved(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.spa2 != nil {
		return o.dialSPA2(ctx, network, destination)
	}
	knocked, err := o.knock(ctx, destination, false)
	if err != nil {
		return nil, err
	}
	conn, err := o.dialer.DialContext(ctx, network, destination)
	if err != nil && !knocked {
		// the cached knock may be stale (window closed, server restarted): knock and retry once
		o.logger.DebugContext(ctx, "dial after cached knock failed, knocking again: ", err)
		if _, knockErr := o.knock(ctx, destination, true); knockErr != nil {
			return nil, err
		}
		conn, err = o.dialer.DialContext(ctx, network, destination)
	}
	if err != nil {
		// the port may need a moment more, knock again on the next attempt
		o.forget(ctx, destination)
		return nil, err
	}
	o.passed(destination)
	if N.NetworkName(network) == N.NetworkUDP {
		// e.g. WireGuard with one peer dials its UDP socket
		return o.watchConn(conn, destination), nil
	}
	// A broken TCP session errors out and the reconnect knocks; established
	// TCP survives a closed window via conntrack, and silence after a write is
	// normal there (uploads), so TCP connections are returned unwrapped.
	return conn, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	plain := o.plain(ctx, destination)
	var err error
	if o.node != nil && !plain && knockable(destination) {
		// a datagram's peer is one address: the first of the attempt (UDP tells nothing of the next one's need)
		targets, name := o.nodeTargets(ctx, destination)
		if len(targets) == 0 {
			return nil, E.New("knock: no address for ", destination)
		}
		ctx = o.withServerName(ctx, name)
		destination = targets[0]
	} else if targets := o.detourTargets(destination); targets != nil && !plain {
		// SPA v3 through a detour: the node's first signed address (spa-v3 §6)
		ctx = o.withServerName(ctx, destination.Fqdn)
		destination = targets[0]
	} else {
		if destination.IsFqdn() {
			ctx = o.withServerName(ctx, destination.Fqdn)
		}
		destination, err = o.resolve(ctx, destination)
		if err != nil {
			return nil, err
		}
	}
	// e.g. multi-peer WireGuard listens on 0.0.0.0, there is nothing to knock at
	if plain || !knockable(destination) {
		return o.dialer.ListenPacket(ctx, destination)
	}
	_, err = o.knock(ctx, destination, false)
	if err != nil {
		return nil, err
	}
	packetConn, err := o.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	if o.spa2 != nil {
		packetConn = o.trackPacketConn(packetConn, destination)
	}
	if o.silence <= 0 {
		return packetConn, nil
	}
	return &silentPacketConn{PacketConn: packetConn, watchdog: o.newWatchdog(destination)}, nil
}

// InterfaceUpdated is called when the default network changes. The server
// only opened the port for the old client address, so every knock is stale.
// It must not block: sing-box calls it from ResetNetwork.
func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	o.generation.Add(1)
	o.rounds.newNetwork()
	// a new network: the first carrier again
	o.spa2Carrier.Store(int32(o.carriers[0]))
	if o.spa2 != nil {
		// SPA v2: hosts in use get a packet from the new address at once
		go o.renewInUse()
	}
}

func knockable(destination M.Socksaddr) bool {
	if destination.Port == 0 {
		return false
	}
	return destination.IsFqdn() || destination.Addr.IsValid() && !destination.Addr.IsUnspecified()
}

func (o *Outbound) resolve(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsFqdn() || o.hasDetour {
		return destination, nil
	}
	addresses, err := o.lookup(ctx, destination.Fqdn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if len(addresses) == 0 {
		return M.Socksaddr{}, E.New("knock: no address for ", destination.Fqdn)
	}
	return M.SocksaddrFrom(addresses[0], destination.Port), nil
}

// lookup resolves a name with this outbound's resolver (domain_resolver)
func (o *Outbound) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	queryOptions, err := dialer.NewDNSQueryOptions(o.ctx, o.domainResolver, false)
	if err != nil {
		return nil, err
	}
	return service.FromContext[adapter.DNSRouter](o.ctx).Lookup(ctx, name, queryOptions)
}

func (o *Outbound) target(host string) *target {
	o.access.Lock()
	defer o.access.Unlock()
	t, loaded := o.targets[host]
	if !loaded {
		t = &target{}
		o.targets[host] = t
	}
	return t
}

func (o *Outbound) forget(ctx context.Context, destination M.Socksaddr) {
	o.forgetBefore(ctx, destination, time.Now())
}

// roundGoesOnKey marks a dial whose failure is not the round's end: the v3 half of an attempt that tries v2 next
// (dialSPA2)
type roundGoesOnKey struct{}

func withRoundGoesOn(ctx context.Context) context.Context {
	return context.WithValue(ctx, roundGoesOnKey{}, true)
}

func roundGoesOn(ctx context.Context) bool {
	goesOn, _ := ctx.Value(roundGoesOnKey{}).(bool)
	return goesOn
}

// forgetBefore drops the knock unless it finished after attempt, the start of
// the dial that failed: a knock sent after it (by a parallel dial) is not
// disproved by this failure, and dropping it would make every dial knock anew.
//
// The knock dropped is a failed round (roundBook.failed) when it was one of this network and no dial got through after it:
// a knock that opened the access and then ran out is no failure. The parallel dials that fail with it count once,
// the first drops it. A dial that ended with its caller (cancelled, out of time) says nothing of the node, and the v3
// half of an attempt goes on with v2 (roundGoesOn): neither is counted.
func (o *Outbound) forgetBefore(ctx context.Context, destination M.Socksaddr, attempt time.Time) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	if !t.lastKnock.After(attempt) {
		if !t.lastKnock.IsZero() && t.generation == o.generation.Load() && t.passedAt.Before(t.lastKnock) &&
			ctx.Err() == nil && !roundGoesOn(ctx) {
			o.rounds.failed(destination.AddrString(), t.lastKnock, time.Now())
		}
		t.lastKnock = time.Time{}
	}
	t.access.Unlock()
}

// passed: a dial after a knock got through; the next failure counts from one.
func (o *Outbound) passed(destination M.Socksaddr) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	t.passedAt = time.Now()
	o.rounds.passed(destination.AddrString())
	t.access.Unlock()
}

// cached reports whether a knock to the host is still considered valid.
func (o *Outbound) cached(destination M.Socksaddr) bool {
	t := o.target(destination.AddrString())
	t.access.Lock()
	defer t.access.Unlock()
	return !t.lastKnock.IsZero() && t.generation == o.generation.Load() && time.Since(t.lastKnock) < o.ttl
}

// knock sends the sequence to the host unless a knock is still valid (with
// force: unless it was sent just now) and reports whether it sent one.
// Concurrent callers share one knock in flight.
//
// A round's first knock (not forced) waits the pause after failed rounds (roundBook); the knocks within a round (a
// forced one after a cached knock failed, the reknocks over the carriers), renewals and the watchdog's do not.
func (o *Outbound) knock(ctx context.Context, destination M.Socksaddr, force bool) (bool, error) {
	return o.knockOnce(ctx, destination, func(t *target, waited bool) bool {
		since := time.Since(t.lastKnock)
		// after waiting for a knock in flight: re-check, it may have failed or become stale
		return since < o.ttl && (!force || waited) || since < minReknockGap
	}, o.carrier(), o.sendSequence, !force)
}

// carrier is the SPA v2 carrier in use on this network (UDP for SPA v1 and port knocking).
func (o *Outbound) carrier() Carrier {
	return Carrier(o.spa2Carrier.Load())
}

// reknock sends again over carrier after a dial that started at attempt
// failed, unless a knock over the same carrier finished after that (a parallel
// dial already sent one, which this dial did not wait for): a slot turn that
// breaks many dials at once sends one packet, not one per dial.
func (o *Outbound) reknock(ctx context.Context, destination M.Socksaddr, attempt time.Time, carrier Carrier, send func(context.Context, M.Socksaddr) error) (bool, error) {
	return o.knockOnce(ctx, destination, func(t *target, _ bool) bool {
		return t.lastByCarrier[carrier].After(attempt)
	}, carrier, send, false)
}

// knockOnce runs send unless fresh (called under the target's lock, only for a
// knock of this network) says the access is fresh; concurrent callers share
// one send in flight and re-check after it. A paced send waits the pause after failed rounds.
func (o *Outbound) knockOnce(ctx context.Context, destination M.Socksaddr, fresh func(t *target, waited bool) bool, carrier Carrier, send func(context.Context, M.Socksaddr) error, paced bool) (bool, error) {
	t := o.target(destination.AddrString())
	waited := false
	for {
		t.access.Lock()
		generation := o.generation.Load()
		if !t.lastKnock.IsZero() && t.generation == generation && fresh(t, waited) {
			t.access.Unlock()
			return false, nil
		}
		if t.inflight == nil {
			// a round after failed ones waits its turn; a caller whose time runs out first is told so at once
			if wait, rounds := o.rounds.wait(destination.AddrString(), time.Now()); paced && wait > 0 {
				t.access.Unlock()
				if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
					return false, E.New("knock: ", destination.AddrString(), " did not open after ", rounds,
						" round(s), the next in ", wait.Round(100*time.Millisecond))
				}
				if err := sleep(ctx, wait); err != nil {
					return false, err
				}
				continue
			}
			done := make(chan struct{})
			t.inflight = done
			t.access.Unlock()
			err := send(ctx, destination)
			t.access.Lock()
			t.inflight = nil
			if err == nil {
				// a network change during the knock leaves it stale
				t.lastKnock = time.Now()
				t.lastByCarrier[carrier] = t.lastKnock
				t.generation = generation
				if o.spa2 != nil {
					o.scheduleRenewal(t, destination)
				}
			}
			t.access.Unlock()
			close(done)
			return err == nil, err
		}
		inflight := t.inflight
		t.access.Unlock()
		select {
		case <-inflight:
			waited = true
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

// sendSequence knocks the steps strictly in order: a step starts only after
// the previous one is over and at least `interval` after it started.
func (o *Outbound) sendSequence(ctx context.Context, destination M.Socksaddr) error {
	if o.spa2 != nil {
		return o.sendSPA2(ctx, destination)
	}
	o.logger.InfoContext(ctx, "knocking ", destination.AddrString(), " (", len(o.steps), " steps)")
	for i, s := range o.steps {
		started := time.Now()
		o.send(ctx, M.Socksaddr{Addr: destination.Addr, Fqdn: destination.Fqdn, Port: s.port}, s)
		if i == len(o.steps)-1 {
			break
		}
		err := sleep(ctx, o.interval-time.Since(started))
		if err != nil {
			return err
		}
	}
	// give the firewall time to apply the rule before the real connection
	return sleep(ctx, max(o.interval, minSettle))
}

func (o *Outbound) send(ctx context.Context, destination M.Socksaddr, s step) {
	if s.udp {
		packetConn, err := o.dialer.ListenPacket(ctx, destination)
		if err != nil {
			o.logger.DebugContext(ctx, "knock udp ", destination, ": ", err)
			return
		}
		defer packetConn.Close()
		var addr net.Addr = destination
		if destination.IsIP() {
			addr = destination.UDPAddr()
		}
		payload := s.payload
		if s.spaKey != nil {
			payload = spaPacket(s.spaKey, s.spaMasked)
		} else if len(payload) == 0 {
			payload = defaultUDPPayload
		}
		_, err = packetConn.WriteTo(payload, addr)
		if err != nil {
			o.logger.DebugContext(ctx, "knock udp ", destination, ": ", err)
		}
		return
	}
	// Like `knock`: one SYN, no waiting for the handshake. A dropped port
	// never answers, so the attempt is cut before the SYN is retransmitted.
	dialCtx, cancel := context.WithTimeout(ctx, tcpAttemptTimeout(o.interval))
	defer cancel()
	conn, err := o.dialer.DialContext(dialCtx, N.NetworkTCP, destination)
	if err == nil {
		// an open knock port; knockd needs `tcpflags = syn` to ignore our FIN
		conn.Close()
	}
}

func tcpAttemptTimeout(interval time.Duration) time.Duration {
	return min(max(interval, minTCPAttempt), maxTCPAttempt)
}

func sleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// watchdog re-knocks a UDP session once when data was sent but nothing came
// back for `silence`, then checks after another `silence` whether the server
// answers again. It re-arms only after a reply, so a dead server is knocked
// once per session. Long-lived UDP transports (WireGuard, QUIC) keep one
// socket and never dial again, so this is their only way back.
type watchdog struct {
	outbound    *Outbound
	destination M.Socksaddr
	lastRead    atomic.Int64
	pending     atomic.Bool
	knocked     atomic.Bool
	closed      atomic.Bool
}

func (o *Outbound) newWatchdog(destination M.Socksaddr) *watchdog {
	// neko: no read yet. The time of creation stood here, and where the clock is coarse (Windows) a write right
	// after the dial (WireGuard's handshake) fell in the same tick: it looked answered, and the first silence of the
	// session was never knocked for
	return &watchdog{outbound: o, destination: destination}
}

func (w *watchdog) onRead() {
	w.lastRead.Store(time.Now().UnixNano())
	if w.knocked.CompareAndSwap(true, false) {
		w.outbound.logger.Info("server ", w.destination.AddrString(), " answers again after re-knock")
	}
}

// isWireGuardKeepalive matches an empty WireGuard transport message: the
// peer does not answer it, so it must not arm the watchdog. Bytes 1-3 may
// carry "reserved" values.
func isWireGuardKeepalive(p []byte) bool {
	return len(p) == 32 && p[0] == 4
}

func (w *watchdog) onWrite(p []byte) {
	if isWireGuardKeepalive(p) || w.knocked.Load() || !w.pending.CompareAndSwap(false, true) {
		return
	}
	sentAt := time.Now().UnixNano()
	time.AfterFunc(w.outbound.silence, func() {
		w.pending.Store(false)
		if w.closed.Load() || w.lastRead.Load() >= sentAt || !w.knocked.CompareAndSwap(false, true) {
			return
		}
		o := w.outbound
		ctx, cancel := context.WithTimeout(o.ctx, o.interval*time.Duration(len(o.steps)+2)+5*time.Second)
		defer cancel()
		knocked, err := o.knock(ctx, w.destination, true)
		if err != nil || !knocked {
			// nothing sent (another session knocked just now): stay armed
			w.knocked.Store(false)
			return
		}
		o.logger.Warn("no reply from ", w.destination.AddrString(), " for ", o.silence, ", knocked again")
		knockedAt := time.Now().UnixNano()
		time.AfterFunc(o.silence, func() {
			if !w.closed.Load() && w.lastRead.Load() < knockedAt {
				o.logger.Warn("still no reply from ", w.destination.AddrString(), " after re-knock")
			}
		})
	})
}

func (o *Outbound) watchConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	if o.silence <= 0 {
		return conn
	}
	return &silentConn{Conn: conn, watchdog: o.newWatchdog(destination)}
}

type silentConn struct {
	net.Conn
	*watchdog
}

func (c *silentConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.onRead()
	}
	return n, err
}

func (c *silentConn) Write(p []byte) (int, error) {
	c.onWrite(p)
	return c.Conn.Write(p)
}

func (c *silentConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type silentPacketConn struct {
	net.PacketConn
	*watchdog
}

func (c *silentPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.onRead()
	}
	return n, addr, err
}

func (c *silentPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.onWrite(p)
	return c.PacketConn.WriteTo(p, addr)
}

func (c *silentPacketConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}
