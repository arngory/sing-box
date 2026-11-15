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
	// TCP connections to a node still waiting for its first bytes (handshakes.go)
	handshakes handshakeGate

	// the only hosts knocked at (Options.Hosts); nil: all
	hosts *knockHosts
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
		targets:        make(map[string]*target),
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
	destination, err := o.resolve(ctx, destination)
	if err != nil {
		return nil, err
	}
	if plain {
		return o.dialer.DialContext(ctx, network, destination)
	}
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
		o.forget(destination)
		return nil, err
	}
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
	destination, err := o.resolve(ctx, destination)
	if err != nil {
		return nil, err
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

func (o *Outbound) forget(destination M.Socksaddr) {
	o.forgetBefore(destination, time.Now())
}

// forgetBefore drops the knock unless it finished after attempt, the start of
// the dial that failed: a knock sent after it (by a parallel dial) is not
// disproved by this failure, and dropping it would make every dial knock anew.
func (o *Outbound) forgetBefore(destination M.Socksaddr, attempt time.Time) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	if !t.lastKnock.After(attempt) {
		t.lastKnock = time.Time{}
	}
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
func (o *Outbound) knock(ctx context.Context, destination M.Socksaddr, force bool) (bool, error) {
	return o.knockOnce(ctx, destination, func(t *target, waited bool) bool {
		since := time.Since(t.lastKnock)
		// after waiting for a knock in flight: re-check, it may have failed or become stale
		return since < o.ttl && (!force || waited) || since < minReknockGap
	}, o.carrier(), o.sendSequence)
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
	}, carrier, send)
}

// knockOnce runs send unless fresh (called under the target's lock, only for a
// knock of this network) says the access is fresh; concurrent callers share
// one send in flight and re-check after it.
func (o *Outbound) knockOnce(ctx context.Context, destination M.Socksaddr, fresh func(t *target, waited bool) bool, carrier Carrier, send func(context.Context, M.Socksaddr) error) (bool, error) {
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
	w := &watchdog{outbound: o, destination: destination}
	w.lastRead.Store(time.Now().UnixNano())
	return w
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
