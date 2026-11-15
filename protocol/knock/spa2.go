package knock

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/chacha20poly1305"
)

// raycontrol SPA v2 (arngory/raycontrol docs/spec/spa-v2.md, frozen for R0):
// one XChaCha20-Poly1305 packet of a random length, sealed with a per-epoch
// key of the device, sent to the port of the current time slot. Test vectors:
// testdata/spa_v2_vectors.json, copied from raycontrol internal/spa/testdata.

const (
	spa2Version    = 0x02
	spa2NonceSize  = 24
	spa2TagSize    = 16
	spa2KeySize    = 32
	spa2NodeIDSize = 16
	spa2Header     = 1 + 8 + 2 + 1 + 1
	spa2MaxScope   = 16
	spa2KeyInfo    = "raycontrol-spa-v2 key"
	spa2PortInfo   = "raycontrol-spa-v2 port"
	spa2AADLabel   = "raycontrol-spa-v2"
	// the server default when the packet asks for 0
	spa2DefaultTTL = 10 * time.Minute
	// the node reads the TCP carrier for at most 3 s
	spa2TCPTimeout = 3 * time.Second
)

// SPAv2Options are the node parameters and the device key from the
// registration package (spa-v2.md §1, §8).
type SPAv2Options struct {
	NodeID    string `json:"node_id"`
	EpochLen  uint32 `json:"epoch_len_s"`
	SlotLen   uint32 `json:"slot_len_s"`
	PortKey   string `json:"port_key"`
	PortBase  uint16 `json:"port_base"`
	PortRange uint16 `json:"port_range"`
	LenMin    int    `json:"len_min"`
	LenMax    int    `json:"len_max"`
	DeviceKey string `json:"device_key,omitempty"`
	// DeviceKeyRef names a key set with SetDeviceKey, so the key stays out of the config
	DeviceKeyRef string   `json:"device_key_ref,omitempty"`
	Scope        []uint16 `json:"scope,omitempty"`
	// TTL is the access time asked for, seconds; 0 = the server default (10 min)
	TTL uint16 `json:"ttl_s,omitempty"`
	// Carriers the node takes, in the order to try them (the subscription's spa.carriers, raycontrol v0.10.1):
	// "udp", "tls", "tcp"; none = an older node, all three in that order. The outbound tries only these; one-off
	// requests try the others last (TryCarriers)
	Carriers []string `json:"carriers,omitempty"`
	// Relay: these are the parameters of a relay in front of the node (relay-v1 §3), knocked at with K_relay
	Relay *SPARelay `json:"relay,omitempty"`
}

// SPARelay names the relay and the node behind it: K_relay = HKDF-SHA256(device key, the exit's node_id,
// "raycontrol-relay-v1" || the relay's node_id || relay id). The device key itself opens nothing at a relay.
type SPARelay struct {
	ExitNodeID string `json:"exit_node_id"`
	ID         string `json:"id"`
}

const relayKeyInfo = "raycontrol-relay-v1"

// RelayKey is K_relay of relay-v1 §3.
func RelayKey(deviceKey, exitNodeID, relayNodeID []byte, relayID string) ([]byte, error) {
	info := append(append([]byte(relayKeyInfo), relayNodeID...), relayID...)
	return hkdf.Key(sha256.New, deviceKey, exitNodeID, string(info), spa2KeySize)
}

// CarrierOrder is the order to try the carriers in: the node's list (unknown names left out), or UDP, ClientHello,
// bare TCP for a node that sends none.
func (o SPAv2Options) CarrierOrder() []Carrier {
	var order []Carrier
	for _, name := range o.Carriers {
		for _, c := range Carriers {
			if c.String() == name && !slices.Contains(order, c) {
				order = append(order, c)
			}
		}
	}
	if len(order) == 0 {
		return Carriers
	}
	return order
}

// TryCarriers is the order for a one-off request (the subscription, the API, the probe): the node's carriers first,
// then UDP or the ClientHello it did not list as a last resort. The list is the one of the last subscription, and
// only a subscription brings a new one: a node that changed it must still be reachable when the old one fails.
// Bare TCP never goes to a node whose list leaves it out: random bytes as the first data of a TCP connection are
// the class of traffic censors drop on sight (RAYCONTROL.md §22.2.3), and such a node does not read it.
func (o SPAv2Options) TryCarriers() []Carrier {
	order := o.CarrierOrder()
	for _, c := range Carriers {
		if c == CarrierTCP && len(o.Carriers) > 0 {
			continue
		}
		if !slices.Contains(order, c) {
			order = append(order, c)
		}
	}
	return order
}

// FetchCarriers is the order of the knocks before a one-off request: TryCarriers, with UDP twice, as the slot may
// turn.
func (o SPAv2Options) FetchCarriers() []Carrier {
	var out []Carrier
	for _, c := range o.TryCarriers() {
		out = append(out, c)
		if c == CarrierUDP {
			out = append(out, c)
		}
	}
	return out
}

type spa2Params struct {
	nodeID    [spa2NodeIDSize]byte
	epochLen  uint64
	slotLen   uint64
	portKey   [spa2KeySize]byte
	portBase  uint16
	portRange uint16
	lenMin    int
	lenMax    int
	deviceKey [spa2KeySize]byte
	scope     []uint16
	ttl       uint16
}

func decodeHexInto(dst []byte, s, name string) error {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(dst) {
		return E.New("spa_v2: ", name, " must be ", len(dst)*2, " hex digits")
	}
	copy(dst, raw)
	return nil
}

// deviceKeys holds device keys by reference (SetDeviceKey), hex.
var deviceKeys sync.Map

// SetDeviceKey stores the device key for spa_v2.device_key_ref; an empty key removes it.
func SetDeviceKey(ref, keyHex string) {
	if keyHex == "" {
		deviceKeys.Delete(ref)
		return
	}
	deviceKeys.Store(ref, keyHex)
}

// DeviceKey is the device key stored for ref (SetDeviceKey), 32 bytes: other users of the node's key
// (dnsauth-v1 of DNS tunnels) take it by the same reference as SPA.
func DeviceKey(ref string) ([]byte, error) {
	key, loaded := deviceKeys.Load(ref)
	if !loaded {
		return nil, E.New("no device key for ", ref)
	}
	return hex.DecodeString(key.(string))
}

// RetainDeviceKeys forgets every stored device key whose reference is not in
// refs. Outbounds already created keep their own copy, and keys still in refs
// stay, so this is safe while boxes are being built and run.
func RetainDeviceKeys(refs []string) {
	keep := make(map[string]bool, len(refs))
	for _, ref := range refs {
		keep[ref] = true
	}
	deviceKeys.Range(func(ref, _ any) bool {
		if !keep[ref.(string)] {
			deviceKeys.Delete(ref)
		}
		return true
	})
}

func parseSPAv2(o SPAv2Options) (*spa2Params, error) {
	if o.DeviceKey == "" && o.DeviceKeyRef != "" {
		key, loaded := deviceKeys.Load(o.DeviceKeyRef)
		if !loaded {
			return nil, E.New("spa_v2: no device key for ", o.DeviceKeyRef)
		}
		o.DeviceKey = key.(string)
	}
	p := &spa2Params{
		epochLen:  uint64(o.EpochLen),
		slotLen:   uint64(o.SlotLen),
		portBase:  o.PortBase,
		portRange: o.PortRange,
		lenMin:    o.LenMin,
		lenMax:    o.LenMax,
		scope:     o.Scope,
		ttl:       o.TTL,
	}
	for _, field := range []struct {
		dst  []byte
		s    string
		name string
	}{{p.nodeID[:], o.NodeID, "node_id"}, {p.portKey[:], o.PortKey, "port_key"}, {p.deviceKey[:], o.DeviceKey, "device_key"}} {
		if err := decodeHexInto(field.dst, field.s, field.name); err != nil {
			return nil, err
		}
	}
	if o.Relay != nil {
		var exit [16]byte
		if err := decodeHexInto(exit[:], o.Relay.ExitNodeID, "relay.exit_node_id"); err != nil {
			return nil, err
		}
		if o.Relay.ID == "" {
			return nil, E.New("spa_v2: relay without an id")
		}
		key, err := RelayKey(p.deviceKey[:], exit[:], p.nodeID[:], o.Relay.ID)
		if err != nil {
			return nil, err
		}
		copy(p.deviceKey[:], key)
	}
	switch {
	case p.epochLen == 0 || p.slotLen == 0:
		return nil, E.New("spa_v2: epoch_len_s and slot_len_s must be positive")
	case p.portRange == 0 || int(p.portBase)+int(p.portRange) > 65536:
		return nil, E.New("spa_v2: invalid port range")
	case p.lenMin < spa2NonceSize+spa2TagSize+spa2Header+2*len(p.scope) || p.lenMax < p.lenMin || p.lenMax > 512:
		return nil, E.New("spa_v2: invalid packet length bounds for this scope")
	case len(p.scope) > spa2MaxScope:
		return nil, E.New("spa_v2: scope has more than ", spa2MaxScope, " services")
	}
	return p, nil
}

func be64(v uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, v)
}

func (p *spa2Params) epoch(t time.Time) uint64 { return uint64(t.Unix()) / p.epochLen }
func (p *spa2Params) slot(t time.Time) uint64  { return uint64(t.Unix()) / p.slotLen }

// port of a slot: base + BE64(HMAC-SHA256(port_key, label || BE64(slot))[0:8]) mod range
func (p *spa2Params) port(slot uint64) uint16 {
	return slotPort(p.portKey[:], p.portBase, p.portRange, slot)
}

// epochKey = HKDF-SHA256(ikm = device_key, salt = node_id, info = label || BE64(epoch), 32)
func (p *spa2Params) epochKey(epoch uint64) ([]byte, error) {
	return hkdf.Key(sha256.New, p.deviceKey[:], p.nodeID[:], spa2KeyInfo+string(be64(epoch)), spa2KeySize)
}

// seal builds a packet of exactly length bytes for the time now.
func (p *spa2Params) seal(now time.Time, nonce []byte, length int) ([]byte, error) {
	if length < p.lenMin || length > p.lenMax {
		return nil, E.New("spa_v2: packet length out of range")
	}
	plaintext := make([]byte, length-spa2NonceSize-spa2TagSize)
	plaintext[0] = spa2Version
	binary.BigEndian.PutUint64(plaintext[1:9], uint64(now.Unix()))
	binary.BigEndian.PutUint16(plaintext[9:11], p.ttl)
	plaintext[11] = 0
	plaintext[12] = byte(len(p.scope))
	for i, id := range p.scope {
		binary.BigEndian.PutUint16(plaintext[spa2Header+2*i:], id)
	}
	key, err := p.epochKey(p.epoch(now))
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	aad := append([]byte(spa2AADLabel), p.nodeID[:]...)
	return aead.Seal(append(make([]byte, 0, length), nonce...), nonce, plaintext, aad), nil
}

func randomInt(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

// packet returns the port of the current slot and a fresh packet of a random length.
func (p *spa2Params) packet(now time.Time) (uint16, []byte, error) {
	nonce := make([]byte, spa2NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return 0, nil, err
	}
	length := p.lenMin + int(randomInt(int64(p.lenMax-p.lenMin+1)))
	packet, err := p.seal(now, nonce, length)
	return p.port(p.slot(now)), packet, err
}

// access is how long the server keeps the address allowed.
func (p *spa2Params) access() time.Duration {
	if p.ttl == 0 {
		return spa2DefaultTTL
	}
	return time.Duration(p.ttl) * time.Second
}

// settle is the random pause between the packet and the connection (spa-v2.md §7).
func spa2Settle() time.Duration {
	return 150*time.Millisecond + time.Duration(randomInt(251))*time.Millisecond
}

// renewIn is when to renew: at a random point in the second half of the access
// time, so a renewal does not line up with connections.
func (p *spa2Params) renewIn() time.Duration {
	access := p.access()
	return access/2 + time.Duration(randomInt(int64(access*3/10)+1))
}

// sendSPA2 sends one packet to the port of the current slot over the carrier
// in use, then waits a random 150-400 ms before the connection may start.
func (o *Outbound) sendSPA2(ctx context.Context, destination M.Socksaddr) error {
	return o.sendSPA2Over(ctx, destination, o.carrier())
}

// sendSPA2Over sends the packet over UDP or, where unknown UDP is cut, in a TCP
// connection to the same slot port (spa-v2.md §10): as a ClientHello (§10.1)
// or bare for nodes before raycontrol v0.10.0, then close; the node answers
// nothing and resets.
func (o *Outbound) sendSPA2Over(ctx context.Context, destination M.Socksaddr, carrier Carrier) error {
	port, packet, err := o.spa2.packet(time.Now())
	if err != nil {
		return err
	}
	target := M.Socksaddr{Addr: destination.Addr, Fqdn: destination.Fqdn, Port: port}
	if carrier == CarrierUDP {
		o.logger.DebugContext(ctx, "SPA v2 to ", destination.AddrString(), " port ", port)
		o.send(ctx, target, step{port: port, udp: true, payload: packet})
		return sleep(ctx, spa2Settle())
	}
	payload, err := carrierPayload(carrier, packet)
	if err != nil {
		return err
	}
	o.logger.DebugContext(ctx, "SPA v2 over ", carrier, " to ", destination.AddrString(), " port ", port)
	dialCtx, cancel := context.WithTimeout(ctx, spa2TCPTimeout)
	conn, err := o.dialer.DialContext(dialCtx, N.NetworkTCP, target)
	cancel()
	if err != nil {
		o.logger.DebugContext(ctx, "SPA v2 over ", carrier, ": ", err)
	} else {
		conn.SetWriteDeadline(time.Now().Add(spa2TCPTimeout))
		conn.Write(payload)
		if closer, ok := conn.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
		conn.Close()
	}
	return sleep(ctx, spa2Settle())
}

// dialSPA2 dials after SPA v2 (spa-v2.md §7, §10): on a failed dial one more
// packet over the carrier in use (the slot may have turned), then the carriers
// after it in turn (UDP, ClientHello, bare TCP); the one that worked is kept
// until the network changes.
func (o *Outbound) dialSPA2(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if _, err := o.knock(ctx, destination, false); err != nil {
		return nil, err
	}
	// the retries are shared with parallel dials (reknock): a packet sent after this dial started serves it
	// too, so a slot turn that breaks many dials sends one packet, not one per dial
	attempt := time.Now()
	conn, err := o.dialPeer(ctx, network, destination)
	current := o.carrier()
	order := o.carriers
	if err != nil {
		o.logger.DebugContext(ctx, "dial after SPA failed, sending it once more: ", err)
		if _, knockErr := o.reknock(ctx, destination, attempt, current, o.sendSPA2); knockErr == nil {
			attempt = time.Now()
			conn, err = o.dialPeer(ctx, network, destination)
		}
	}
	for _, carrier := range order[slices.Index(order, current)+1:] {
		if err == nil {
			break
		}
		o.logger.DebugContext(ctx, "dial after SPA over ", Carrier(o.spa2Carrier.Load()), " failed, trying ", carrier, ": ", err)
		_, knockErr := o.reknock(ctx, destination, attempt, carrier, func(ctx context.Context, destination M.Socksaddr) error {
			return o.sendSPA2Over(ctx, destination, carrier)
		})
		if knockErr != nil {
			continue
		}
		attempt = time.Now()
		conn, err = o.dialPeer(ctx, network, destination)
		// a knock over this carrier after the earlier ones failed opened it (this dial's or a parallel one's)
		if err == nil && o.spa2Carrier.CompareAndSwap(int32(current), int32(carrier)) {
			o.logger.InfoContext(ctx, "SPA v2 goes over ", carrier, " on this network (", current, " did not open ", destination.AddrString(), ")")
		}
	}
	if err != nil {
		o.forgetBefore(destination, attempt)
		return nil, err
	}
	// a new TCP connection waits its turn to say hello when three to the node have not heard from it yet (R5);
	// the dial itself is not held, so the SPA retries of parallel dials stay shared
	if N.NetworkName(network) == N.NetworkTCP {
		release, err := o.handshakes.acquire(ctx, destination.String())
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = &gatedConn{Conn: conn, release: release}
	}
	o.touch(destination)
	conn = o.trackConn(conn, destination)
	if N.NetworkName(network) == N.NetworkUDP {
		return o.watchConn(conn, destination), nil
	}
	return conn, nil
}

// dialPeer dials the service; a UDP service with a rotating port (spa-v2.md §11)
// gets one socket that follows the slot port.
func (o *Outbound) dialPeer(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	schedule := o.udpPorts[destination.Port]
	if schedule == nil || N.NetworkName(network) != N.NetworkUDP || !destination.IsIP() {
		return o.dialer.DialContext(ctx, network, destination)
	}
	packetConn, err := o.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	conn := newRotatingUDPConn(packetConn, destination, schedule)
	conn.onTurn = func(from, to uint16) {
		o.logger.Debug("UDP ", destination.AddrString(), ":", destination.Port, ": slot port ", from, " -> ", to)
	}
	o.logger.DebugContext(ctx, "UDP ", destination, " goes to the slot port ", conn.current().Port)
	return conn, nil
}

// touch records that access to the host is fresh and keeps it renewed.
func (o *Outbound) touch(destination M.Socksaddr) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	defer t.access.Unlock()
	if t.lastKnock.IsZero() || t.generation != o.generation.Load() {
		t.lastKnock = time.Now()
		t.generation = o.generation.Load()
		o.scheduleRenewal(t, destination)
	}
}

// scheduleRenewal arms the renewal of a host's access; t.access is held.
func (o *Outbound) scheduleRenewal(t *target, destination M.Socksaddr) {
	if t.renew != nil {
		t.renew.Stop()
	}
	t.renew = time.AfterFunc(o.spa2.renewIn(), func() {
		if o.ctx.Err() != nil || !o.inUse(t) {
			return
		}
		ctx, cancel := context.WithTimeout(o.ctx, 10*time.Second)
		defer cancel()
		if _, err := o.knock(ctx, destination, true); err != nil {
			o.logger.Debug("SPA v2 renewal for ", destination.AddrString(), ": ", err)
		}
	})
}

func (o *Outbound) inUse(t *target) bool {
	t.access.Lock()
	defer t.access.Unlock()
	return t.active > 0 || time.Since(t.lastUse) < o.spa2.access()
}

// renewInUse sends a packet for every host in use, after a network change.
func (o *Outbound) renewInUse() {
	o.access.Lock()
	hosts := make(map[string]*target, len(o.targets))
	for host, t := range o.targets {
		hosts[host] = t
	}
	o.access.Unlock()
	for host, t := range hosts {
		if !o.inUse(t) {
			continue
		}
		ctx, cancel := context.WithTimeout(o.ctx, 10*time.Second)
		if _, err := o.knock(ctx, M.ParseSocksaddrHostPort(host, 0), true); err != nil {
			o.logger.Debug("SPA v2 after a network change, ", host, ": ", err)
		}
		cancel()
	}
}

func (o *Outbound) use(destination M.Socksaddr, delta int) {
	t := o.target(destination.AddrString())
	t.access.Lock()
	t.active += delta
	t.lastUse = time.Now()
	t.access.Unlock()
}

func (o *Outbound) trackConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	o.use(destination, 1)
	return &trackedConn{Conn: conn, done: func() { o.use(destination, -1) }}
}

func (o *Outbound) trackPacketConn(conn net.PacketConn, destination M.Socksaddr) net.PacketConn {
	o.use(destination, 1)
	return &trackedPacketConn{PacketConn: conn, done: func() { o.use(destination, -1) }}
}

type trackedConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any { return c.Conn }

type trackedPacketConn struct {
	net.PacketConn
	once sync.Once
	done func()
}

func (c *trackedPacketConn) Close() error {
	c.once.Do(c.done)
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any { return c.PacketConn }

// SPAv2Packet returns the slot port and a fresh packet for the options at now
// (the subscription fetch sends it outside an outbound).
func SPAv2Packet(options SPAv2Options, now time.Time) (uint16, []byte, error) {
	p, err := parseSPAv2(options)
	if err != nil {
		return 0, nil, err
	}
	return p.packet(now)
}

// SendSPAv2 sends one packet for options to host at the port of the slot of
// now, over UDP or as the first data of a TCP connection, as a ClientHello or
// bare (spa-v2.md §10, §10.1), and
// waits 300 ms for the node to apply it (§7). For requests made outside an
// outbound: the subscription and the remote API.
func SendSPAv2(ctx context.Context, dialer *net.Dialer, host string, options SPAv2Options, carrier Carrier, now time.Time) error {
	port, packet, err := SPAv2Packet(options, now)
	if err != nil {
		return err
	}
	payload, err := carrierPayload(carrier, packet)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, spa2TCPTimeout)
	conn, err := dialer.DialContext(dialCtx, carrier.network(), net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancel()
	if err == nil {
		conn.SetWriteDeadline(time.Now().Add(spa2TCPTimeout))
		conn.Write(payload)
		conn.Close()
	}
	select {
	case <-time.After(300 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
