package udpserver

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// neko: dnsauth for masterdns (raycontrol docs/spec/dnsauth-masterdns.md §3, §4). Every query of a client with a
// device key carries the device's tag inside AES-GCM before its frame; the node checks it after the cipher opens and
// before the frame is parsed further or inflated. A query before a session is the device's whose key the tag holds
// (the authenticator scans the keys within its budget); a session is bound to the device of its SESSION_INIT and
// takes only that device's tags (at most 3 HMACs, outside the budget). A refused query gets the empty answer any
// undecipherable one gets.

const (
	authOff uint8 = iota
	authOptional
	authRequired
)

// The budgets an Authenticator's Scan keeps apart (§3.2): the probes after a node's restart do not eat the
// SESSION_INITs of the clients past them.
const (
	ScanProbe   = iota // MTU_UP_REQ, MTU_DOWN_REQ
	ScanInit           // SESSION_INIT
	ScanSession        // a query to a session with no live record of it (closed, expired, a restarted node)
)

// Authenticator checks tags with the devices' keys (niko-server, its keys file). Called from many goroutines.
type Authenticator interface {
	// Device is whether tag is device id's over msg (nonce || frame) in the current epoch or one next to it; false
	// for a device revoked since.
	Device(id string, tag [security.AuthTagLen]byte, msg []byte) bool
	// Scan is the device whose tag it is, the recent ones first, within the budget of kind; false when none's or the
	// budget is spent.
	Scan(kind int, tag [security.AuthTagLen]byte, msg []byte) (string, bool)
}

// maxSessionsPerDevice is the most live sessions a device holds: a new one closes its oldest (§3.5)
const maxSessionsPerDevice = 4

// ParseAuthMode is dnsauth's mode by its name: "", "off", "optional", "required".
func ParseAuthMode(mode string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "off":
		return authOff, nil
	case "optional":
		return authOptional, nil
	case "required":
		return authRequired, nil
	default:
		return 0, fmt.Errorf("masterdnsvpn: auth %q (off, optional or required)", mode)
	}
}

// SetAuth sets dnsauth's mode and the authenticator; before the server runs. AES-GCM only (methods 3-5): under the
// others a seen query can be changed without the key, and its tag says nothing.
func (s *Server) SetAuth(mode uint8, auth Authenticator) error {
	if mode == authOff {
		s.authMode, s.auth, s.authNonces = authOff, nil, nil
		return nil
	}
	if auth == nil {
		return errors.New("masterdnsvpn: auth without an authenticator")
	}
	if codec := s.firstCodec(); codec == nil || codec.Method() < 3 {
		return security.ErrAuthNeedsAEAD
	}
	s.authMode, s.auth, s.authNonces = mode, auth, newNonceMemory()
	return nil
}

// openQuery is the packet a query's labels carry, the device whose tag it bears ("" for none) and the service key
// that opened it: the cipher opened (the current key, then the previous), the tag checked, the frame parsed and
// inflated. False for a query to answer as undecipherable.
func (s *Server) openQuery(labels string, now time.Time) (VpnProto.Packet, string, *serviceKey, bool) {
	keys := s.currentKeys()
	if s.authMode == authOff {
		for _, key := range keys {
			if packet, err := VpnProto.ParseInflatedFromLabels(labels, key.codec); err == nil {
				return packet, "", key, true
			}
		}
		return VpnProto.Packet{}, "", nil, false
	}
	var key *serviceKey
	var nonce, plain []byte
	for _, candidate := range keys {
		var err error
		if nonce, plain, err = candidate.codec.DecodeStringAndOpen(labels); err == nil {
			key = candidate
			break
		}
	}
	if key == nil {
		return VpnProto.Packet{}, "", nil, false
	}
	if len(plain) > security.AuthTagLen {
		frameBytes := plain[security.AuthTagLen:]
		// a frame that does not parse at 8 bears no tag (an old client's, but for about 1 in 1000)
		if frame, err := VpnProto.Parse(frameBytes); err == nil {
			var tag [security.AuthTagLen]byte
			copy(tag[:], plain)
			if device, ok := s.checkTag(tag, nonce, frameBytes, frame, now); ok {
				packet, err := VpnProto.InflatePayload(frame)
				return packet, device, key, err == nil
			}
		}
	}
	if s.authMode == authRequired {
		return VpnProto.Packet{}, "", nil, false
	}
	// optional: a frame without a tag, an old client's, unless it is about a session a device holds
	frame, err := VpnProto.Parse(plain)
	if err != nil {
		return VpnProto.Packet{}, "", nil, false
	}
	if !isPreSessionRequestType(frame.PacketType) {
		if device, _ := s.sessions.deviceOf(frame.SessionID, frame.SessionCookie); device != "" {
			return VpnProto.Packet{}, "", nil, false
		}
	}
	packet, err := VpnProto.InflatePayload(frame)
	return packet, "", key, err == nil
}

// checkTag is the device whose tag a query bears (§3): before a session, by a scan, a request seen too often refused
// first; in a live session, its device's key alone; to a session no longer live, its closed record's device, else a
// scan. A live session of no device (an old client's) takes no tag.
func (s *Server) checkTag(tag [security.AuthTagLen]byte, nonce, frameBytes []byte, frame VpnProto.Packet, now time.Time) (string, bool) {
	msg := make([]byte, 0, len(nonce)+len(frameBytes))
	msg = append(append(msg, nonce...), frameBytes...)
	if isPreSessionRequestType(frame.PacketType) {
		// a query seen too often is refused before the scan; its sight is taken at once (copies at the same time count
		// against one another) and given back when the tag does not hold, so junk with the service's key never stays
		// in the memory (dnsauth-masterdns §3.6)
		sight, ok := s.authNonces.reserve(nonce, now)
		if !ok {
			return "", false
		}
		kind := ScanProbe
		if frame.PacketType == Enums.PACKET_SESSION_INIT {
			kind = ScanInit
		}
		device, ok := s.auth.Scan(kind, tag, msg)
		if !ok || device == "" {
			s.authNonces.undo(sight)
			return "", false
		}
		kept, event := s.authNonces.keep(sight, device, now)
		if s.log != nil {
			switch event.kind {
			case nonceQuotaReached:
				s.log.Warnf("dnsauth: device %s spent its %d queries before a session: its new ones go at %.0f a second until it rests", device, nonceDeviceBurst, nonceDeviceRate)
			case nonceTurnedEarly:
				s.log.Warnf("dnsauth: the nonce memory filled before its time (%d queries of many devices), turned early: replays of the oldest become possible; most new nonces: %s", nonceGenerationCap, event.topText())
			}
		}
		if !kept {
			// a device past its quota: its own queries refused, the others' as they are
			return "", false
		}
		return device, true
	}
	device, live := s.sessions.deviceOf(frame.SessionID, frame.SessionCookie)
	switch {
	case device != "":
		return device, s.auth.Device(device, tag, msg)
	case live:
		return "", false
	default:
		device, ok := s.auth.Scan(ScanSession, tag, msg)
		return device, ok && device != ""
	}
}

// nonceMemory keeps the nonces of queries before a session whose tag held, 30 to 60 minutes in two generations (longer
// than a tag holds: its epoch of 600 s and one next to it, a client's clock off by up to 10 minutes), by the decoded
// bytes (base36 lets different names give the same bytes, §3.6). The same query is served up to 3 times in 30 s from
// its first sight (a client sends a SESSION_INIT to several resolvers in the same bytes, a resolver repeats one);
// past that, or later, it is someone's replay. Each device's new nonces go through a bucket of nonceDeviceBurst that
// fills again in nonceDeviceRefill: a device that spends it (a stolen key's flood, or a start on a list of resolvers
// by the hundred) goes on at nonceDeviceRate a second, its queries past that refused, so one device neither locks
// the others out nor itself for long; the whole generation full (many devices at once) turns early, logged with the
// devices that filled it. A nonce is paid for once, by its first copy kept: the copies of it after pass on that.
// Times are the memory's own, monotonic: a step of the wall clock neither fills the buckets nor empties them.
type nonceMemory struct {
	mu                sync.Mutex
	current, previous map[[nonceKeyLen]byte]nonceSeen
	// each device's bucket of new nonces
	perDevice map[string]nonceBucket
	rotatedAt time.Time
	// each device's new nonces in the current generation, for the log of an early turn
	newOfDevice map[string]int
	// base is the memory's start: its times are nanoseconds since, by the monotonic clock
	base time.Time
}

// nonceBucket is a device's allowance of new nonces: tokens at time at (the memory's); spent marks it logged as empty
type nonceBucket struct {
	tokens float64
	at     int64
	spent  bool
}

// nonceSeen is a nonce's sights: how many, the first's time (the memory's), and whether a device's bucket paid for it
type nonceSeen struct {
	count   uint8
	charged bool
	first   int64
}

const (
	nonceKeyLen        = 12
	nonceGeneration    = 30 * time.Minute
	nonceRepeatWindow  = 30 * time.Second
	nonceRepeats       = 3
	nonceGenerationCap = 1 << 17
	// a start of Niko probes the MTU up and down on each resolver, about 35 probes on each: some 300 on its own list,
	// a start on a /24 of resolvers about 9000, the bucket's burst most of it and its rate the rest in minutes
	nonceDeviceBurst  = 8192
	nonceDeviceRefill = 15 * time.Minute
	nonceDeviceRate   = float64(nonceDeviceBurst) / (float64(nonceDeviceRefill) / float64(time.Second))
)

func newNonceMemory() *nonceMemory {
	now := time.Now()
	return &nonceMemory{
		current: make(map[[nonceKeyLen]byte]nonceSeen), previous: make(map[[nonceKeyLen]byte]nonceSeen),
		perDevice: make(map[string]nonceBucket), rotatedAt: now, newOfDevice: make(map[string]int), base: now,
	}
}

// mono is now in the memory's time: nanoseconds since its start, by the monotonic clock (time.Now's)
func (m *nonceMemory) mono(now time.Time) int64 {
	return int64(now.Sub(m.base))
}

// nonceSight is a sight of a nonce taken by reserve: undone when the query's tag does not hold, kept when it does
type nonceSight struct {
	key [nonceKeyLen]byte
}

// what keep reports for the log
const (
	nonceKept = iota
	nonceQuotaReached
	nonceTurnedEarly
)

// nonceEvent is what keep reports for the log: its kind, and for an early turn the devices of the most new nonces in
// the generation that filled, the most first
type nonceEvent struct {
	kind int
	top  []deviceNonces
}

// deviceNonces is a device's count of new nonces in a generation
type deviceNonces struct {
	device string
	count  int
}

// nonceTopDevices is how many devices the log of an early turn names
const nonceTopDevices = 3

func (e nonceEvent) topText() string {
	parts := make([]string, 0, len(e.top))
	for _, d := range e.top {
		parts = append(parts, fmt.Sprintf("%s %d", d.device, d.count))
	}
	return strings.Join(parts, ", ")
}

// reserve takes a sight of nonce for a query about to be checked, under the one lock: false when the nonce was seen 3
// times, or first more than 30 s ago (a replay). An unseen one is taken in, to be undone or kept.
func (m *nonceMemory) reserve(nonce []byte, now time.Time) (nonceSight, bool) {
	if len(nonce) != nonceKeyLen {
		return nonceSight{}, false
	}
	key := [nonceKeyLen]byte(nonce)
	at := m.mono(now)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.turnLocked(now)
	for _, generation := range []map[[nonceKeyLen]byte]nonceSeen{m.current, m.previous} {
		if seen, ok := generation[key]; ok {
			if seen.count >= nonceRepeats || at-seen.first > int64(nonceRepeatWindow) {
				return nonceSight{}, false
			}
			seen.count++
			generation[key] = seen
			return nonceSight{key: key}, true
		}
	}
	m.current[key] = nonceSeen{count: 1, first: at}
	return nonceSight{key: key}, true
}

// undo gives a sight back: its tag did not hold (or the scan's budget was spent); an unseen nonce leaves no trace
func (m *nonceMemory) undo(sight nonceSight) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.undoLocked(sight)
}

func (m *nonceMemory) undoLocked(sight nonceSight) {
	if generation, seen, ok := m.findLocked(sight.key); ok {
		if seen.count--; seen.count == 0 {
			delete(generation, sight.key)
		} else {
			generation[sight.key] = seen
		}
	}
}

// findLocked is the generation that holds key, and its entry there
func (m *nonceMemory) findLocked(key [nonceKeyLen]byte) (map[[nonceKeyLen]byte]nonceSeen, nonceSeen, bool) {
	for _, generation := range []map[[nonceKeyLen]byte]nonceSeen{m.current, m.previous} {
		if seen, ok := generation[key]; ok {
			return generation, seen, true
		}
	}
	return nil, nonceSeen{}, false
}

// keep keeps a sight whose tag held, device's. The nonce's first copy kept pays a token of the device's bucket for it,
// and its copies after pass on that; while the bucket is empty, each copy is undone and refused (false), the ones
// reserved at the same time as well, until one pays. The event to log: a bucket's emptying, once until it fills up
// again; a generation turned early.
func (m *nonceMemory) keep(sight nonceSight, device string, now time.Time) (bool, nonceEvent) {
	at := m.mono(now)
	m.mu.Lock()
	defer m.mu.Unlock()
	generation, seen, found := m.findLocked(sight.key)
	if found && seen.charged {
		return true, nonceEvent{}
	}
	bucket, ok := m.perDevice[device]
	if !ok {
		bucket = nonceBucket{tokens: nonceDeviceBurst, at: at}
	}
	// a query's time taken before another's that got the lock first: no refill, the later time kept
	if elapsed := at - bucket.at; elapsed > 0 {
		bucket.tokens = min(nonceDeviceBurst, bucket.tokens+nonceDeviceRate*float64(elapsed)/float64(time.Second))
		bucket.at = at
	}
	if bucket.tokens >= nonceDeviceBurst/2 {
		bucket.spent = false
	}
	if bucket.tokens < 1 {
		var event nonceEvent
		if !bucket.spent {
			bucket.spent, event.kind = true, nonceQuotaReached
		}
		m.perDevice[device] = bucket
		m.undoLocked(sight)
		return false, event
	}
	bucket.tokens--
	m.perDevice[device] = bucket
	m.newOfDevice[device]++
	seen.charged = true
	if !found {
		// both generations turned since its sight (early, under a flood): it goes into the new one
		generation, seen = m.current, nonceSeen{count: 1, charged: true, first: at}
	}
	generation[sight.key] = seen
	// the whole generation full, of many devices at their burst: it turns early, the sight going on into the new one
	if len(m.current) > nonceGenerationCap {
		top := m.topDevicesLocked(nonceTopDevices)
		m.turnNowLocked(now)
		delete(m.previous, sight.key)
		m.current[sight.key] = seen
		return true, nonceEvent{kind: nonceTurnedEarly, top: top}
	}
	return true, nonceEvent{}
}

// topDevicesLocked are the n devices of the most new nonces in the current generation, the most first (by name for
// the same count)
func (m *nonceMemory) topDevicesLocked(n int) []deviceNonces {
	top := make([]deviceNonces, 0, n+1)
	for device, count := range m.newOfDevice {
		i := len(top)
		for i > 0 && (top[i-1].count < count || top[i-1].count == count && top[i-1].device > device) {
			i--
		}
		if i >= n {
			continue
		}
		top = slices.Insert(top, i, deviceNonces{device: device, count: count})
		if len(top) > n {
			top = top[:n]
		}
	}
	return top
}

// turnLocked starts a new generation every nonceGeneration, the one before kept
func (m *nonceMemory) turnLocked(now time.Time) {
	if now.Sub(m.rotatedAt) >= nonceGeneration {
		m.turnNowLocked(now)
	}
}

func (m *nonceMemory) turnNowLocked(now time.Time) {
	m.previous, m.current, m.rotatedAt = m.current, make(map[[nonceKeyLen]byte]nonceSeen), now
	m.newOfDevice = make(map[string]int)
	// the buckets full again by now leave the map: it holds the devices of the last half hour
	at := m.mono(now)
	for device, bucket := range m.perDevice {
		if bucket.tokens+nonceDeviceRate*float64(at-bucket.at)/float64(time.Second) >= nonceDeviceBurst {
			delete(m.perDevice, device)
		}
	}
}

// deviceOf is the device of the session id with cookie: a live one (live true) or its closed record; "" when the
// session has none, or there is no such session.
func (s *sessionStore) deviceOf(sessionID uint8, cookie uint8) (device string, live bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if record := s.byID[sessionID]; record != nil && record.Cookie == cookie {
		return record.Device, true
	}
	if record, ok := s.recentClosed[sessionID]; ok && record.Cookie == cookie {
		return record.Device, false
	}
	return "", false
}

// idlestOfDeviceLocked is the live session of device silent longest, when it holds maxSessionsPerDevice or more: a
// second copy of the app on the device keeps its own (§3.5)
func (s *sessionStore) idlestOfDeviceLocked(device string) (uint8, bool) {
	if device == "" {
		return 0, false
	}
	count, oldest := 0, -1
	for id := 1; id <= maxServerSessionID; id++ {
		record := s.byID[id]
		if record == nil || record.Device != device {
			continue
		}
		count++
		if oldest < 0 || record.lastActivity() < s.byID[oldest].lastActivity() {
			oldest = id
		}
	}
	if count < maxSessionsPerDevice {
		return 0, false
	}
	return uint8(oldest), true
}
