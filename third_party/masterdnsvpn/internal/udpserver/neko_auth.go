package udpserver

import (
	"errors"
	"fmt"
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
	if s.codec == nil || s.codec.Method() < 3 {
		return security.ErrAuthNeedsAEAD
	}
	s.authMode, s.auth, s.authNonces = mode, auth, newNonceMemory()
	return nil
}

// openQuery is the packet a query's labels carry, and the device whose tag it bears ("" for none): the cipher opened,
// the tag checked, the frame parsed and inflated. False for a query to answer as undecipherable.
func (s *Server) openQuery(labels string, now time.Time) (VpnProto.Packet, string, bool) {
	if s.authMode == authOff {
		packet, err := VpnProto.ParseInflatedFromLabels(labels, s.codec)
		return packet, "", err == nil
	}
	nonce, plain, err := s.codec.DecodeStringAndOpen(labels)
	if err != nil {
		return VpnProto.Packet{}, "", false
	}
	if len(plain) > security.AuthTagLen {
		frameBytes := plain[security.AuthTagLen:]
		// a frame that does not parse at 8 bears no tag (an old client's, but for about 1 in 1000)
		if frame, err := VpnProto.Parse(frameBytes); err == nil {
			var tag [security.AuthTagLen]byte
			copy(tag[:], plain)
			if device, ok := s.checkTag(tag, nonce, frameBytes, frame, now); ok {
				packet, err := VpnProto.InflatePayload(frame)
				return packet, device, err == nil
			}
		}
	}
	if s.authMode == authRequired {
		return VpnProto.Packet{}, "", false
	}
	// optional: a frame without a tag, an old client's, unless it is about a session a device holds
	frame, err := VpnProto.Parse(plain)
	if err != nil {
		return VpnProto.Packet{}, "", false
	}
	if !isPreSessionRequestType(frame.PacketType) {
		if device, _ := s.sessions.deviceOf(frame.SessionID, frame.SessionCookie); device != "" {
			return VpnProto.Packet{}, "", false
		}
	}
	packet, err := VpnProto.InflatePayload(frame)
	return packet, "", err == nil
}

// checkTag is the device whose tag a query bears (§3): before a session, by a scan, a request seen too often refused
// first; in a live session, its device's key alone; to a session no longer live, its closed record's device, else a
// scan. A live session of no device (an old client's) takes no tag.
func (s *Server) checkTag(tag [security.AuthTagLen]byte, nonce, frameBytes []byte, frame VpnProto.Packet, now time.Time) (string, bool) {
	msg := make([]byte, 0, len(nonce)+len(frameBytes))
	msg = append(append(msg, nonce...), frameBytes...)
	if isPreSessionRequestType(frame.PacketType) {
		if !s.authNonces.allow(nonce, now) {
			return "", false
		}
		kind := ScanProbe
		if frame.PacketType == Enums.PACKET_SESSION_INIT {
			kind = ScanInit
		}
		return s.auth.Scan(kind, tag, msg)
	}
	device, live := s.sessions.deviceOf(frame.SessionID, frame.SessionCookie)
	switch {
	case device != "":
		return device, s.auth.Device(device, tag, msg)
	case live:
		return "", false
	default:
		return s.auth.Scan(ScanSession, tag, msg)
	}
}

// nonceMemory keeps the nonces of queries before a session for about 30 minutes, in two generations, by the decoded
// bytes (base36 lets different names give the same bytes, §3.6). The same query is served up to 3 times in 30 s from
// its first sight (a client sends a SESSION_INIT to several resolvers in the same bytes, a resolver repeats one);
// past that, or later, it is someone's replay.
type nonceMemory struct {
	mu                sync.Mutex
	current, previous map[[nonceKeyLen]byte]nonceSeen
	rotatedAt         time.Time
}

type nonceSeen struct {
	count uint8
	first int64
}

const (
	nonceKeyLen        = 12
	nonceGeneration    = 15 * time.Minute
	nonceRepeatWindow  = 30 * time.Second
	nonceRepeats       = 3
	nonceGenerationCap = 1 << 17
)

func newNonceMemory() *nonceMemory {
	return &nonceMemory{
		current: make(map[[nonceKeyLen]byte]nonceSeen), previous: make(map[[nonceKeyLen]byte]nonceSeen),
		rotatedAt: time.Now(),
	}
}

// allow is whether a query of this nonce may be served now; it counts the sight
func (m *nonceMemory) allow(nonce []byte, now time.Time) bool {
	if len(nonce) != nonceKeyLen {
		return false
	}
	key := [nonceKeyLen]byte(nonce)
	m.mu.Lock()
	defer m.mu.Unlock()
	// a generation full turns early: memory stays bounded under a flood, the window shorter then
	if now.Sub(m.rotatedAt) >= nonceGeneration || len(m.current) >= nonceGenerationCap {
		m.previous, m.current, m.rotatedAt = m.current, make(map[[nonceKeyLen]byte]nonceSeen), now
	}
	seen, ok := m.current[key]
	if !ok {
		seen, ok = m.previous[key]
	}
	if !ok {
		m.current[key] = nonceSeen{count: 1, first: now.UnixNano()}
		return true
	}
	if seen.count >= nonceRepeats || now.UnixNano()-seen.first > int64(nonceRepeatWindow) {
		return false
	}
	seen.count++
	m.current[key] = seen
	return true
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

// oldestOfDeviceLocked is the live session device holds longest, when it holds maxSessionsPerDevice or more
func (s *sessionStore) oldestOfDeviceLocked(device string) (uint8, bool) {
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
		if oldest < 0 || record.CreatedAt.Before(s.byID[oldest].CreatedAt) {
			oldest = id
		}
	}
	if count < maxSessionsPerDevice {
		return 0, false
	}
	return uint8(oldest), true
}
