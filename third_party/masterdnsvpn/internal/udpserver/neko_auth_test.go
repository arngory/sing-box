package udpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func nekoAuthTag(key, msg []byte, at time.Time) (tag [security.AuthTagLen]byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("dnsauth1"))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(at.Unix()/600)))
	mac.Write(msg)
	copy(tag[:], mac.Sum(nil))
	return tag
}

// nekoAuthenticator is niko-server's part for the tests: the devices' keys, the epochs around now
type nekoAuthenticator struct {
	mu      sync.Mutex
	keys    map[string][]byte
	scans   [3]int
	revoked map[string]bool
}

func (a *nekoAuthenticator) holds(key []byte, tag [security.AuthTagLen]byte, msg []byte) bool {
	now := time.Now()
	for _, at := range []time.Time{now, now.Add(-10 * time.Minute), now.Add(10 * time.Minute)} {
		if want := nekoAuthTag(key, msg, at); hmac.Equal(want[:], tag[:]) {
			return true
		}
	}
	return false
}

func (a *nekoAuthenticator) Device(id string, tag [security.AuthTagLen]byte, msg []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.revoked[id] && a.keys[id] != nil && a.holds(a.keys[id], tag, msg)
}

func (a *nekoAuthenticator) Scan(kind int, tag [security.AuthTagLen]byte, msg []byte) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scans[kind]++
	for id, key := range a.keys {
		if !a.revoked[id] && a.holds(key, tag, msg) {
			return id, true
		}
	}
	return "", false
}

// nekoDevice is a client's codec: the service's key, tagged with a device's key (nil: an old client)
func nekoDevice(t *testing.T, deviceKey []byte) *security.Codec {
	t.Helper()
	codec, err := security.NewCodec(5, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if deviceKey != nil {
		err = codec.SetTagger(func(nonce, frame []byte) [security.AuthTagLen]byte {
			return nekoAuthTag(deviceKey, append(append([]byte(nil), nonce...), frame...), time.Now())
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return codec
}

func nekoAuthServer(t *testing.T, mode uint8) (*Server, *nekoAuthenticator) {
	server, _ := nekoTestServer(t, map[string]any{"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": 1232})
	auth := &nekoAuthenticator{
		keys:    map[string][]byte{"phone": []byte("phone key, 32 bytes of it ......"), "tablet": []byte("tablet key, 32 bytes of it .....")},
		revoked: map[string]bool{},
	}
	if err := server.SetAuth(mode, auth); err != nil {
		t.Fatal(err)
	}
	return server, auth
}

func nekoProbeAnswered(t *testing.T, server *Server, codec *security.Codec) bool {
	t.Helper()
	answer := server.handlePacket(nekoProbe(t, codec, mtuProbeModeRaw, 300))
	packet, err := DnsParser.ExtractVPNResponse(answer, false)
	if err != nil && !errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
		t.Fatal(err)
	}
	return err == nil && packet.PacketType == Enums.PACKET_MTU_DOWN_RES
}

// nekoInit sets a session up: its ID and cookie, false when not answered
func nekoInit(t *testing.T, server *Server, codec *security.Codec, verify byte) (uint8, uint8, bool) {
	t.Helper()
	payload := make([]byte, sessionInitDataSize)
	binary.BigEndian.PutUint16(payload[2:4], 150)
	binary.BigEndian.PutUint16(payload[4:6], 400)
	payload[6], payload[7], payload[8], payload[9] = verify, 1, 2, 3
	answer := server.handlePacket(nekoQuery(t, codec, VpnProto.BuildOptions{PacketType: Enums.PACKET_SESSION_INIT, Payload: payload}))
	packet, err := DnsParser.ExtractVPNResponse(answer, false)
	if err != nil || packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
		return 0, 0, false
	}
	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return accept.SessionID, accept.SessionCookie, true
}

// nekoPing is a ping in the session: true when answered (a PONG or what it queued), false for the empty answer
func nekoPing(t *testing.T, server *Server, codec *security.Codec, id, cookie uint8) (VpnProto.Packet, bool) {
	t.Helper()
	answer := server.handlePacket(nekoQuery(t, codec, VpnProto.BuildOptions{
		SessionID: id, SessionCookie: cookie, PacketType: Enums.PACKET_PING, Payload: []byte("ping"),
	}))
	packet, err := DnsParser.ExtractVPNResponse(answer, false)
	return packet, err == nil
}

// neko: dnsauth-masterdns §4: what each mode serves a tagged query of a device, one of an unknown key, an old client's
func TestNekoAuthModes(t *testing.T) {
	phone := []byte("phone key, 32 bytes of it ......")
	stranger := []byte("not a device of this node ......")
	for _, c := range []struct {
		name                  string
		mode                  uint8
		device, unknown, open bool
	}{
		{"off", authOff, false, false, true},
		{"optional", authOptional, true, false, true},
		{"required", authRequired, true, false, false},
	} {
		server, _ := nekoAuthServer(t, c.mode)
		if got := nekoProbeAnswered(t, server, nekoDevice(t, phone)); got != c.device {
			t.Fatalf("%s: a device's probe answered %v", c.name, got)
		}
		if got := nekoProbeAnswered(t, server, nekoDevice(t, stranger)); got != c.unknown {
			t.Fatalf("%s: an unknown key's probe answered %v", c.name, got)
		}
		if got := nekoProbeAnswered(t, server, nekoDevice(t, nil)); got != c.open {
			t.Fatalf("%s: an untagged probe answered %v", c.name, got)
		}
	}
	server, _ := nekoTestServer(t, nil)
	if err := server.SetAuth(authRequired, nil); err == nil {
		t.Fatal("auth without an authenticator")
	}
	for _, method := range []int{0, 1, 2} {
		server, _ := nekoTestServer(t, map[string]any{"DATA_ENCRYPTION_METHOD": method})
		codec, _ := security.NewCodec(method, "0123456789abcdef0123456789abcdef")
		server.codec = codec
		if err := server.SetAuth(authOptional, &nekoAuthenticator{}); !errors.Is(err, security.ErrAuthNeedsAEAD) {
			t.Fatalf("method %d: %v", method, err)
		}
	}
}

// neko: §3.3, §3.5, §4: a session is its device's; another's tag, an untagged query, a revoked device get nothing
func TestNekoAuthSessionBound(t *testing.T) {
	for _, mode := range []uint8{authOptional, authRequired} {
		server, auth := nekoAuthServer(t, mode)
		phone := nekoDevice(t, auth.keys["phone"])
		id, cookie, ok := nekoInit(t, server, phone, 1)
		if !ok {
			t.Fatalf("mode %d: no session for the phone", mode)
		}
		if device, live := server.sessions.deviceOf(id, cookie); device != "phone" || !live {
			t.Fatalf("mode %d: session of %q", mode, device)
		}
		scansBefore := auth.scans
		if _, ok := nekoPing(t, server, phone, id, cookie); !ok {
			t.Fatalf("mode %d: the phone's ping in its session", mode)
		}
		if auth.scans != scansBefore {
			t.Fatalf("mode %d: a bound session's query scanned the keys", mode)
		}
		if _, ok := nekoPing(t, server, nekoDevice(t, auth.keys["tablet"]), id, cookie); ok {
			t.Fatalf("mode %d: the tablet's ping in the phone's session", mode)
		}
		if _, ok := nekoPing(t, server, nekoDevice(t, nil), id, cookie); ok {
			t.Fatalf("mode %d: an untagged ping in the phone's session", mode)
		}
		// the same INIT again: the same session for the phone only
		if again, _, ok := nekoInit(t, server, phone, 1); !ok || again != id {
			t.Fatalf("mode %d: the phone's INIT again: %d %v", mode, again, ok)
		}
		if other, _, ok := nekoInit(t, server, nekoDevice(t, auth.keys["tablet"]), 1); ok && other == id {
			t.Fatalf("mode %d: the tablet got the phone's session by its INIT", mode)
		}
		auth.mu.Lock()
		auth.revoked["phone"] = true
		auth.mu.Unlock()
		if _, ok := nekoPing(t, server, phone, id, cookie); ok {
			t.Fatalf("mode %d: a revoked device's ping", mode)
		}
	}
	// optional: an old client's session stays open to it
	server, _ := nekoAuthServer(t, authOptional)
	old := nekoDevice(t, nil)
	id, cookie, ok := nekoInit(t, server, old, 9)
	if !ok {
		t.Fatal("no session for an old client in optional")
	}
	if device, _ := server.sessions.deviceOf(id, cookie); device != "" {
		t.Fatalf("an old client's session bound to %q", device)
	}
	if _, ok := nekoPing(t, server, old, id, cookie); !ok {
		t.Fatal("an old client's ping in its session")
	}
}

// neko: §3.5: a device holds four live sessions, a fifth closes its oldest; another device's stay
func TestNekoAuthSessionsPerDevice(t *testing.T) {
	server, auth := nekoAuthServer(t, authRequired)
	phone := nekoDevice(t, auth.keys["phone"])
	tablet := nekoDevice(t, auth.keys["tablet"])
	tabletID, tabletCookie, ok := nekoInit(t, server, tablet, 100)
	if !ok {
		t.Fatal("no session for the tablet")
	}
	type session struct{ id, cookie uint8 }
	var sessions []session
	for verify := byte(1); verify <= maxSessionsPerDevice+1; verify++ {
		id, cookie, ok := nekoInit(t, server, phone, verify)
		if !ok {
			t.Fatalf("INIT %d", verify)
		}
		sessions = append(sessions, session{id, cookie})
		time.Sleep(2 * time.Millisecond)
	}
	if _, live := server.sessions.deviceOf(sessions[0].id, sessions[0].cookie); live {
		t.Fatal("the phone's oldest session is still live")
	}
	for _, s := range sessions[1:] {
		if device, live := server.sessions.deviceOf(s.id, s.cookie); !live || device != "phone" {
			t.Fatalf("session %d: %q %v", s.id, device, live)
		}
	}
	if device, live := server.sessions.deviceOf(tabletID, tabletCookie); !live || device != "tablet" {
		t.Fatal("the tablet's session went with the phone's")
	}
	// the closed one keeps its device: the phone's query to it gets its ERROR_DROP, the tablet's nothing
	packet, ok := nekoPing(t, server, phone, sessions[0].id, sessions[0].cookie)
	if !ok || packet.PacketType != Enums.PACKET_ERROR_DROP {
		t.Fatalf("the phone's query to its closed session: %v %d", ok, packet.PacketType)
	}
	if _, ok := nekoPing(t, server, tablet, sessions[0].id, sessions[0].cookie); ok {
		t.Fatal("the tablet's query to the phone's closed session answered")
	}
}

// neko: §3.6: a query before a session is served up to 3 times in 30 s, by its decoded bytes; only one whose tag held
// is noted
func TestNekoAuthNonceRepeats(t *testing.T) {
	memory := newNonceMemory()
	nonce := []byte("twelve bytes")
	now := time.Now()
	for i := 1; i <= nonceRepeats; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		if !memory.servable(nonce, at) {
			t.Fatalf("sight %d refused", i)
		}
		memory.note(nonce, at)
	}
	if memory.servable(nonce, now.Add(5*time.Second)) {
		t.Fatal("a fourth sight served")
	}
	other := []byte("other twelve")
	memory.note(other, now)
	if memory.servable(other, now.Add(31*time.Second)) {
		t.Fatal("a repeat after 30 s served")
	}
	// kept longer than a tag holds (its epoch and one next to it, the client's clock 10 minutes off): through the
	// first turn of the generations, gone after the second
	late := []byte("late twelve.")
	memory.note(late, now)
	for _, after := range []time.Duration{15*time.Minute + time.Second, 31 * time.Minute, 59 * time.Minute} {
		if memory.servable(late, now.Add(after)) {
			t.Fatalf("a nonce forgotten after %v", after)
		}
	}
	if memory.servable([]byte("short"), now) {
		t.Fatal("a nonce of another length")
	}
}

// neko: the review's flush: queries whose tag does not hold (junk with the service's key, or past the budget) note
// nothing, so they never wash a noted nonce out; a generation full refuses new nonces rather than forget old ones
func TestNekoAuthNonceNotFlushed(t *testing.T) {
	memory := newNonceMemory()
	now := time.Now()
	victim := []byte("victim probe")
	memory.note(victim, now)
	junk := make([]byte, nonceKeyLen)
	for i := 0; i < 3*nonceGenerationCap; i++ {
		binary.BigEndian.PutUint64(junk, uint64(i))
		memory.servable(junk, now) // a scan that fails: nothing noted
	}
	if len(memory.current) != 1 || memory.servable(victim, now.Add(time.Minute)) {
		t.Fatalf("%d noted, the victim's nonce served again", len(memory.current))
	}
	// full of nonces whose tag held: the new are refused, the noted stay
	for i := 0; len(memory.current) < nonceGenerationCap; i++ {
		binary.BigEndian.PutUint64(junk, uint64(i))
		memory.note(junk, now)
	}
	if memory.servable([]byte("a new one..."), now) {
		t.Fatal("a new nonce served with the generation full")
	}
	if memory.servable(victim, now.Add(time.Minute)) {
		t.Fatal("the victim's nonce served again with the generation full")
	}

	// through the server: probes of an unknown key, then the device's probe four times
	server, auth := nekoAuthServer(t, authRequired)
	stranger := nekoDevice(t, []byte("not a device of this node ......"))
	for i := 0; i < 20; i++ {
		if nekoProbeAnswered(t, server, stranger) {
			t.Fatal("a stranger's probe answered")
		}
	}
	if n := len(server.authNonces.current); n != 0 {
		t.Fatalf("%d nonces noted for tags that did not hold", n)
	}
	query := nekoProbe(t, nekoDevice(t, auth.keys["phone"]), mtuProbeModeRaw, 300)
	for i := 1; i <= nonceRepeats+1; i++ {
		_, err := DnsParser.ExtractVPNResponse(server.handlePacket(query), false)
		if (err == nil) != (i <= nonceRepeats) {
			t.Fatalf("copy %d: %v", i, err)
		}
	}
}

// neko: the review: a scan that names no device is no device's
func TestNekoAuthEmptyScan(t *testing.T) {
	server, _ := nekoTestServer(t, map[string]any{"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": 1232})
	if err := server.SetAuth(authRequired, nekoEmptyAuthenticator{}); err != nil {
		t.Fatal(err)
	}
	if nekoProbeAnswered(t, server, nekoDevice(t, []byte("phone key, 32 bytes of it ......"))) {
		t.Fatal("a probe answered for a scan of no device")
	}
}

type nekoEmptyAuthenticator struct{}

func (nekoEmptyAuthenticator) Device(string, [security.AuthTagLen]byte, []byte) bool { return true }
func (nekoEmptyAuthenticator) Scan(int, [security.AuthTagLen]byte, []byte) (string, bool) {
	return "", true
}

// neko: §3.5: an INIT's reuse is its device's entry, another device's same INIT takes none of it; a device at its
// limit gives up the session silent longest
func TestNekoAuthReuseAndIdlest(t *testing.T) {
	server, auth := nekoAuthServer(t, authRequired)
	phone := nekoDevice(t, auth.keys["phone"])
	tablet := nekoDevice(t, auth.keys["tablet"])
	first, _, ok := nekoInit(t, server, phone, 1)
	if !ok {
		t.Fatal("no session for the phone")
	}
	other, _, ok := nekoInit(t, server, tablet, 1)
	if !ok || other == first {
		t.Fatalf("the tablet's same INIT: %d %v", other, ok)
	}
	if again, _, ok := nekoInit(t, server, phone, 1); !ok || again != first {
		t.Fatalf("the phone's INIT again after the tablet's: %d, want %d", again, first)
	}

	type session struct{ id, cookie uint8 }
	sessions := []session{}
	for verify := byte(10); verify < 10+maxSessionsPerDevice-1; verify++ {
		id, cookie, ok := nekoInit(t, server, phone, verify)
		if !ok {
			t.Fatal("INIT", verify)
		}
		sessions = append(sessions, session{id, cookie})
		time.Sleep(2 * time.Millisecond)
	}
	// the first session is the oldest but the one in use: the next INIT closes the one silent longest
	firstCookie := server.sessions.byID[first].Cookie
	time.Sleep(2 * time.Millisecond)
	if _, ok := nekoPing(t, server, phone, first, firstCookie); !ok {
		t.Fatal("the phone's ping in its first session")
	}
	if _, _, ok := nekoInit(t, server, phone, 99); !ok {
		t.Fatal("the fifth INIT")
	}
	if _, live := server.sessions.deviceOf(first, firstCookie); !live {
		t.Fatal("the session in use was closed")
	}
	if _, live := server.sessions.deviceOf(sessions[0].id, sessions[0].cookie); live {
		t.Fatal("the session silent longest is still live")
	}
}

// neko: the review: the device is checked as the session is used; a query of another device, or none, to a session
// that changed hands between the tag's check and its use gets the empty answer, and closes nothing
func TestNekoAuthDeviceAtUse(t *testing.T) {
	server, auth := nekoAuthServer(t, authOptional)
	id, cookie, ok := nekoInit(t, server, nekoDevice(t, auth.keys["phone"]), 1)
	if !ok {
		t.Fatal("no session for the phone")
	}
	query := nekoQuery(t, nekoDevice(t, nil), VpnProto.BuildOptions{
		SessionID: id, SessionCookie: cookie, PacketType: Enums.PACKET_PING, Payload: []byte("ping"),
	})
	packet := VpnProto.Packet{SessionID: id, SessionCookie: cookie, PacketType: Enums.PACKET_PING}
	if v := server.validatePostSessionPacket(query, nekoTestDomain, packet, "tablet"); v.ok || v.response != nil {
		t.Fatal("another device's query used the phone's session")
	}
	if v := server.validatePostSessionPacket(query, nekoTestDomain, packet, ""); v.ok {
		t.Fatal("an untagged query used the phone's session")
	}
	if v := server.validatePostSessionPacket(query, nekoTestDomain, packet, "phone"); !v.ok {
		t.Fatal("the phone's own query")
	}
	server.handleSessionCloseNotice(packet, time.Now(), "tablet")
	if _, live := server.sessions.deviceOf(id, cookie); !live {
		t.Fatal("another device closed the phone's session")
	}
	server.handleSessionCloseNotice(packet, time.Now(), "phone")
	if _, live := server.sessions.deviceOf(id, cookie); live {
		t.Fatal("the phone could not close its session")
	}
}
