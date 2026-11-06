package udpserver

import (
	"encoding/binary"
	"testing"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// the key nekoTestServer's codec is of, and the one it changes to
const (
	nekoOldKey = "0123456789abcdef0123456789abcdef"
	nekoNewKey = "fedcba9876543210fedcba9876543210"
)

func nekoCodec(t *testing.T, key string) *security.Codec {
	t.Helper()
	codec, err := security.NewCodec(5, key)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func nekoSetKeys(t *testing.T, server *Server, keys ...string) {
	t.Helper()
	if err := server.SetKeys(keys); err != nil {
		t.Fatal(err)
	}
}

// neko: masterdns-key-rotation §3: a session on the previous key goes on after the change, a new one opens on the
// new key; a session's queries open with its own key only; the previous key taken out closes its sessions and opens
// nothing more
func TestNekoKeysRotation(t *testing.T) {
	server, _ := nekoTestServer(t, nil)
	oldCodec, newCodec := nekoCodec(t, nekoOldKey), nekoCodec(t, nekoNewKey)
	nekoSetKeys(t, server, nekoOldKey)
	oldID, oldCookie, ok := nekoInit(t, server, oldCodec, 1)
	if !ok {
		t.Fatal("no session on the old key")
	}
	if _, _, ok := nekoInit(t, server, newCodec, 2); ok {
		t.Fatal("a session on a key the server does not have")
	}

	nekoSetKeys(t, server, nekoNewKey, nekoOldKey)
	if _, ok := nekoPing(t, server, oldCodec, oldID, oldCookie); !ok {
		t.Fatal("the session on the previous key stopped at the change")
	}
	newID, newCookie, ok := nekoInit(t, server, newCodec, 3)
	if !ok {
		t.Fatal("no session on the new key")
	}
	// a session's query opened with the other key is not its: the empty answer, the session untouched
	before := server.sessions.byID[oldID].lastActivity()
	if _, ok := nekoPing(t, server, newCodec, oldID, oldCookie); ok {
		t.Fatal("the old key's session took a query in the new key")
	}
	if _, ok := nekoPing(t, server, oldCodec, newID, newCookie); ok {
		t.Fatal("the new key's session took a query in the old key")
	}
	if server.sessions.byID[oldID] == nil || server.sessions.byID[oldID].lastActivity() != before {
		t.Fatal("a query in another key touched the session")
	}
	// a SESSION_CLOSE in the other key closes nothing
	server.handlePacket(nekoQuery(t, newCodec, VpnProto.BuildOptions{
		SessionID: oldID, SessionCookie: oldCookie, PacketType: Enums.PACKET_SESSION_CLOSE,
	}))
	if _, live := server.sessions.deviceOf(oldID, oldCookie); !live {
		t.Fatal("a close in the new key closed the old key's session")
	}
	// the same INIT in the other key is another session, not the old one reused
	if id, _, ok := nekoInit(t, server, newCodec, 1); !ok || id == oldID {
		t.Fatalf("an INIT in the new key reused the old key's session (%d, %v)", id, ok)
	}

	// the previous key out: its sessions close, its queries open no more; the new key's go on
	kept := server.currentKeys()[0]
	nekoSetKeys(t, server, nekoNewKey)
	if server.currentKeys()[0] != kept {
		t.Fatal("a key kept became another")
	}
	if _, live := server.sessions.deviceOf(oldID, oldCookie); live {
		t.Fatal("the session on the key taken out is live")
	}
	if _, ok := nekoPing(t, server, oldCodec, oldID, oldCookie); ok {
		t.Fatal("a query in the key taken out was answered")
	}
	if _, _, ok := nekoInit(t, server, oldCodec, 4); ok {
		t.Fatal("a session opened on the key taken out")
	}
	if _, ok := nekoPing(t, server, newCodec, newID, newCookie); !ok {
		t.Fatal("the new key's session stopped")
	}
}

// neko: §3: what SetKeys refuses
func TestNekoKeysRefused(t *testing.T) {
	server, _ := nekoTestServer(t, nil)
	for name, keys := range map[string][]string{
		"none":        nil,
		"three":       {nekoOldKey, nekoNewKey, "00000000000000000000000000000000"},
		"twice":       {nekoOldKey, nekoOldKey},
		"empty":       {""},
		"a short key": {"short"},
	} {
		if err := server.SetKeys(keys); err == nil {
			t.Fatalf("%s: taken", name)
		}
	}
	// two keys need AES-GCM: no tag tells them apart under the other methods
	open, _ := nekoTestServer(t, map[string]any{"DATA_ENCRYPTION_METHOD": 2})
	if err := open.SetKeys([]string{nekoOldKey, nekoNewKey}); err == nil {
		t.Fatal("two keys under method 2")
	}
	if err := open.SetKeys([]string{nekoNewKey}); err != nil {
		t.Fatalf("one key under method 2: %v", err)
	}
}

// nekoSealedInit is nekoInit asking for sealed answers, its answer opened with keys
func nekoSealedInit(t *testing.T, server *Server, codec *security.Codec, keys *mdseal.Keys, verify byte) (uint8, uint8, bool) {
	t.Helper()
	payload := make([]byte, sessionInitDataSize)
	payload[0] = mtuProbeModeRaw | mdseal.ModeBit
	binary.BigEndian.PutUint16(payload[2:4], 150)
	binary.BigEndian.PutUint16(payload[4:6], 400)
	payload[6], payload[7], payload[8], payload[9] = verify, 1, 2, 3
	answer := server.handlePacket(nekoQuery(t, codec, VpnProto.BuildOptions{PacketType: Enums.PACKET_SESSION_INIT, Payload: payload}))
	packet, _, err := DnsParser.ExtractSealedVPNResponse(answer, false, keys)
	if err != nil || packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
		return 0, 0, false
	}
	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return accept.SessionID, accept.SessionCookie, true
}

// neko: §3: each session's answers are sealed with its own key's seal keys (mdseal-v1 Kd, Kdt of it), a probe's
// with its query's key
func TestNekoKeysSealPerSession(t *testing.T) {
	server, _ := nekoTestServer(t, map[string]any{"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": 1232})
	if err := server.SetSeal(sealRequired, nekoOldKey); err != nil {
		t.Fatal(err)
	}
	first := server.currentKeys()[0]
	nekoSetKeys(t, server, nekoOldKey)
	if server.currentKeys()[0] != first {
		t.Fatal("SetKeys made the sealed key anew")
	}
	oldCodec, newCodec := nekoCodec(t, nekoOldKey), nekoCodec(t, nekoNewKey)
	oldSeal, _ := mdseal.NewKeys(nekoOldKey)
	newSeal, _ := mdseal.NewKeys(nekoNewKey)
	oldID, oldCookie, ok := nekoSealedInit(t, server, oldCodec, oldSeal, 1)
	if !ok {
		t.Fatal("no sealed session on the old key")
	}
	nekoSetKeys(t, server, nekoNewKey, nekoOldKey)
	newID, newCookie, ok := nekoSealedInit(t, server, newCodec, newSeal, 2)
	if !ok {
		t.Fatal("no sealed session on the new key, its answer sealed with the new key")
	}
	ping := func(codec *security.Codec, id, cookie uint8) []byte {
		return server.handlePacket(nekoQuery(t, codec, VpnProto.BuildOptions{
			SessionID: id, SessionCookie: cookie, PacketType: Enums.PACKET_PING, Payload: []byte("ping"),
		}))
	}
	for _, c := range []struct {
		name        string
		answer      []byte
		own, others *mdseal.Keys
	}{
		{"the old key's session", ping(oldCodec, oldID, oldCookie), oldSeal, newSeal},
		{"the new key's session", ping(newCodec, newID, newCookie), newSeal, oldSeal},
		{"a probe in the old key", server.handlePacket(nekoProbe(t, oldCodec, mtuProbeModeRaw|mdseal.ModeBit, 600)), oldSeal, newSeal},
		{"a probe in the new key", server.handlePacket(nekoProbe(t, newCodec, mtuProbeModeRaw|mdseal.ModeBit, 600)), newSeal, oldSeal},
	} {
		if _, _, err := DnsParser.ExtractSealedVPNResponse(c.answer, false, c.own); err != nil {
			t.Fatalf("%s: its answer does not open with its key: %v", c.name, err)
		}
		if _, _, err := DnsParser.ExtractSealedVPNResponse(c.answer, false, c.others); err == nil {
			t.Fatalf("%s: its answer opens with the other key", c.name)
		}
	}
}

// neko: SetKeys while queries are handled (niko-server calls it from its file watcher): no race, and a session on a
// key kept throughout is never dropped
func TestNekoKeysChangeWhileServing(t *testing.T) {
	server, _ := nekoTestServer(t, nil)
	newCodec := nekoCodec(t, nekoNewKey)
	nekoSetKeys(t, server, nekoNewKey)
	id, cookie, ok := nekoInit(t, server, newCodec, 1)
	if !ok {
		t.Fatal("no session")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			keys := []string{nekoNewKey, nekoOldKey}
			if i%2 == 1 {
				keys = keys[:1]
			}
			if err := server.SetKeys(keys); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		if _, ok := nekoPing(t, server, newCodec, id, cookie); !ok {
			t.Fatalf("ping %d: the session on the kept key dropped", i)
		}
	}
	<-done
}

// neko: the review: a SESSION_INIT opened with a key that SetKeys took out before the session was made sets nothing
// up (it would outlive the close of its key's sessions), and the close goes by the key, not by an ID read earlier
func TestNekoKeysInitOnAKeyTakenOut(t *testing.T) {
	server, _ := nekoTestServer(t, nil)
	nekoSetKeys(t, server, nekoNewKey, nekoOldKey)
	keys := server.currentKeys()
	newKey, oldKey := keys[0], keys[1]
	payload := make([]byte, sessionInitDataSize)
	payload[2], payload[3], payload[4], payload[5] = 0, 150, 1, 144
	payload[6] = 9
	init := func(key *serviceKey) (*sessionRecord, error) {
		record, _, _, err := server.sessions.findOrCreate(payload, 0, 0, 1, 1000, 1000, "", key, time.Minute)
		return record, err
	}
	// the query opened with the old key while it was listed; the key goes before the session is made
	nekoSetKeys(t, server, nekoNewKey)
	if record, err := init(oldKey); record != nil || err != nil {
		t.Fatalf("a session on a key taken out: %v %v", record, err)
	}
	kept, err := init(newKey)
	if kept == nil || err != nil {
		t.Fatalf("no session on the key kept: %v", err)
	}
	// closing by the key leaves the kept key's sessions, whatever slot they took
	if closed := server.sessions.closeKeysNotIn(map[*serviceKey]bool{newKey: true}, time.Now(), time.Minute); len(closed) != 0 {
		t.Fatalf("closed %d sessions of the key kept", len(closed))
	}
	if server.sessions.byID[kept.ID] == nil {
		t.Fatal("the kept key's session is gone")
	}
}
