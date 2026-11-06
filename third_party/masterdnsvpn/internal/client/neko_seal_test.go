package client

import (
	"errors"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func nekoKeys(t *testing.T) *mdseal.Keys {
	t.Helper()
	keys, err := mdseal.NewKeys("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// neko: the mode byte a client asks for: its encoding, bit 7 with the seal; a reset session asks for it again
func TestNekoConfiguredResponseMode(t *testing.T) {
	keys := nekoKeys(t)
	for _, c := range []struct {
		base bool
		keys *mdseal.Keys
		want uint8
	}{
		{false, nil, 0x00}, {true, nil, 0x01}, {false, keys, 0x80}, {true, keys, 0x81},
	} {
		client := &Client{cfg: config.ClientConfig{BaseEncodeData: c.base}, sealKeys: c.keys}
		if got := client.configuredResponseMode(); got != c.want {
			t.Fatalf("base64 %v, sealed %v: %#x", c.base, c.keys != nil, got)
		}
		client.responseMode.Store(0x7f)
		client.resetSessionState(true)
		if got := uint8(client.responseMode.Load()); got != c.want {
			t.Fatalf("after a reset, base64 %v, sealed %v: %#x", c.base, c.keys != nil, got)
		}
	}
}

// neko: what a client takes from an answer in each mode: sealed answers opened; an open one only as an ERROR_DROP to
// a session the node no longer knows, in either encoding, and never in required
func TestNekoExtractResponse(t *testing.T) {
	keys := nekoKeys(t)
	query, err := DnsParser.BuildTXTQuestionPacket("abcdefgh.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	data := VpnProto.Packet{SessionID: 3, SessionCookie: 9, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, Payload: []byte("data")}
	drop := VpnProto.Packet{SessionID: 3, PacketType: Enums.PACKET_ERROR_DROP, Payload: []byte("12345678")}
	open := func(packet VpnProto.Packet, base bool) []byte {
		answer, err := DnsParser.BuildVPNResponsePacket(query, "abcdefgh.v.example.com", packet, base)
		if err != nil {
			t.Fatal(err)
		}
		return answer
	}
	sealed := func(packet VpnProto.Packet, base bool) []byte {
		answer, err := DnsParser.BuildSealedVPNResponsePacket(query, "abcdefgh.v.example.com", packet, base, keys, 0)
		if err != nil {
			t.Fatal(err)
		}
		return answer
	}
	for _, c := range []struct {
		name     string
		mode     uint8
		keys     *mdseal.Keys
		required bool
		answer   []byte
		want     uint8 // the packet's type, 0: refused
	}{
		{"open raw", 0x00, nil, false, open(data, false), Enums.PACKET_STREAM_DATA},
		{"open base64", 0x01, nil, false, open(data, true), Enums.PACKET_STREAM_DATA},
		{"a raw ERROR_DROP to a base64 session", 0x01, nil, false, open(drop, false), Enums.PACKET_ERROR_DROP},
		{"open data in the other encoding", 0x01, nil, false, open(data, false), 0},
		{"sealed", 0x80, keys, false, sealed(data, false), Enums.PACKET_STREAM_DATA},
		{"sealed base64", 0x81, keys, true, sealed(data, true), Enums.PACKET_STREAM_DATA},
		{"open data to a sealed session", 0x80, keys, false, open(data, false), 0},
		{"an open ERROR_DROP, optional", 0x81, keys, false, open(drop, false), Enums.PACKET_ERROR_DROP},
		{"an open ERROR_DROP, required", 0x80, keys, true, open(drop, false), 0},
		{"a sealed raw ERROR_DROP to a base64 session", 0x81, keys, true, sealed(drop, false), Enums.PACKET_ERROR_DROP},
		{"sealed raw data to a base64 session", 0x81, keys, true, sealed(data, false), 0},
	} {
		client := &Client{sealKeys: c.keys, sealRequired: c.required}
		client.noteSentQuery(query)
		packet, err := client.extractResponse(c.answer, c.mode)
		if c.want == 0 {
			if err == nil {
				t.Fatalf("%s: took %d", c.name, packet.PacketType)
			}
			continue
		}
		if err != nil || packet.PacketType != c.want {
			t.Fatalf("%s: %v, type %d", c.name, err, packet.PacketType)
		}
	}
	// an answer without a record stays what it is, for the resolver's count
	empty, _ := DnsParser.BuildEmptyNoErrorResponse(query)
	client := &Client{sealKeys: keys, sealRequired: true}
	if _, err := client.extractResponse(empty, 0x80); !errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
		t.Fatalf("an empty answer: %v", err)
	}
}

// neko: a sealed answer is taken only as the answer to a query this client sent lately, once: one seen on the path and
// sent again as it was (its question and seal with it) is lost, as is an answer to a query never sent or sent long ago
func TestNekoSealedReplay(t *testing.T) {
	keys := nekoKeys(t)
	query, _ := DnsParser.BuildTXTQuestionPacket("abcdefgh.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	drop := VpnProto.Packet{SessionID: 3, PacketType: Enums.PACKET_ERROR_DROP, Payload: []byte("12345678")}
	sealed, err := DnsParser.BuildSealedVPNResponsePacket(query, "abcdefgh.v.example.com", drop, false, keys, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []bool{false, true} {
		client := &Client{sealKeys: keys, sealRequired: required, sessionID: 3, sessionReady: true}
		// never sent: the node's answer to another client of the service, or an old one of this client's
		if _, err := client.extractResponse(sealed, 0x80); !errors.Is(err, ErrNotOurs) {
			t.Fatalf("required %v: an answer to a query never sent: %v", required, err)
		}
		client.noteSentQuery(query)
		if packet, err := client.extractResponse(sealed, 0x80); err != nil || packet.PacketType != Enums.PACKET_ERROR_DROP {
			t.Fatalf("required %v: the answer to the query sent: %v", required, err)
		}
		// the same answer again, as it was: its query is answered
		if _, err := client.extractResponse(sealed, 0x80); !errors.Is(err, ErrNotOurs) {
			t.Fatalf("required %v: a verbatim replay taken: %v", required, err)
		}
		if client.runtimeResetPending.Load() {
			t.Fatal("extractResponse restarted the session itself")
		}
	}
	// an open ERROR_DROP in optional: the same rule
	open, _ := DnsParser.BuildVPNResponsePacket(query, "abcdefgh.v.example.com", drop, false)
	client := &Client{sealKeys: keys}
	if _, err := client.extractResponse(open, 0x80); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("an open ERROR_DROP to a query never sent: %v", err)
	}
	// a query sent too long ago: past both generations
	var sent sentQueries
	now := time.Now()
	sent.note("abcdefgh.v.example.com", now)
	if !sent.take("abcdefgh.v.example.com", now.Add(sentQueryWindow+time.Second)) {
		t.Fatal("an answer within the second generation lost")
	}
	var old sentQueries
	old.note("abcdefgh.v.example.com", now)
	old.take("x", now.Add(sentQueryWindow))
	if old.take("abcdefgh.v.example.com", now.Add(2*sentQueryWindow+time.Second)) {
		t.Fatal("an answer past both generations taken")
	}
}

// neko: an ERROR_DROP restarts the session it is about only
func TestNekoHandleErrorDrop(t *testing.T) {
	client := &Client{sessionID: 5, sessionReady: true}
	client.HandleErrorDrop(VpnProto.Packet{SessionID: 6, PacketType: Enums.PACKET_ERROR_DROP})
	if client.runtimeResetPending.Load() {
		t.Fatal("another session's ERROR_DROP restarted this one")
	}
	client.HandleErrorDrop(VpnProto.Packet{SessionID: 5, PacketType: Enums.PACKET_ERROR_DROP})
	if !client.runtimeResetPending.Load() {
		t.Fatal("this session's ERROR_DROP restarted nothing")
	}
	// no session yet: any ERROR_DROP is taken, as upstream
	idle := &Client{}
	idle.HandleErrorDrop(VpnProto.Packet{SessionID: 9, PacketType: Enums.PACKET_ERROR_DROP})
	if !idle.runtimeResetPending.Load() {
		t.Fatal("an ERROR_DROP without a session restarted nothing")
	}
}
