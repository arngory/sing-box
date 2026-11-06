package udpserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const nekoSealKey = "0123456789abcdef0123456789abcdef"

// nekoQuery is a client's query carrying frame, encrypted with the codec, with an OPT of 1232.
func nekoQuery(t *testing.T, codec *security.Codec, options VpnProto.BuildOptions) []byte {
	t.Helper()
	frame, err := VpnProto.BuildRaw(options)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := codec.EncryptAndEncodeBytes(frame)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(nekoTestDomain, encoded, Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func nekoProbe(t *testing.T, codec *security.Codec, mode uint8, size int) []byte {
	// padded as Niko pads its probes, to a name the zone still takes
	payload := make([]byte, 100)
	payload[0] = mode
	copy(payload[1:], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(payload[mtuProbeUpMinSize:], uint16(size))
	return nekoQuery(t, codec, VpnProto.BuildOptions{
		SessionID: 255, PacketType: Enums.PACKET_MTU_DOWN_REQ, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload,
	})
}

func nekoSealedServer(t *testing.T, mode uint8) (*Server, *security.Codec, *mdseal.Keys) {
	server, codec := nekoTestServer(t, map[string]any{"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": 1232})
	if err := server.SetSeal(mode, nekoSealKey); err != nil {
		t.Fatal(err)
	}
	keys, _ := mdseal.NewKeys(nekoSealKey)
	return server, codec, keys
}

// neko: mdseal-v1 §4, §5: what each mode answers a probe asking for the seal and one not asking
func TestNekoSealProbeModes(t *testing.T) {
	for _, c := range []struct {
		name         string
		mode         uint8
		open, sealed bool // answered
	}{
		{"off", sealOff, true, false},
		{"optional", sealOptional, true, true},
		{"required", sealRequired, false, true},
	} {
		server, codec, keys := nekoSealedServer(t, c.mode)
		for _, encoding := range []uint8{mtuProbeModeRaw, mtuProbeModeBase64} {
			base := encoding == mtuProbeModeBase64
			answer := server.handlePacket(nekoProbe(t, codec, encoding, 600))
			if packet, err := DnsParser.ExtractVPNResponse(answer, base); c.open != (err == nil) {
				t.Fatalf("%s, base64 %v: open probe answered %v (%v)", c.name, base, err == nil, err)
			} else if err == nil && (packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) != 600) {
				t.Fatalf("%s: open probe's answer %d, %d bytes", c.name, packet.PacketType, len(packet.Payload))
			}
			answer = server.handlePacket(nekoProbe(t, codec, encoding|mdseal.ModeBit, 600))
			packet, err := DnsParser.ExtractSealedVPNResponse(answer, base, keys)
			if c.sealed != (err == nil) {
				t.Fatalf("%s, base64 %v: sealed probe answered %v (%v)", c.name, base, err == nil, err)
			}
			if err == nil {
				if packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) != 600 {
					t.Fatalf("%s: sealed probe's answer %d, %d bytes", c.name, packet.PacketType, len(packet.Payload))
				}
				// nothing of it reads open
				if _, err := DnsParser.ExtractVPNResponse(answer, base); err == nil {
					if open, _ := DnsParser.ExtractVPNResponse(answer, base); open.PacketType == Enums.PACKET_MTU_DOWN_RES {
						t.Fatalf("%s: a sealed answer read open", c.name)
					}
				}
			}
		}
		// an unknown encoding stays refused, sealed or not: an answer without a record
		for _, mode := range []uint8{2, 2 | mdseal.ModeBit} {
			answer := server.handlePacket(nekoProbe(t, codec, mode, 600))
			if _, err := DnsParser.ExtractVPNResponse(answer, false); !errors.Is(err, DnsParser.ErrTXTAnswerMissing) && answer != nil {
				t.Fatalf("%s: encoding %#x answered (%v)", c.name, mode, err)
			}
		}
	}
}

// neko: an ERROR_DROP to a session the node does not know is raw every time (sealed in required), its payload random;
// upstream alternated raw and base64 and put a counter in it
func TestNekoUnknownSessionDrop(t *testing.T) {
	for _, mode := range []uint8{sealOff, sealOptional, sealRequired} {
		server, codec, keys := nekoSealedServer(t, mode)
		payloads := map[string]bool{}
		for i := 0; i < 6; i++ {
			query := nekoQuery(t, codec, VpnProto.BuildOptions{
				SessionID: 77, SessionCookie: 5, PacketType: Enums.PACKET_PING, Payload: []byte("ping"),
			})
			answer := server.handlePacket(query)
			var packet VpnProto.Packet
			var err error
			if mode == sealRequired {
				packet, err = DnsParser.ExtractSealedVPNResponse(answer, false, keys)
			} else {
				packet, err = DnsParser.ExtractVPNResponse(answer, false)
			}
			if err != nil || packet.PacketType != Enums.PACKET_ERROR_DROP || packet.SessionID != 77 {
				t.Fatalf("mode %d, drop %d: %v, type %d, session %d", mode, i, err, packet.PacketType, packet.SessionID)
			}
			if bytes.HasPrefix(packet.Payload, []byte("INV")) {
				t.Fatalf("mode %d: the marker is back", mode)
			}
			payloads[string(packet.Payload)] = true
		}
		if len(payloads) != 6 {
			t.Fatalf("mode %d: %d different payloads of 6", mode, len(payloads))
		}
	}
}

// neko: a session's sealed answers stay within the S of its probe answer at its download MTU
func TestNekoSessionSealCap(t *testing.T) {
	for _, mtu := range []int{200, 500, 900, 1150} {
		cap := sessionSealCap(mtu)
		if cap%mdseal.Block != 0 || cap < mdseal.Overhead+VpnProto.HeaderRawSize(Enums.PACKET_MTU_DOWN_RES)+mtu || cap-mdseal.Block >= mdseal.Overhead+VpnProto.HeaderRawSize(Enums.PACKET_MTU_DOWN_RES)+mtu {
			t.Fatalf("MTU %d: cap %d", mtu, cap)
		}
	}
	keys, _ := mdseal.NewKeys(nekoSealKey)
	query, _ := DnsParser.BuildTXTQuestionPacket("abcdefgh."+nekoTestDomain, Enums.DNS_RECORD_TYPE_TXT, 4096)
	cap := sessionSealCap(500)
	for payload := 400; payload <= 520; payload += 7 {
		answer, err := DnsParser.BuildSealedVPNResponsePacket(query, "abcdefgh."+nekoTestDomain, VpnProto.Packet{
			SessionID: 1, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 2, SequenceNum: 3, Payload: bytes.Repeat([]byte{4}, payload),
		}, false, keys, cap)
		if err != nil {
			t.Fatal(err)
		}
		frameLen := VpnProto.HeaderRawSize(Enums.PACKET_STREAM_DATA) + payload
		sized, _ := DnsParser.SealedAnswerLen(query, "abcdefgh."+nekoTestDomain, max(cap, mdseal.Overhead+frameLen), false)
		if len(answer) > sized {
			t.Fatalf("payload %d: %d bytes past the cap's %d", payload, len(answer), sized)
		}
	}
}

func TestNekoParseSealMode(t *testing.T) {
	for name, want := range map[string]uint8{"": sealOff, "off": sealOff, "Optional": sealOptional, " required ": sealRequired} {
		if got, err := ParseSealMode(name); err != nil || got != want {
			t.Fatalf("%q: %d %v", name, got, err)
		}
	}
	if _, err := ParseSealMode("v1"); err == nil {
		t.Fatal("an unknown mode taken")
	}
	server, _ := nekoTestServer(t, nil)
	if err := server.SetSeal(sealRequired, ""); err == nil {
		t.Fatal("a seal without a key")
	}
}
