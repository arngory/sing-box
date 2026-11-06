package dnsparser

import (
	"bytes"
	"errors"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func sealKeys(t *testing.T, key string) *mdseal.Keys {
	t.Helper()
	keys, err := mdseal.NewKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// neko: the length the padding is chosen by is the length the answer is built with, for any S, name and encoding
func TestNekoSealedAnswerLen(t *testing.T) {
	query, err := BuildTXTQuestionPacket("abcdefgh.a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"abcdefgh.a.example.com", "b.example.com", "."} {
		for _, base := range []bool{false, true} {
			for sLen := mdseal.Overhead; sLen <= 1400; sLen++ {
				chunks, err := sealedTXTChunks(bytes.Repeat([]byte{0xa5}, sLen), base)
				if err != nil {
					t.Fatal(err)
				}
				answer, err := BuildTXTResponsePacket(query, name, chunks)
				if err != nil {
					t.Fatal(err)
				}
				want, err := SealedAnswerLen(query, name, sLen, base)
				if err != nil {
					t.Fatal(err)
				}
				if len(answer) != want {
					t.Fatalf("%s, base64 %v, S of %d: built %d, sized %d", name, base, sLen, len(answer), want)
				}
				if _, err := ParseDNSDatagramLite(answer); err != nil {
					t.Fatalf("%s, base64 %v, S of %d: %v", name, base, sLen, err)
				}
			}
		}
	}
}

func TestNekoSealedRoundTrip(t *testing.T) {
	keys := sealKeys(t, "00112233445566778899aabbccddeeff")
	for _, size := range []uint16{0, 512, 1232, 4096} {
		query, err := BuildTXTQuestionPacket("abcdefgh.a.example.com", Enums.DNS_RECORD_TYPE_TXT, size)
		if err != nil {
			t.Fatal(err)
		}
		limit := RequesterUDPSize(query)
		for _, base := range []bool{false, true} {
			for _, payloadLen := range []int{0, 1, 7, 100, 180, 240, 250, 400, 700, 1000, 1150, 1300} {
				payload := bytes.Repeat([]byte{0x5a}, payloadLen)
				for i := range payload {
					payload[i] = byte(i * 7)
				}
				packet := VpnProto.Packet{
					SessionID: 9, SessionCookie: 77, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 3, SequenceNum: 11,
					Payload: payload,
				}
				answer, err := BuildSealedVPNResponsePacket(query, "abcdefgh.a.example.com", packet, base, keys, 0)
				if err != nil {
					t.Fatal(err)
				}
				got, err := ExtractSealedVPNResponse(answer, base, keys)
				if err != nil {
					t.Fatalf("size %d, base64 %v, payload %d: %v", size, base, payloadLen, err)
				}
				if got.SessionID != 9 || got.SessionCookie != 77 || got.PacketType != Enums.PACKET_STREAM_DATA ||
					got.StreamID != 3 || got.SequenceNum != 11 || !bytes.Equal(got.Payload, payload) {
					t.Fatalf("size %d, base64 %v, payload %d: %+v", size, base, payloadLen, got)
				}
				// the padding never takes an answer past what the requester takes; one too large unpadded is whole
				frame, _ := buildResponseFrame(packet)
				unpadded, _ := SealedAnswerLen(query, "abcdefgh.a.example.com", mdseal.Overhead+len(frame), base)
				if unpadded <= limit && len(answer) > limit {
					t.Fatalf("size %d, base64 %v, payload %d: %d bytes padded past %d", size, base, payloadLen, len(answer), limit)
				}
				// the open reader takes none of it
				if _, err := ExtractVPNResponse(answer, base); err == nil {
					if open, _ := ExtractVPNResponse(answer, base); open.PacketType == Enums.PACKET_STREAM_DATA && bytes.Equal(open.Payload, payload) {
						t.Fatal("a sealed answer read open")
					}
				}
			}
		}
	}
}

// neko: S is a multiple of 64 when the answer has room, its length otherwise as far as the requester or the session's
// cap goes
func TestNekoSealedPadding(t *testing.T) {
	keys := sealKeys(t, "00112233445566778899aabbccddeeff")
	query, _ := BuildTXTQuestionPacket("abcdefgh.a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	sealedLen := func(answer []byte, base bool) int {
		parsed, err := ParsePacket(answer)
		if err != nil {
			t.Fatal(err)
		}
		s, err := assembleSealed(extractTXTAnswerPayloads(parsed), base)
		if err != nil {
			t.Fatal(err)
		}
		return len(s)
	}
	packet := VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_PONG, Payload: []byte("1234567")}
	for _, base := range []bool{false, true} {
		answer, _ := BuildSealedVPNResponsePacket(query, "abcdefgh.a.example.com", packet, base, keys, 0)
		if n := sealedLen(answer, base); n%mdseal.Block != 0 {
			t.Fatalf("base64 %v: S of %d", base, n)
		}
		// the session's cap: S of a large frame no longer than the cap, never shorter than the frame sealed
		big := VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, Payload: bytes.Repeat([]byte{1}, 600)}
		frame, _ := buildResponseFrame(big)
		least := mdseal.Overhead + len(frame)
		answer, _ = BuildSealedVPNResponsePacket(query, "abcdefgh.a.example.com", big, base, keys, least+3)
		if n := sealedLen(answer, base); n != least+3 {
			t.Fatalf("base64 %v: S of %d under a cap of %d", base, n, least+3)
		}
		answer, _ = BuildSealedVPNResponsePacket(query, "abcdefgh.a.example.com", big, base, keys, least-10)
		if n := sealedLen(answer, base); n != least {
			t.Fatalf("base64 %v: S of %d under a cap below the frame (%d)", base, n, least)
		}
	}
	// a requester of 512: the padding stops at its size
	small, _ := BuildTXTQuestionPacket("abcdefgh.a.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	for payloadLen := 380; payloadLen <= 470; payloadLen++ {
		packet := VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, Payload: bytes.Repeat([]byte{2}, payloadLen)}
		answer, _ := BuildSealedVPNResponsePacket(small, "abcdefgh.a.example.com", packet, false, keys, 0)
		frame, _ := buildResponseFrame(packet)
		unpadded, _ := SealedAnswerLen(small, "abcdefgh.a.example.com", mdseal.Overhead+len(frame), false)
		if unpadded <= 512 && len(answer) > 512 {
			t.Fatalf("payload %d: %d bytes for a requester of 512", payloadLen, len(answer))
		}
		if unpadded <= 512 && len(answer) < 512 && sealedLen(answer, false)%mdseal.Block != 0 {
			t.Fatalf("payload %d: room left (%d bytes) but S of %d", payloadLen, len(answer), sealedLen(answer, false))
		}
	}
}

func TestNekoSealedRefused(t *testing.T) {
	keys := sealKeys(t, "00112233445566778899aabbccddeeff")
	other := sealKeys(t, "ffeeddccbbaa99887766554433221100")
	query, _ := BuildTXTQuestionPacket("abcdefgh.a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	packet := VpnProto.Packet{SessionID: 4, PacketType: Enums.PACKET_ERROR_DROP, Payload: []byte("12345678")}
	for _, base := range []bool{false, true} {
		sealed, _ := BuildSealedVPNResponsePacket(query, "abcdefgh.a.example.com", packet, base, keys, 0)
		if _, err := ExtractSealedVPNResponse(sealed, base, other); !errors.Is(err, ErrSealTag) {
			t.Fatalf("base64 %v: another key's answer: %v", base, err)
		}
		open, _ := BuildVPNResponsePacket(query, "abcdefgh.a.example.com", packet, base)
		if _, err := ExtractSealedVPNResponse(open, base, keys); err == nil {
			t.Fatalf("base64 %v: an open answer opened", base)
		}
		// the same sealed answer to another query (an ERROR_DROP seen on the path, sent again): it fits none but its
		// own; the name's case as a resolver may have changed it does not matter
		other, _ := BuildTXTQuestionPacket("abcdefgi.a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
		replayed := append(append([]byte(nil), sealed[:12]...), other[12:12+len(other)-12-11]...)
		replayed = append(replayed, sealed[12+len(query)-12-11:]...)
		if _, err := ExtractSealedVPNResponse(replayed, base, keys); !errors.Is(err, ErrSealTag) {
			t.Fatalf("base64 %v: a sealed answer under another question: %v", base, err)
		}
		upper := append([]byte(nil), sealed...)
		for i := 12; i < 12+len(query)-12-11-4; i++ {
			if upper[i] >= 'a' && upper[i] <= 'z' {
				upper[i] -= 'a' - 'A'
			}
		}
		if got, err := ExtractSealedVPNResponse(upper, base, keys); err != nil || got.PacketType != Enums.PACKET_ERROR_DROP {
			t.Fatalf("base64 %v: the question in upper case: %v", base, err)
		}
	}
	// parts: one missing, one twice, a count that does not match
	big := VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, Payload: bytes.Repeat([]byte{3}, 700)}
	frame, _ := buildResponseFrame(big)
	s := keys.Seal("abcdefgh.a.example.com", frame, -1)
	chunks, _ := sealedTXTChunks(s, false)
	if len(chunks) < 3 {
		t.Fatalf("%d parts", len(chunks))
	}
	raw := func(chunks [][]byte) [][]byte {
		out := make([][]byte, len(chunks))
		for i, c := range chunks {
			out[i] = c[1:]
		}
		return out
	}
	whole, err := assembleSealed(raw(chunks), false)
	if err != nil || !bytes.Equal(whole, s) {
		t.Fatalf("parts in order: %v", err)
	}
	reversed := raw(chunks)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if got, err := assembleSealed(reversed, false); err != nil || !bytes.Equal(got, s) {
		t.Fatalf("parts out of order: %v", err)
	}
	for name, parts := range map[string][][]byte{
		"missing": raw(chunks)[:len(chunks)-1],
		"twice":   append(raw(chunks)[:len(chunks)-1], raw(chunks)[1]),
	} {
		if _, err := assembleSealed(parts, false); err == nil {
			t.Fatalf("%s part assembled", name)
		}
	}
}
