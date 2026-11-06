package udpserver

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// neko: mdseal-v1 (raycontrol docs/spec/mdseal-v1.md). Bit 7 of the response mode byte of MTU_UP_REQ, MTU_DOWN_REQ
// and SESSION_INIT asks for sealed answers: a probe's answer is sealed when its byte had it, a session's answers all
// when its SESSION_INIT's had it (the bit is in the ten bytes that reuse a session, so a sealed and an open INIT never
// share one). The encoding is the byte without it.

const (
	sealOff uint8 = iota
	sealOptional
	sealRequired
)

// ParseSealMode is mdseal-v1 §5's mode by its name: "", "off", "optional", "required".
func ParseSealMode(mode string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "off":
		return sealOff, nil
	case "optional":
		return sealOptional, nil
	case "required":
		return sealRequired, nil
	default:
		return 0, fmt.Errorf("masterdnsvpn: seal %q (off, optional or required)", mode)
	}
}

// SetSeal sets the seal mode and the service's key K, its text (mdseal-v1 §2), the key New's codec is of; before the
// server runs. Keys set later (SetKeys) get their own seal keys in this mode.
func (s *Server) SetSeal(mode uint8, key string) error {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	keys := s.currentKeys()
	if len(keys) == 0 {
		return errors.New("masterdnsvpn: no key")
	}
	first := *keys[0]
	first.text = key
	first.seal = nil
	if mode != sealOff {
		seal, err := mdseal.NewKeys(key)
		if err != nil {
			return err
		}
		first.seal = seal
	}
	next := append(serviceKeys{&first}, keys[1:]...)
	s.sealMode = mode
	s.keys.Store(&next)
	return nil
}

// responseModeAllowed is whether a probe or SESSION_INIT may ask for answers in mode: a known encoding, the seal as
// this server's mode lets it (off: an old server, for which bit 7 is an unknown mode; required: only sealed).
func (s *Server) responseModeAllowed(mode uint8) bool {
	if mode&^mdseal.ModeBit > mtuProbeModeBase64 {
		return false
	}
	sealed := mode&mdseal.ModeBit != 0
	switch s.sealMode {
	case sealRequired:
		return sealed
	case sealOptional:
		return true
	default:
		return !sealed
	}
}

// answer builds the answer carrying packet in the response mode mode: base64 by its low bit, sealed by bit 7 with
// key's seal keys (the session's key, or before a session the query's; with capS the session's cap, 0 for a probe's
// answer).
func (s *Server) answer(questionPacket []byte, requestName string, packet VpnProto.Packet, mode uint8, capS int, key *serviceKey) ([]byte, error) {
	base := mode&^mdseal.ModeBit == mtuProbeModeBase64
	if mode&mdseal.ModeBit != 0 {
		// a sealed answer asked for is never sent open (responseModeAllowed lets bit 7 in with a seal mode only)
		if key == nil || key.seal == nil {
			return nil, mdseal.ErrNoKey
		}
		return DnsParser.BuildSealedVPNResponsePacket(questionPacket, requestName, packet, base, key.seal, capS)
	}
	return DnsParser.BuildVPNResponsePacket(questionPacket, requestName, packet, base)
}

// unknownSessionDropMode is the mode of an ERROR_DROP to a session this server does not know: raw always, sealed when
// every answer is (required); a client reads it in either encoding. Upstream alternated raw and base64, which marked
// the answers to such a session.
func (s *Server) unknownSessionDropMode() uint8 {
	if s.sealMode == sealRequired {
		return mtuProbeModeRaw | mdseal.ModeBit
	}
	return mtuProbeModeRaw
}

// sessionSealCap is the most S an answer in a session takes: the S of its probe answer at its download MTU, so the
// padding never takes an answer past what the probe found (mdseal-v1 §3, §7).
func sessionSealCap(downloadMTU int) int {
	return mdseal.SealedLen(VpnProto.HeaderRawSize(Enums.PACKET_MTU_DOWN_RES)+downloadMTU, -1)
}

// randomPayload is n random bytes: PONG's and ERROR_DROP's payloads, where upstream put a marker and a shared
// counter through xorshift32, which can be undone (neko)
func randomPayload(n int) []byte {
	payload := make([]byte, n)
	if _, err := rand.Read(payload); err != nil {
		panic(err)
	}
	return payload
}
