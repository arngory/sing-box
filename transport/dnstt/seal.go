package dnstt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	mrand "math/rand/v2"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/crypto/chacha20"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

// raycontrol dnsseal-v1 (docs/spec/dnsseal-v1.md): the framing of dnstt sealed with the zone's key K, so a DPI that
// knows dnstt no longer reads the ClientID, the padding byte, the packets' lengths or KCP's headers.
//
//	query:    N (8) || ChaCha20(Ku, N || 0^4)(00 00 00 00 || [dnsauth tag] || ClientID || frames)
//	response: R (8) || ChaCha20(Kd, R || 0^4)(uint16 length || packet, ... || 00 00 || zeros)
//
// Ku = HMAC-SHA256(K, "dnsseal-v1 up"), Kd = HMAC-SHA256(K, "dnsseal-v1 down"). A query's frames are dnstt's: a
// byte b, a packet of b bytes when b < 224, b-224 bytes of padding otherwise.

const (
	sealKeyLen = 32
	// N and the key check of a query
	sealOverhead = 8 + 4
	// a query's padding frame is 0-31 bytes long, as much as fits
	sealMaxPadding = 31
	// the labels of a sealed query are 32-63 characters long, the last one shorter
	sealLabelMin = 32
	sealLabelMax = 63
)

type sealer struct {
	up, down []byte
}

func newSealer(key []byte) (*sealer, error) {
	if len(key) != sealKeyLen {
		return nil, E.New("dnsseal: key of ", len(key), " bytes, want ", sealKeyLen)
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	return &sealer{up: derive("dnsseal-v1 up"), down: derive("dnsseal-v1 down")}, nil
}

func sealNonce(prefix []byte) []byte {
	return append(append(make([]byte, 0, chacha20.NonceSize), prefix...), 0, 0, 0, 0)
}

// sealQuery seals inner ([dnsauth tag] || ClientID || frames) under a new random N.
func (s *sealer) sealQuery(inner []byte) []byte {
	var n [8]byte
	rand.Read(n[:])
	return s.sealQueryWith(n, inner)
}

func (s *sealer) sealQueryWith(n [8]byte, inner []byte) []byte {
	plain := append(make([]byte, 4, 4+len(inner)), inner...)
	stream, err := chacha20.NewUnauthenticatedCipher(s.up, sealNonce(n[:]))
	if err != nil {
		panic(err) // the key and the nonce have their sizes
	}
	out := append(make([]byte, 0, 8+len(plain)), n[:]...)
	out = append(out, make([]byte, len(plain))...)
	stream.XORKeyStream(out[8:], plain)
	return out
}

// openResponse is a response's frames: the TXT data without R, deciphered. False for data too short to hold R.
func (s *sealer) openResponse(data []byte) ([]byte, bool) {
	if len(data) < 8 {
		return nil, false
	}
	stream, err := chacha20.NewUnauthenticatedCipher(s.down, sealNonce(data[:8]))
	if err != nil {
		panic(err)
	}
	plain := make([]byte, len(data)-8)
	stream.XORKeyStream(plain, data[8:])
	return plain, true
}

// sealPadding is a padding frame for a query that has room bytes left (its prefix byte included): random length
// from 0 to 31, no more than fits; nothing when no byte is left.
func sealPadding(room int) []byte {
	if room < 1 {
		return nil
	}
	n := mrand.IntN(min(sealMaxPadding, room-1) + 1)
	frame := make([]byte, 1+n)
	frame[0] = byte(224 + n)
	rand.Read(frame[1:])
	return frame
}

// sealLabels cuts a sealed query's base32 into labels of 32-63 characters, the last one shorter.
func sealLabels(encoded []byte) [][]byte {
	var labels [][]byte
	for len(encoded) > 0 {
		size := min(len(encoded), sealLabelMin+mrand.IntN(sealLabelMax-sealLabelMin+1))
		labels = append(labels, encoded[:size])
		encoded = encoded[size:]
	}
	return labels
}

// dnsNameCapacitySealed is what a sealed query's name under domain carries for certain, its labels at their
// shortest (32 characters and a length octet each): the bytes before base32.
func dnsNameCapacitySealed(domain dns.Name) int {
	octets := 255 - 1
	for _, label := range domain {
		octets -= len(label) + 1
	}
	characters := octets / (sealLabelMin + 1) * sealLabelMin
	if rest := octets % (sealLabelMin + 1); rest > 1 {
		characters += rest - 1
	}
	return characters * 5 / 8
}
