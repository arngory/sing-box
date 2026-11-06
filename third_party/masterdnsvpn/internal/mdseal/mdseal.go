// Package mdseal is raycontrol's mdseal-v1 (docs/spec/mdseal-v1.md): a masterdns answer's frame sealed with the
// service's key, so the path no longer reads the session's ID and cookie, the packet types, PONG's counter or the
// probes' answers, nor forges any of them (neko).
//
//	P = uint16_be(len(F)) || F || 00 … 00    zeros until len(S) is a multiple of 64, as far as the answer has room
//	C = ChaCha20(Kd, R || 00 00 00 00)(P)    RFC 8439, the block counter from 0; R 8 random bytes, new in each answer
//	T = HMAC-SHA256(Kdt, R || C)[:4]         encrypt-then-MAC
//	S = R || T || C
//
// Kd, Kdt = HMAC-SHA256(K, "mdseal-v1 down", "mdseal-v1 down tag"); K is the key's text as the link gives it
// (niko-dnskey), its ASCII bytes as they are: not decoded from hex.
package mdseal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

const (
	nonceLen = 8
	tagLen   = 4
	lenLen   = 2
	// Overhead is what the seal adds to a frame before its padding: R, T and the frame's length.
	Overhead = nonceLen + tagLen + lenLen
	// Block is what a sealed answer's length is a multiple of, as far as the answer has room.
	Block = 64
)

// Mode bit of the probes' and SESSION_INIT's response mode byte that asks for sealed answers (§4).
const ModeBit = 0x80

// ErrNoKey is a seal asked for without the service's key.
var ErrNoKey = errors.New("mdseal: no key")

// Keys are a service's sealing keys.
type Keys struct {
	down, downTag []byte
}

// NewKeys derives the keys from the service's key K, its text as the link gives it.
func NewKeys(key string) (*Keys, error) {
	if key == "" {
		return nil, ErrNoKey
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	return &Keys{down: derive("mdseal-v1 down"), downTag: derive("mdseal-v1 down tag")}, nil
}

// SealedLen is the length of S for a frame of frameLen bytes with at most room bytes for S (room < 0: no bound):
// the next multiple of Block, as far as room goes; never under the frame with the overhead.
func SealedLen(frameLen, room int) int {
	least := Overhead + frameLen
	full := (least + Block - 1) / Block * Block
	if room >= 0 && full > room {
		return max(least, room)
	}
	return full
}

// Seal is S for the frame f, under a new random R, padded within room bytes (room < 0: no bound).
func (k *Keys) Seal(f []byte, room int) []byte {
	var r [nonceLen]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err) // crypto/rand does not fail on the platforms the core runs on
	}
	return k.sealWith(r, f, room)
}

func (k *Keys) sealWith(r [nonceLen]byte, f []byte, room int) []byte {
	total := SealedLen(len(f), room)
	out := make([]byte, total)
	copy(out, r[:])
	plain := out[nonceLen+tagLen:]
	binary.BigEndian.PutUint16(plain, uint16(len(f)))
	copy(plain[lenLen:], f)
	// the rest of plain is the padding: zeros, as make left it
	stream, err := newCipher(k.down, r[:])
	if err != nil {
		panic(err) // the key and the nonce have their sizes
	}
	stream.XORKeyStream(plain, plain)
	copy(out[nonceLen:], tag(k.downTag, r[:], plain))
	return out
}

// Open is the frame sealed in s; false when s is too short, its tag does not hold (not the node's, another key, an
// open answer) or its length runs past what it holds. The padding is not checked.
func (k *Keys) Open(s []byte) ([]byte, bool) {
	if len(s) < Overhead {
		return nil, false
	}
	r, t, ciphertext := s[:nonceLen], s[nonceLen:nonceLen+tagLen], s[nonceLen+tagLen:]
	if !hmac.Equal(t, tag(k.downTag, r, ciphertext)) {
		return nil, false
	}
	stream, err := newCipher(k.down, r)
	if err != nil {
		panic(err)
	}
	plain := make([]byte, len(ciphertext))
	stream.XORKeyStream(plain, ciphertext)
	n := int(binary.BigEndian.Uint16(plain))
	if lenLen+n > len(plain) {
		return nil, false
	}
	return plain[lenLen : lenLen+n], true
}

func tag(key, r, ciphertext []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(r)
	mac.Write(ciphertext)
	return mac.Sum(nil)[:tagLen]
}

// newCipher is ChaCha20 under key with the nonce R || 00 00 00 00, the block counter from 0.
func newCipher(key, r []byte) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(key, append(append(make([]byte, 0, chacha20.NonceSize), r...), 0, 0, 0, 0))
}
