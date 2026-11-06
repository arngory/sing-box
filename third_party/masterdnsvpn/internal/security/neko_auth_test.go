package security

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func nekoSeq(from, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(from + i)
	}
	return out
}

// dnsauth-masterdns.md §2, computed apart from this code: the whole query
func TestNekoAuthVector(t *testing.T) {
	codec, err := NewCodec(5, "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(codec.key); got != "5947d7c33d783f94b3b4c1a96ebc8991ed28f1b069b71e03376cba8caa98a720" {
		t.Fatalf("AES key %s", got)
	}
	k, _ := hex.DecodeString("2f9bd5e6fc2ef3f56206998eee87f2d4b798a66c3c846ef34eff2f2647599bd5")
	const epoch = 1767268800 / 600
	tagger := func(nonce, frame []byte) (tag [AuthTagLen]byte) {
		mac := hmac.New(sha256.New, k)
		mac.Write([]byte("dnsauth1"))
		mac.Write(binary.BigEndian.AppendUint32(nil, epoch))
		mac.Write(nonce)
		mac.Write(frame)
		copy(tag[:], mac.Sum(nil))
		return tag
	}
	if tag := tagger(nekoSeq(0, 12), nekoSeq(12, 12)); hex.EncodeToString(tag[:]) != "67e1435d89134138" {
		t.Fatalf("tag %x", tag)
	}
	if err := codec.SetTagger(tagger); err != nil {
		t.Fatal(err)
	}
	randRead = func(b []byte) (int, error) { return copy(b, nekoSeq(0, len(b))), nil }
	defer func() { randRead = defaultRandRead }()

	sealed, err := codec.Encrypt(nekoSeq(12, 12))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sealed); got != "000102030405060708090a0b32c491aa95ea072a19bc306ccefca5c41b5dc961da6a8ecbb51828fda63aee7b209d70a1" {
		t.Fatalf("query %s", got)
	}
	encoded, err := codec.EncryptAndEncodeBytes(nekoSeq(12, 12))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(encoded); got != "000e52t6l1i0jhjxfso43ob7psm1qqejdehkhlwss24k23ugrkfn5hqfoktbmt7k1m2ky2sxa081" {
		t.Fatalf("base36 %s", got)
	}
	nonce, plain, err := codec.DecodeStringAndOpen(string(encoded))
	if err != nil || !bytes.Equal(nonce, nekoSeq(0, 12)) || !bytes.Equal(plain[AuthTagLen:], nekoSeq(12, 12)) ||
		hex.EncodeToString(plain[:AuthTagLen]) != "67e1435d89134138" {
		t.Fatalf("opened %x %x %v", nonce, plain, err)
	}
}

func TestNekoAuthNeedsAEAD(t *testing.T) {
	for _, method := range []int{0, 1, 2} {
		codec, err := NewCodec(method, "00112233445566778899aabbccddeeff")
		if err != nil {
			t.Fatal(err)
		}
		if err := codec.SetTagger(func(_, _ []byte) [AuthTagLen]byte { return [AuthTagLen]byte{} }); err != ErrAuthNeedsAEAD {
			t.Fatalf("method %d: %v", method, err)
		}
		if _, _, err := codec.DecodeStringAndOpen("abc"); err != ErrAuthNeedsAEAD {
			t.Fatalf("method %d open: %v", method, err)
		}
	}
	// a codec without a tagger encrypts as upstream: the frame alone under GCM
	codec, _ := NewCodec(5, "00112233445566778899aabbccddeeff")
	sealed, _ := codec.Encrypt(nekoSeq(12, 12))
	plain, err := codec.Decrypt(sealed)
	if err != nil || !bytes.Equal(plain, nekoSeq(12, 12)) {
		t.Fatalf("untagged %x %v", plain, err)
	}
}
