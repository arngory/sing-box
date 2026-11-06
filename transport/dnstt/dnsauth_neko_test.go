package dnstt

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// TestNekoDNSAuthVector: K and the tag of dnsauth-v1 (raycontrol docs/spec/dnsauth-v1.md §2-§3), against values
// computed independently from the spec (Python hmac/hashlib) and confirmed by raycontrol (TestDerivedKeyVectors)
// and niko-server (TestTagVector); the second, the spec's own.
func TestNekoDNSAuthVector(t *testing.T) {
	key, err := AuthKey(bytes.Repeat([]byte{0x11}, 32), strings.Repeat("33", 16), 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != "2f9bd5e6fc2ef3f56206998eee87f2d4b798a66c3c846ef34eff2f2647599bd5" {
		t.Fatalf("K %s", got)
	}
	payload := make([]byte, 24)
	for i := range payload {
		payload[i] = byte(i)
	}
	if got := hex.EncodeToString(authTag(key, payload, time.Unix(1767268800, 0))); got != "67e1435d89134138" {
		t.Fatalf("tag %s", got)
	}
	// the epoch is 10 minutes: the same tag within it, another after
	if !bytes.Equal(authTag(key, payload, time.Unix(1767268800+599, 0)), authTag(key, payload, time.Unix(1767268800, 0))) ||
		bytes.Equal(authTag(key, payload, time.Unix(1767268800+600, 0)), authTag(key, payload, time.Unix(1767268800, 0))) {
		t.Fatal("epoch")
	}
	// the spec's own vector (dnsauth-v1 §2), as raycontrol TestDerivedKeyVectors: key 00..1f, node a0..af, svc 3
	ordered := make([]byte, 32)
	for i := range ordered {
		ordered[i] = byte(i)
	}
	key2, err := AuthKey(ordered, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key2); got != "0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c" {
		t.Fatalf("K of the spec's vector %s", got)
	}
	if _, err = AuthKey(make([]byte, 31), strings.Repeat("33", 16), 3); err == nil {
		t.Fatal("short device key accepted")
	}
}

// TestNekoDNSAuthQuery: a query with a key starts with the tag of the rest of its payload; the MTU is 8 smaller.
func TestNekoDNSAuthQuery(t *testing.T) {
	key, _ := AuthKey(bytes.Repeat([]byte{0x11}, 32), strings.Repeat("33", 16), 3)
	plain, err := NewClient(ClientOptions{Domain: "t.example.com", PubKey: strings.Repeat("ab", 32)})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewClient(ClientOptions{Domain: "t.example.com", PubKey: strings.Repeat("ab", 32), AuthKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if plain.mtu-signed.mtu != authTagLen {
		t.Fatalf("MTU %d and %d", plain.mtu, signed.mtu)
	}
}

// TestNekoDNSAuthV2Vector: dnsauth-v2's field (raycontrol docs/spec/dnsauth-v2.md §6), against the spec's values
// (computed in Python apart from the code; the slipstream client's meson test checks the same).
func TestNekoDNSAuthV2Vector(t *testing.T) {
	key, _ := hex.DecodeString("0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c")
	msg := make([]byte, 24)
	for i := range msg {
		msg[i] = byte(i)
	}
	now := time.Unix(1767268800, 0)
	if got := hex.EncodeToString(AuthField(key, 2, now, msg)); got != "2d82b1220002a927" {
		t.Fatalf("field %s", got)
	}
	// the parts are one message: split anywhere, the same tag
	if got := hex.EncodeToString(AuthField(key, 2, now, msg[:5], msg[5:])); got != "2d82b1220002a927" {
		t.Fatalf("split field %s", got)
	}
	if got := hex.EncodeToString(AuthField(key, 2, now.Add(-600*time.Second), msg)[:2]); got != "a5f9" {
		t.Fatalf("hint (epoch - 1) %s", got)
	}
	if got := hex.EncodeToString(AuthField(key, 2, now.Add(600*time.Second), msg)[:2]); got != "e97f" {
		t.Fatalf("hint (epoch + 1) %s", got)
	}
	// the hint is the device's for the epoch, whatever the message; v1 stays v1
	if !bytes.Equal(AuthField(key, 2, now, []byte("other"))[:2], AuthField(key, 2, now, msg)[:2]) {
		t.Fatal("the hint follows the message")
	}
	if !bytes.Equal(AuthField(key, 1, now, msg), AuthTag(key, now, msg)) {
		t.Fatal("v1 is not the v1 tag")
	}
	for version, want := range map[uint8]int{0: 1, 1: 1, 2: 2} {
		if got, err := AuthVersion(version); err != nil || got != want {
			t.Fatalf("version %d: %d %v", version, got, err)
		}
	}
	if _, err := AuthVersion(3); err == nil {
		t.Fatal("version 3 accepted")
	}
}
