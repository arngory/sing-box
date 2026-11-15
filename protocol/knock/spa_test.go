package knock

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// The vector the server implementation checks against (docs/server/SPEC.md).
func TestSPAVector(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 16)
	packet := spaPacketWith(key, nonce, 1767225600, []byte{0xaa, 0xbb}, false)
	const want = "22222222222222222222222222222222" + "000000006955b900" +
		"96884244d2f8c829abd0b8b1a4c28af18da31cdfb79f8530cb215247c1b7b72f" + "aabb"
	if got := hex.EncodeToString(packet); got != want {
		t.Fatalf("got %s", got)
	}
	now := time.Unix(1767225600, 0)
	if !spaVerify(key, packet, now.Add(20*time.Second), 30*time.Second, false) {
		t.Fatal("rejected")
	}
	if spaVerify(key, packet, now.Add(40*time.Second), 30*time.Second, false) {
		t.Fatal("stale accepted")
	}
	other := bytes.Repeat([]byte{0x12}, 32)
	if spaVerify(other, packet, now, 30*time.Second, false) {
		t.Fatal("wrong key accepted")
	}
	packet[20] ^= 1
	if spaVerify(key, packet, now, 30*time.Second, false) {
		t.Fatal("tampered accepted")
	}
}

func TestSPAPacketsDiffer(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	a, b := spaPacket(key, false), spaPacket(key, false)
	if bytes.Equal(a[:spaMinSize], b[:spaMinSize]) {
		t.Fatal("two packets are equal")
	}
	for _, p := range [][]byte{a, b} {
		if !spaVerify(key, p, time.Now(), 30*time.Second, false) {
			t.Fatal("rejected")
		}
	}
}

func TestSPAStepParse(t *testing.T) {
	steps, err := parseSequence([]Step{{Port: 62201, Network: "spa", Payload: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}})
	if err != nil || len(steps) != 1 || !steps[0].udp || len(steps[0].spaKey) != 32 {
		t.Fatal(steps, err)
	}
	if _, err = parseSequence([]Step{{Port: 1, Network: "spa", Payload: "abcd"}}); err == nil {
		t.Fatal("short key accepted")
	}
}

// v1m: the time is masked, so no byte of the packet is fixed (S9); the MAC is v1's
func TestSPAMasked(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 16)
	clear := spaPacketWith(key, nonce, 1767225600, nil, false)
	masked := spaPacketWith(key, nonce, 1767225600, nil, true)
	if !bytes.Equal(clear[spaHeader:], masked[spaHeader:]) || bytes.Equal(clear[spaNonceSize:spaHeader], masked[spaNonceSize:spaHeader]) {
		t.Fatalf("clear %x masked %x", clear, masked)
	}
	now := time.Unix(1767225600, 0)
	if !spaVerify(key, masked, now.Add(20*time.Second), 30*time.Second, true) {
		t.Fatal("rejected")
	}
	if spaVerify(key, masked, now, 30*time.Second, false) || spaVerify(key, clear, now, 30*time.Second, true) {
		t.Fatal("one form read as the other")
	}
	if spaVerify(bytes.Repeat([]byte{0x12}, 32), masked, now, 30*time.Second, true) {
		t.Fatal("wrong key accepted")
	}
	// the vector for a server: the masked time of this key, nonce and second
	if got := hex.EncodeToString(masked[spaNonceSize:spaHeader]); got != maskedTimeVector {
		t.Fatalf("masked time %s", got)
	}
	// over many packets the time's first bytes take many values (v1: always zero)
	seen := map[uint32]bool{}
	for range 64 {
		p := spaPacket(key, true)
		seen[binary.BigEndian.Uint32(p[spaNonceSize:])] = true
		if !spaVerify(key, p, time.Now(), 30*time.Second, true) {
			t.Fatal("rejected")
		}
	}
	if len(seen) < 60 {
		t.Fatalf("%d distinct heads of 64", len(seen))
	}
	steps, err := parseSequence([]Step{{Port: 62201, Network: "spa1m", Payload: hex.EncodeToString(key)}})
	if err != nil || len(steps) != 1 || !steps[0].spaMasked {
		t.Fatal(steps, err)
	}
}

const maskedTimeVector = "4bf55c0ec1d637cf"
