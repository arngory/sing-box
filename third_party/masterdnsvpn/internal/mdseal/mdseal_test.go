package mdseal

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mdseal-v1.md §9, computed apart from this code
func TestVectors(t *testing.T) {
	keys, err := NewKeys("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(keys.down); got != "98a7c64c2873c0f9ba78cfc12e9902bd1f2081ac478d1db3cbce83eb78bd0a02" {
		t.Fatalf("Kd %s", got)
	}
	if got := hex.EncodeToString(keys.downTag); got != "939c7d33a720441963e78291d5b51c24e26a3f61a62a5c0fd082dac66c6061c5" {
		t.Fatalf("Kdt %s", got)
	}
	r := [8]byte{0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7}
	frame := make([]byte, 42)
	for i := range frame {
		frame[i] = byte(i)
	}
	for _, c := range []struct {
		name  string
		frame []byte
		room  int
		want  string
	}{
		{"42 bytes", frame, -1, "c0c1c2c3c4c5c6c76b0519aed048831995597c85674215c3b694e25a0e45f90ba648aed96769262065593728b4aa31559f5ae03c5c8bb7f898f170e0f11e838c"},
		{"empty", nil, -1, "c0c1c2c3c4c5c6c7a8a96dfdd0628318975a788061451dcabc9fee57004ae91ab45bbacc717e3e397f422b35aab51174bd79c4197aac9fd198f170e0f11e838c"},
		{"room of 60", frame, 60, "c0c1c2c3c4c5c6c702724ce3d048831995597c85674215c3b694e25a0e45f90ba648aed96769262065593728b4aa31559f5ae03c5c8bb7f898f170e0"},
	} {
		s := keys.sealWith(r, c.frame, c.room)
		if got := hex.EncodeToString(s); got != c.want {
			t.Fatalf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
		opened, ok := keys.Open(s)
		if !ok || !bytes.Equal(opened, c.frame) {
			t.Fatalf("%s: opened %x, %v", c.name, opened, ok)
		}
	}
}

func TestLengths(t *testing.T) {
	for _, c := range []struct{ frame, room, want int }{
		{42, -1, 64}, {0, -1, 64}, {50, -1, 64}, {51, -1, 128}, {42, 60, 60}, {42, 56, 56},
		// no room even for the frame: never cut, the caller's size check sends it truncated
		{42, 40, 56},
		{500, 1232, 576}, {1200, 1232, 1216}, {1210, 1232, 1232}, {1219, 1232, 1233},
	} {
		if got := SealedLen(c.frame, c.room); got != c.want {
			t.Fatalf("frame %d, room %d: %d, want %d", c.frame, c.room, got, c.want)
		}
	}
}

func TestOpenRefuses(t *testing.T) {
	keys, _ := NewKeys("00112233445566778899aabbccddeeff")
	other, _ := NewKeys("ffeeddccbbaa99887766554433221100")
	s := keys.Seal([]byte("frame"), -1)
	if _, ok := other.Open(s); ok {
		t.Fatal("another key's answer opened")
	}
	for i := range s {
		bad := append([]byte(nil), s...)
		bad[i] ^= 1
		if _, ok := keys.Open(bad); ok {
			t.Fatalf("a bit flipped at %d still opened", i)
		}
	}
	if _, ok := keys.Open(s[:Overhead-1]); ok {
		t.Fatal("a short answer opened")
	}
	// an open frame is not a sealed one
	if _, ok := keys.Open(append([]byte{0, 1, 2}, bytes.Repeat([]byte{9}, 60)...)); ok {
		t.Fatal("an open frame opened")
	}
	// a length past what the answer holds: the tag holds (the node's own key), the length does not
	long := keys.sealWith([8]byte{}, nil, 16)
	stream := xorStream(keys, long[:8])
	plain := make([]byte, len(long)-12)
	stream(plain, long[12:])
	plain[0], plain[1] = 0, 200
	stream(long[12:], plain)
	copy(long[8:12], tag(keys.downTag, long[:8], long[12:]))
	if _, ok := keys.Open(long); ok {
		t.Fatal("a length past the answer opened")
	}
	if _, err := NewKeys(""); err != ErrNoKey {
		t.Fatal("no key accepted")
	}
}

func xorStream(k *Keys, r []byte) func(dst, src []byte) {
	return func(dst, src []byte) {
		c, err := newCipher(k.down, r)
		if err != nil {
			panic(err)
		}
		c.XORKeyStream(dst, src)
	}
}
