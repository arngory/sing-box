package compression

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// neko: a frame's payload inflates to at most 64 KiB; a bomb is refused, an MTU's payload goes through.
func TestNekoDecompressBounded(t *testing.T) {
	for _, typ := range []uint8{TypeZSTD, TypeLZ4, TypeZLIB} {
		// past the minimum size up to the cap: zstd frames of small payloads declare a window of their own size
		for _, size := range []int{101, 500, 1024, 1025, 4096, maxDecompressedSize} {
			data := bytes.Repeat([]byte("niko "), size/5+1)[:size]
			packed, got := CompressPayload(data, typ, 0)
			if got != typ {
				t.Fatalf("type %d size %d: not compressed", typ, size)
			}
			out, ok := TryDecompressPayload(packed, typ)
			if !ok || !bytes.Equal(out, data) {
				t.Fatalf("type %d size %d: round trip failed", typ, size)
			}
		}
		// random data at an MTU (zstd and lz4 may leave it as is; whatever they send must come back)
		random := make([]byte, 4096)
		rand.Read(random)
		if packed, got := CompressPayload(random, typ, 0); got != TypeOff {
			if out, ok := TryDecompressPayload(packed, got); !ok || !bytes.Equal(out, random) {
				t.Fatalf("type %d: random round trip failed", typ)
			}
		}
		// one byte past the cap
		over := bytes.Repeat([]byte{0}, maxDecompressedSize+1)
		if packed, got := CompressPayload(over, typ, 0); got == typ {
			if _, ok := TryDecompressPayload(packed, typ); ok {
				t.Fatalf("type %d: %d bytes inflated", typ, len(over))
			}
		}
	}

	// a zstd bomb as the old cap let through: 8 MB of zeros in a couple of KB (an answer's payload)
	encoder, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithWindowSize(8<<20))
	bomb := encoder.EncodeAll(make([]byte, 8<<20), nil)
	if len(bomb) > 4096 {
		t.Fatalf("bomb of %d bytes", len(bomb))
	}
	if _, ok := TryDecompressPayload(bomb, TypeZSTD); ok {
		t.Fatal("zstd bomb inflated")
	}
	// lz4's size header is believed before anything else: a claim of 10 MB is refused
	lz4 := make([]byte, 8)
	binary.LittleEndian.PutUint32(lz4, 10<<20)
	if _, ok := TryDecompressPayload(lz4, TypeLZ4); ok {
		t.Fatal("lz4 claim of 10 MB accepted")
	}
}
