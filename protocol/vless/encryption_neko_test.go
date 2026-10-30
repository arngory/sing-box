package vless

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
)

// Spec strings as Xray's `xray vlessenc` prints them parse and initialize the client;
// malformed ones are config errors naming the segment.
func TestNekoVLESSEncryptionSpec(t *testing.T) {
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decapsulationKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	x25519 := base64.RawURLEncoding.EncodeToString(x25519Key.PublicKey().Bytes())
	mlkem768 := base64.RawURLEncoding.EncodeToString(decapsulationKey.EncapsulationKey().Bytes())
	for _, spec := range []string{
		"mlkem768x25519plus.native.0rtt." + x25519,
		"mlkem768x25519plus.xorpub.1rtt.100-111-1111.75-0-111." + mlkem768,
		"mlkem768x25519plus.random.1rtt." + x25519 + "." + mlkem768,
	} {
		config, err := parseClientEncryption(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec[:40], err)
		}
		client := &encryption.ClientInstance{}
		if err = client.Init(config.keys, config.xorMode, config.seconds, config.padding); err != nil {
			t.Fatalf("%s: init: %v", spec[:40], err)
		}
	}
	for spec, want := range map[string]string{
		"mlkem768x25519plus.native." + x25519:           "at least",
		"aes128.native.0rtt." + x25519:                  "unsupported encryption method",
		"mlkem768x25519plus.plain.0rtt." + x25519:       "appearance",
		"mlkem768x25519plus.native.2rtt." + x25519:      "RTT mode",
		"mlkem768x25519plus.native.0rtt.100-111-1111":   "no encryption keys",
		"mlkem768x25519plus.native.0rtt." + x25519[:30]: "length",
	} {
		_, err := parseClientEncryption(spec)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: got %v, want an error with %q", spec, err, want)
		}
	}
}
