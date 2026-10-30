//go:build with_yggdrasil

package yggdrasil

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

// A seed and the 64-byte key yggdrasil-go stores give the same node; the certificate
// carries that key, so the node's address follows from it.
func TestNekoYggdrasilKey(t *testing.T) {
	seed := strings.Repeat("ab", 32)
	fromSeed, err := parsePrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	fromFull, err := parsePrivateKey(hex.EncodeToString(fromSeed))
	if err != nil {
		t.Fatal(err)
	}
	if !fromSeed.Equal(fromFull) {
		t.Fatal("seed and full key differ")
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("ab", 16)} {
		if _, err = parsePrivateKey(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	certificate, err := selfSignedCertificate(fromSeed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	publicKey := parsed.PublicKey.(ed25519.PublicKey)
	if !publicKey.Equal(fromSeed.Public()) {
		t.Fatal("certificate key differs")
	}
	nodeAddress := address.AddrForKey(publicKey)
	ip, _ := netip.AddrFromSlice(nodeAddress[:])
	if !yggdrasilPrefix.Contains(ip) {
		t.Fatalf("address %s outside 200::/7", ip)
	}
}
