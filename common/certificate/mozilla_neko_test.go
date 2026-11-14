package certificate

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

// The keys of Mozilla's roots, for the naive outbound's pins under the store "mozilla": one hash per root of the
// list, Let's Encrypt's root among them by the hash everyone publishes, and what the list shares with Chrome's
// is nearly all of Chrome's.
func TestNekoMozillaPublicKeyHashes(t *testing.T) {
	hashes := MozillaPublicKeyHashes()
	roots := bytes.Count([]byte(mozillaIncludedPEM()), []byte("BEGIN CERTIFICATE"))
	if len(hashes) != roots || roots < 100 {
		t.Fatalf("%d hashes for %d roots of Mozilla's list", len(hashes), roots)
	}
	has := func(hash []byte) bool {
		for _, h := range hashes {
			if bytes.Equal(h, hash) {
				return true
			}
		}
		return false
	}
	// ISRG Root X1 (Let's Encrypt), the SPKI hash of its documentation
	isrg, _ := base64.StdEncoding.DecodeString("C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=")
	if !has(isrg) {
		t.Fatal("ISRG Root X1's key is not among the hashes")
	}
	shared, chrome := 0, 0
	rest := []byte(chromeIncludedPEM())
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chrome++
		if hash := sha256.Sum256(root.RawSubjectPublicKeyInfo); has(hash[:]) {
			shared++
		}
	}
	t.Logf("Mozilla's list %d roots, Chrome's %d, keys in both %d", roots, chrome, shared)
	if shared < chrome*9/10 {
		t.Fatalf("only %d of Chrome's %d roots have a key in Mozilla's list: a profile under both would lose most public sites", shared, chrome)
	}
}

// The roots Chromium 158 carries in its own store (root_store.certs, store version 43, the port at 1d6fa422) and
// this core's list of Chrome's roots does not: the list's generator leaves out roots CCADB marks China, and
// Chromium's store has them. A naive outbound without pins or a certificate of its own is held to the core's list by
// key pins (StorePublicKeyHashes), so under "chrome" none of the nine passes, and under "mozilla" the three that
// have a key in Mozilla's list do. The test fails when the lists move.
//
// The hashes are the library builder's (SHA-256 of the SPKI), of one Chromium version, counted again with the next
// library. Three of them are checked here against Mozilla's list; the other six have nothing in this repository to
// be checked against (Chromium's store is not in it).
var chromiumOnlyRoots = map[string]string{
	"CFCA EV ROOT":                 "3V7RwJD59EgGG6qUprsRAXVE6e76ogzHFM5sYz9dxik=",
	"GDCA TrustAUTH R5 ROOT":       "zrGUEcZQUsdX+UHrgmyWlB5NCNCWx9t+fqPE+ME/GhM=",
	"Hongkong Post Root CA 3":      "JUHlO6WzsHrL5wl6xKA+BAwRz3ptSmfLIT1Vi1AWegY=",
	"TrustAsia TLS ECC Root CA":    "9GMuWHAcC9fa/H44MTVexDP8E3d94oZoPo7FCWTfBFI=",
	"TrustAsia TLS RSA Root CA":    "ViiHLiRf5mFIuAut6snED2JS5kL6lZWuzks+ili4/UY=",
	"UCA Extended Validation Root": "XEGnOrLDXfzXcfb9bj6PrJtGnThsrdpWqVtkbrSMyjQ=",
	"UCA Global G2 Root":           "ElXKvoFS+mTflC96R0F+KflsHOEb+MhOy+KBXMEoCBA=",
	"vTrus ECC Root CA":            "oka4Ivls/swVUVblR2lXhFSSrPMhh+yKLvEtiWGNcR0=",
	"vTrus Root CA":                "4GZH5SYQFgw+g8QtIuOaqHUMWE1sJK+u1UphFkdCAAo=",
}

func TestNekoChromeListLeavesOutChromiumOnlyRoots(t *testing.T) {
	// what a naive outbound is pinned to under each store
	inChrome := map[string]bool{}
	for _, hash := range StorePublicKeyHashes(C.CertificateStoreChrome) {
		inChrome[base64.StdEncoding.EncodeToString(hash)] = true
	}
	if roots := bytes.Count([]byte(chromeIncludedPEM()), []byte("BEGIN CERTIFICATE")); len(inChrome) != roots || roots < 50 {
		t.Fatalf("%d hashes for %d roots of Chrome's list", len(inChrome), roots)
	}
	if len(StorePublicKeyHashes(C.CertificateStoreMozilla)) != len(MozillaPublicKeyHashes()) ||
		StorePublicKeyHashes(C.CertificateStoreSystem) != nil || StorePublicKeyHashes(C.CertificateStoreNone) != nil ||
		StorePublicKeyHashes("") != nil {
		t.Fatal("which stores hold naive to a list")
	}
	// the three of them Mozilla's list has: their hashes are of real keys, or they would match nothing
	wantInMozilla := map[string]bool{
		"Hongkong Post Root CA 3": true, "TrustAsia TLS ECC Root CA": true, "TrustAsia TLS RSA Root CA": true,
	}
	inMozilla := 0
	for name, hash := range chromiumOnlyRoots {
		raw, err := base64.StdEncoding.DecodeString(hash)
		if err != nil || len(raw) != sha256.Size {
			t.Fatalf("%s: not a SHA-256: %q", name, hash)
		}
		if inChrome[hash] {
			t.Errorf("%s is in the core's list of Chrome's roots now: the lists moved, count again", name)
		}
		found := false
		for _, h := range MozillaPublicKeyHashes() {
			if bytes.Equal(h, raw) {
				found = true
				inMozilla++
			}
		}
		if found != wantInMozilla[name] {
			t.Errorf("%s: a key in Mozilla's list: %v, want %v (a hash that is not the key's, or the lists moved)", name, found, wantInMozilla[name])
		}
	}
	t.Logf("%d roots of Chromium's own store are not in the core's list of Chrome's; %d of them have a key in Mozilla's", len(chromiumOnlyRoots), inMozilla)
}
