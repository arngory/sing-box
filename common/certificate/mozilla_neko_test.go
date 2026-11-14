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
	// and the pins of the store: the intermediates Chromium has as anchors, all of them under roots Mozilla's list has
	anchors := ChromiumIntermediateAnchors()
	if pins := StorePublicKeyHashes(C.CertificateStoreMozilla, anchors); len(pins) != roots+len(anchors) {
		t.Fatalf("%d pins for %d roots of Mozilla's list and %d intermediate anchors of Chromium's", len(pins), roots, len(anchors))
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
	anchors := ChromiumIntermediateAnchors()
	inChrome := map[string]bool{}
	for _, hash := range StorePublicKeyHashes(C.CertificateStoreChrome, anchors) {
		inChrome[base64.StdEncoding.EncodeToString(hash)] = true
	}
	if roots := bytes.Count([]byte(chromeIncludedPEM()), []byte("BEGIN CERTIFICATE")); len(inChrome) != roots+len(anchors) || roots < 50 {
		t.Fatalf("%d hashes for %d roots of Chrome's list and %d intermediate anchors of Chromium's", len(inChrome), roots, len(anchors))
	}
	if len(StorePublicKeyHashes(C.CertificateStoreMozilla, nil)) != len(MozillaPublicKeyHashes()) ||
		StorePublicKeyHashes(C.CertificateStoreSystem, anchors) != nil || StorePublicKeyHashes(C.CertificateStoreNone, anchors) != nil ||
		StorePublicKeyHashes("", anchors) != nil {
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

// A chain Chromium verified ends at the first certificate its store has as a trust anchor, and the store has
// intermediates as anchors: the chain of a Google site is its leaf and WE2, with no root in it. The pins of a list
// have to hold the keys of those intermediates, or naive refuses every server whose certificate is of Google Trust
// Services or of Let's Encrypt's current intermediates (1.50.0 before its release: www.gstatic.com refused with
// "ssl pinned key not in cert chain").
//
// The two hashes are not the generator's: real Chrome logged them as the last key of the chains it verified for
// www.gstatic.com and www.cloudflare.com (the app repository's Chrome workflow, run 43644246996). The naive outbound
// takes the anchors from the library; protocol/naive's tests check that its table and this one agree.
func TestNekoStoreHashesHaveChromiumIntermediateAnchors(t *testing.T) {
	anchors := ChromiumIntermediateAnchors()
	if ChromiumAnchorsVersion == "" || len(anchors) == 0 || len(anchors) != len(chromiumIntermediateAnchors) {
		t.Fatalf("%d intermediate anchors of %d in the table read: generate them for the library's Chromium release", len(anchors), len(chromiumIntermediateAnchors))
	}
	logged := map[string]string{
		"WE2": "vh78KSg1Ry4NaqGDV10w/cTb9VH3BQUZoCWNa93W/EY=",
		"WE1": "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
	}
	for _, kind := range []string{C.CertificateStoreChrome, C.CertificateStoreMozilla} {
		has := map[string]bool{}
		for _, hash := range StorePublicKeyHashes(kind, anchors) {
			if len(hash) != sha256.Size {
				t.Fatalf("%s: a hash of %d bytes", kind, len(hash))
			}
			has[base64.StdEncoding.EncodeToString(hash)] = true
		}
		for name, hash := range logged {
			if !has[hash] {
				t.Errorf("%s: the key of %s, where Chrome ends a chain, is not among the hashes", kind, name)
			}
		}
		for _, anchor := range chromiumIntermediateAnchors {
			if !has[anchor.rootKey] {
				t.Errorf("%s: the root %s of an intermediate anchor is not in the list: the lists moved, count again", kind, anchor.rootKey)
			} else if !has[anchor.key] {
				t.Errorf("%s: the intermediate %s is not among the hashes, its root is", kind, anchor.key)
			}
		}
		// without anchors, the roots alone: what refused www.gstatic.com
		if roots := StorePublicKeyHashes(kind, nil); len(roots) != len(has)-len(anchors) {
			t.Errorf("%s: %d pins without anchors, want the %d roots", kind, len(roots), len(has)-len(anchors))
		}
	}
	// an intermediate goes where its root goes: of a root the list does not have, it stays out
	root, other, key := [sha256.Size]byte{1}, [sha256.Size]byte{2}, [sha256.Size]byte{3}
	roots := [][]byte{root[:]}
	with := withIntermediateAnchors(roots, []IntermediateAnchor{{Key: key, RootKey: other}})
	if len(with) != 1 {
		t.Fatalf("%d hashes for one root and no intermediate of it", len(with))
	}
	with = withIntermediateAnchors(roots, []IntermediateAnchor{
		{Key: key, RootKey: root},
		{Key: key, RootKey: root},
		{Key: root, RootKey: root},
	})
	if len(with) != 2 || !bytes.Equal(with[1], key[:]) {
		t.Fatalf("%d hashes for one root and one intermediate of it, named twice", len(with))
	}
	// the list's own slice stays as it was: the pins of one outbound are not another's
	if len(roots) != 1 || cap(with) == cap(roots) && &with[0] == &roots[0] {
		t.Fatal("the roots' slice is shared with the pins")
	}
	// a malformed row of the generated table is not an anchor
	if len(ChromiumIntermediateAnchors()) != len(chromiumIntermediateAnchors) {
		t.Fatal("a row of the generated table does not read")
	}
}
