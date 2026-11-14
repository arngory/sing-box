//go:build with_naive_outbound

package naive

import (
	"encoding/base64"
	"testing"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing-box/common/certificate"
	C "github.com/sagernet/sing-box/constant"
)

// The intermediate anchors the naive outbound pins come from the library's table (cronet.ChromeRootStoreAnchors,
// made from the Chromium source the library is built from). The core has a table of its own, generated from
// Chromium's repository at the library's release, with each intermediate checked to be signed by its root (the
// library's generator does not check that): the two have to agree, or one of them is of another store. Linked with
// the library: the app's interop workflow runs it, where it builds the core with the naive outbound.
func TestNekoAnchorsOfTheLibraryAreTheCoresTable(t *testing.T) {
	library := libraryAnchors()
	own := certificate.ChromiumIntermediateAnchors()
	intermediates := 0
	for _, anchor := range cronet.ChromeRootStoreAnchors() {
		if anchor.Intermediate {
			intermediates++
		}
	}
	if intermediates == 0 || len(library) != intermediates {
		t.Fatalf("%d of the library's %d intermediate anchors have their root in its table", len(library), intermediates)
	}
	key := func(a certificate.IntermediateAnchor) string {
		return base64.StdEncoding.EncodeToString(a.Key[:]) + " of " + base64.StdEncoding.EncodeToString(a.RootKey[:])
	}
	ours := make(map[string]bool, len(own))
	for _, anchor := range own {
		ours[key(anchor)] = true
	}
	theirs := make(map[string]bool, len(library))
	for _, anchor := range library {
		theirs[key(anchor)] = true
		if !ours[key(anchor)] {
			t.Errorf("the library's anchor %s is not in the core's table (Chromium %s): regenerate it", key(anchor), certificate.ChromiumAnchorsVersion)
		}
	}
	for _, anchor := range own {
		if !theirs[key(anchor)] {
			t.Errorf("the core's anchor %s is not in the library's store %d", key(anchor), cronet.ChromeRootStoreVersion)
		}
	}
	t.Logf("the library's store %d: %d intermediate anchors, the same as the core's table of Chromium %s",
		cronet.ChromeRootStoreVersion, len(library), certificate.ChromiumAnchorsVersion)
}

// The roots of the library's store the core's list of Chrome's roots does not have: the nine of
// certificate's TestNekoChromeListLeavesOutChromiumOnlyRoots, whose hashes that test can check only partly (three are
// in Mozilla's list). Here all nine are checked against the store the library carries.
func TestNekoLibraryRootsBeyondTheChromeList(t *testing.T) {
	inList := make(map[string]bool)
	for _, hash := range certificate.StorePublicKeyHashes(C.CertificateStoreChrome, nil) {
		inList[string(hash)] = true
	}
	want := map[string]bool{
		"3V7RwJD59EgGG6qUprsRAXVE6e76ogzHFM5sYz9dxik=": true, // CFCA EV ROOT
		"zrGUEcZQUsdX+UHrgmyWlB5NCNCWx9t+fqPE+ME/GhM=": true, // GDCA TrustAUTH R5 ROOT
		"JUHlO6WzsHrL5wl6xKA+BAwRz3ptSmfLIT1Vi1AWegY=": true, // Hongkong Post Root CA 3
		"9GMuWHAcC9fa/H44MTVexDP8E3d94oZoPo7FCWTfBFI=": true, // TrustAsia TLS ECC Root CA
		"ViiHLiRf5mFIuAut6snED2JS5kL6lZWuzks+ili4/UY=": true, // TrustAsia TLS RSA Root CA
		"XEGnOrLDXfzXcfb9bj6PrJtGnThsrdpWqVtkbrSMyjQ=": true, // UCA Extended Validation Root
		"ElXKvoFS+mTflC96R0F+KflsHOEb+MhOy+KBXMEoCBA=": true, // UCA Global G2 Root
		"oka4Ivls/swVUVblR2lXhFSSrPMhh+yKLvEtiWGNcR0=": true, // vTrus ECC Root CA
		"4GZH5SYQFgw+g8QtIuOaqHUMWE1sJK+u1UphFkdCAAo=": true, // vTrus Root CA
	}
	roots := 0
	for _, anchor := range cronet.ChromeRootStoreAnchors() {
		if anchor.Intermediate {
			continue
		}
		roots++
		hash := base64.StdEncoding.EncodeToString(anchor.PublicKeySHA256[:])
		if inList[string(anchor.PublicKeySHA256[:])] {
			continue
		}
		if !want[hash] {
			t.Errorf("the library's root %s (%s) is not in the core's list of Chrome's, and not one of the nine", anchor.Subject, hash)
		}
		delete(want, hash)
	}
	for hash := range want {
		t.Errorf("%s is no root of the library's store, or it is in the core's list now: count again", hash)
	}
	t.Logf("the library's store %d: %d roots", cronet.ChromeRootStoreVersion, roots)
}
