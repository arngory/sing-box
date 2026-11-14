package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"sync"

	C "github.com/sagernet/sing-box/constant"
)

// The SHA-256 of the public key (SubjectPublicKeyInfo) of every root of a list this core carries.
//
// neko: the naive outbound is Chromium, which verifies against the store it was built with and can be given another
// list only in place of it, without certificate transparency and Chrome's limits on roots. And Chromium's own store
// is not this core's list of Chrome's roots: the list's generator leaves out the roots CCADB marks China, Chromium
// has them. So a naive outbound is held to the list of the core's store besides its own: Chromium verifies as it
// does, and a key of that list has to be in the chain it verified (these hashes as its key pins). Under "chrome"
// that is Chrome's list as the rest of the core takes it; under "mozilla" the roots the two lists share.
//
// The chain Chromium verified does not always reach a root: its store has intermediates as trust anchors of their
// own (Google Trust Services' and Let's Encrypt's in Chromium 158), and a chain through one ends there, with no
// root's key in it. So the pins of a list also hold each such intermediate whose root the list has
// (StorePublicKeyHashes). Which intermediates those are is the library's to say: its store is the one it verifies
// with (cronet.ChromeRootStoreAnchors in the naive outbound). The table here, generated from Chromium's own
// repository at the library's release (chromium_anchors_neko_generated.go), is the check of that: the two have to
// agree (protocol/naive's tests), and the app's build stops when its release is not the library's.
var (
	ChromePublicKeyHashes  = sync.OnceValue(func() [][]byte { return publicKeyHashes(chromeIncludedPEM()) })
	MozillaPublicKeyHashes = sync.OnceValue(func() [][]byte { return publicKeyHashes(mozillaIncludedPEM()) })
)

// IntermediateAnchor is an intermediate a verifier's store has as a trust anchor of its own: the SHA-256 of its key
// and of its root's key.
type IntermediateAnchor struct {
	Key     [sha256.Size]byte
	RootKey [sha256.Size]byte
}

// StorePublicKeyHashes are the pins for a store by its kind: the keys of the list's roots and of the [anchors]
// whose root is among them. Nil for a kind that is no list of this core's (the system's store, none), where naive is
// held to nothing besides Chromium's own verification.
func StorePublicKeyHashes(kind string, anchors []IntermediateAnchor) [][]byte {
	var roots [][]byte
	switch kind {
	case C.CertificateStoreChrome:
		roots = ChromePublicKeyHashes()
	case C.CertificateStoreMozilla:
		roots = MozillaPublicKeyHashes()
	default:
		return nil
	}
	return withIntermediateAnchors(roots, anchors)
}

// ChromiumIntermediateAnchors are the intermediate anchors of Chromium's store at the release of
// ChromiumAnchorsVersion, from its own repository: the check of the library's table.
func ChromiumIntermediateAnchors() []IntermediateAnchor {
	anchors := make([]IntermediateAnchor, 0, len(chromiumIntermediateAnchors))
	for _, anchor := range chromiumIntermediateAnchors {
		key, keyErr := base64.StdEncoding.DecodeString(anchor.key)
		rootKey, rootErr := base64.StdEncoding.DecodeString(anchor.rootKey)
		if keyErr != nil || rootErr != nil || len(key) != sha256.Size || len(rootKey) != sha256.Size {
			// generated: a test fails on it (TestNekoStoreHashesHaveChromiumIntermediateAnchors)
			continue
		}
		anchors = append(anchors, IntermediateAnchor{Key: [sha256.Size]byte(key), RootKey: [sha256.Size]byte(rootKey)})
	}
	return anchors
}

// chromiumIntermediateAnchor is a row of the generated table: the hashes in base64.
type chromiumIntermediateAnchor struct {
	key     string
	rootKey string
}

// withIntermediateAnchors adds to the hashes of a list's roots those of the intermediates whose root is among them:
// an intermediate of a root the list does not have stays out, as its root does. The roots' slice is not changed.
func withIntermediateAnchors(roots [][]byte, anchors []IntermediateAnchor) [][]byte {
	listed := make(map[string]bool, len(roots))
	for _, hash := range roots {
		listed[string(hash)] = true
	}
	hashes := append(make([][]byte, 0, len(roots)+len(anchors)), roots...)
	for _, anchor := range anchors {
		if !listed[string(anchor.RootKey[:])] || listed[string(anchor.Key[:])] {
			continue
		}
		listed[string(anchor.Key[:])] = true
		key := anchor.Key
		hashes = append(hashes, key[:])
	}
	return hashes
}

func publicKeyHashes(list string) [][]byte {
	var hashes [][]byte
	rest := []byte(list)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return hashes
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		hash := sha256.Sum256(root.RawSubjectPublicKeyInfo)
		hashes = append(hashes, hash[:])
	}
}
