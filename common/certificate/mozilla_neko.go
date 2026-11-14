package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"sync"

	C "github.com/sagernet/sing-box/constant"
)

// The SHA-256 of the public key (SubjectPublicKeyInfo) of every root of a list this core carries, and of the
// intermediates Chromium takes as trust anchors under those roots.
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
// root's key in it. So each such intermediate is in the hashes of a list that has its root
// (chromium_anchors_neko_generated.go, of the Chromium release the library is built from).
var (
	ChromePublicKeyHashes  = sync.OnceValue(func() [][]byte { return storeHashes(chromeIncludedPEM()) })
	MozillaPublicKeyHashes = sync.OnceValue(func() [][]byte { return storeHashes(mozillaIncludedPEM()) })
)

// StorePublicKeyHashes are the hashes for a store by its kind: nil for a kind that is no list of this core's (the
// system's store, none), where naive is held to nothing besides Chromium's own verification.
func StorePublicKeyHashes(kind string) [][]byte {
	switch kind {
	case C.CertificateStoreChrome:
		return ChromePublicKeyHashes()
	case C.CertificateStoreMozilla:
		return MozillaPublicKeyHashes()
	}
	return nil
}

// chromiumIntermediateAnchor is an intermediate Chromium's store has as a trust anchor: the hash of its key and of
// its root's, in base64.
type chromiumIntermediateAnchor struct {
	key     string
	rootKey string
}

func storeHashes(list string) [][]byte {
	return withIntermediateAnchors(publicKeyHashes(list), chromiumIntermediateAnchors)
}

// withIntermediateAnchors adds to the hashes of a list's roots those of the intermediates whose root is among them:
// an intermediate of a root the list does not have stays out, as its root does.
func withIntermediateAnchors(roots [][]byte, anchors []chromiumIntermediateAnchor) [][]byte {
	listed := make(map[string]bool, len(roots))
	for _, hash := range roots {
		listed[string(hash)] = true
	}
	hashes := roots
	for _, anchor := range anchors {
		rootKey, err := base64.StdEncoding.DecodeString(anchor.rootKey)
		if err != nil || !listed[string(rootKey)] {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(anchor.key)
		if err != nil || len(key) != sha256.Size || listed[string(key)] {
			continue
		}
		listed[string(key)] = true
		hashes = append(hashes, key)
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
