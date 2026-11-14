package certificate

import (
	"crypto/sha256"
	"crypto/x509"
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
// does, and a key of a root of that list has to be in the chain it verified (these hashes as its key pins). Under
// "chrome" that is Chrome's list as the rest of the core takes it; under "mozilla" the roots the two lists share.
var (
	ChromePublicKeyHashes  = sync.OnceValue(func() [][]byte { return publicKeyHashes(chromeIncludedPEM()) })
	MozillaPublicKeyHashes = sync.OnceValue(func() [][]byte { return publicKeyHashes(mozillaIncludedPEM()) })
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
