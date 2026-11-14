package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"sync"
)

// MozillaPublicKeyHashes are the SHA-256 of the public key (SubjectPublicKeyInfo) of every root of Mozilla's list as
// this core carries it.
//
// neko: the naive outbound is Chromium, which verifies against Chrome's list and can be given another list only in
// place of it, without certificate transparency and Chrome's limits on roots. Under the store "mozilla" it is held to
// both lists instead: Chromium verifies as it does, and a key of a Mozilla root has to be in the chain it verified
// (these hashes as its key pins). What that leaves is the roots the two lists share.
var MozillaPublicKeyHashes = sync.OnceValue(func() [][]byte {
	var hashes [][]byte
	rest := []byte(mozillaIncludedPEM())
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
})
