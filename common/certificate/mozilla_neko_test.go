package certificate

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
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
