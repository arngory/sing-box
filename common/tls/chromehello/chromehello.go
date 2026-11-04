// Package chromehello is the ClientHello of a real Chrome, captured from the browser itself (hello.hex, where it
// came from in SOURCE), as a uTLS spec. The core's "chrome" fingerprint (uTLS, REALITY, the TLS links of Yggdrasil)
// is built from it instead of a hand-written preset, so a new Chrome is a new capture, not new code.
//
// Per connection, as Chrome does: the extension order is shuffled (ShuffleChromeTLSExtensions) and every GREASE
// value is new, also the one in signature_algorithms (Chrome 152+) that uTLS does not re-GREASE by itself. Key
// shares, random and session_id are made per connection by uTLS; the server name is never taken from the capture.
package chromehello

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"strings"
	"sync"

	utls "github.com/metacubex/utls"
)

//go:embed hello.hex
var helloHex string

//go:embed SOURCE
var Source string

var raw = sync.OnceValues(func() ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(helloHex))
})

// Raw is the captured TLS record (header included).
func Raw() ([]byte, error) {
	b, err := raw()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

// Spec returns a fresh spec for one connection: its extensions are not shared with any other.
func Spec() (*utls.ClientHelloSpec, error) {
	b, err := raw()
	if err != nil {
		return nil, err
	}
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(b)
	if err != nil {
		return nil, err
	}
	for _, extension := range spec.Extensions {
		if algorithms, ok := extension.(*utls.SignatureAlgorithmsExtension); ok {
			for i, scheme := range algorithms.SupportedSignatureAlgorithms {
				if IsGREASE(uint16(scheme)) {
					algorithms.SupportedSignatureAlgorithms[i] = utls.SignatureScheme(greaseValue())
				}
			}
		}
	}
	spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	return spec, nil
}

// IsGREASE matches the GREASE values of RFC 8701 (0x?a?a, both bytes equal).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// greaseValue is a random GREASE value as BoringSSL draws one: (seed & 0xf0) | 0x0a, in both bytes.
func greaseValue() uint16 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	v := uint16(b[0]&0xf0) | 0x0a
	return v<<8 | v
}
