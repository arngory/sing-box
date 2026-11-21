// Package browserhello holds the ClientHellos of real clients, one per uTLS fingerprint name (captures/<name>), as
// uTLS specs: the core's "firefox", "safari" and the rest send what that client was seen to send, not uTLS's
// hand-written preset of an older version, and a new version is a new capture, not new code. niko's browser-hellos.yml
// captures them on disposable runners, as fingerprint.yml does Chrome's (chromehello).
//
// Per connection, as the client does: every GREASE value is new (uTLS draws those of ciphers, groups, versions and
// extensions; signature_algorithms is redrawn here, where Chromium has one), and a client that shuffles its
// extensions (SHUFFLE) gets them shuffled as Chrome's are. Key shares, random and session_id are uTLS's per
// connection; the server name is never the capture's.
package browserhello

import (
	"embed"
	"encoding/hex"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/common/tls/chromehello"

	utls "github.com/metacubex/utls"
)

//go:embed captures
var captures embed.FS

// Capture is one client's ClientHello.
type Capture struct {
	Name    string
	Raw     []byte // the TLS record, header included
	Source  string
	Shuffle bool
}

var all = sync.OnceValues(func() (map[string]*Capture, error) {
	out := make(map[string]*Capture)
	entries, err := fs.ReadDir(captures, "captures")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := path.Join("captures", entry.Name())
		helloHex, err := fs.ReadFile(captures, path.Join(dir, "hello.hex"))
		if err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(helloHex)))
		if err != nil {
			return nil, err
		}
		source, _ := fs.ReadFile(captures, path.Join(dir, "SOURCE"))
		shuffle, _ := fs.ReadFile(captures, path.Join(dir, "SHUFFLE"))
		out[entry.Name()] = &Capture{
			Name:    entry.Name(),
			Raw:     raw,
			Source:  strings.TrimSpace(string(source)),
			Shuffle: strings.TrimSpace(string(shuffle)) == "yes",
		}
	}
	return out, nil
})

// Get is the capture for a fingerprint name, if there is one.
func Get(name string) (*Capture, bool) {
	m, err := all()
	if err != nil {
		return nil, false
	}
	c, ok := m[name]
	return c, ok
}

// Names are the fingerprint names with a capture, sorted.
func Names() []string {
	m, _ := all()
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Spec is a fresh spec for one connection: its extensions are shared with no other.
func (c *Capture) Spec() (*utls.ClientHelloSpec, error) {
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(c.Raw)
	if err != nil {
		return nil, err
	}
	for _, extension := range spec.Extensions {
		if algorithms, ok := extension.(*utls.SignatureAlgorithmsExtension); ok {
			for i, scheme := range algorithms.SupportedSignatureAlgorithms {
				if chromehello.IsGREASE(uint16(scheme)) {
					algorithms.SupportedSignatureAlgorithms[i] = utls.SignatureScheme(chromehello.GREASEValue())
				}
			}
		}
	}
	if c.Shuffle {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}
