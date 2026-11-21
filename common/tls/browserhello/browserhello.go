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
	"errors"
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
	// ReuseX25519: the client puts one X25519 key in its X25519MLKEM768 share and in its X25519 one (Firefox does,
	// Chromium and Safari do not). A hello with two different keys there is told from the client's at a glance.
	ReuseX25519 bool
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
		reuse, err := reusesX25519(raw)
		if err != nil {
			return nil, err
		}
		out[entry.Name()] = &Capture{
			Name:        entry.Name(),
			Raw:         raw,
			Source:      strings.TrimSpace(string(source)),
			Shuffle:     strings.TrimSpace(string(shuffle)) == "yes",
			ReuseX25519: reuse,
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

// Apply makes u send the capture (a fresh spec), and where the client reuses its X25519 key gives the X25519 share the
// X25519 half of the hybrid one, that key then answering for both.
func (c *Capture) Apply(u *utls.UConn) error {
	spec, err := c.Spec()
	if err != nil {
		return err
	}
	if err = u.ApplyPreset(spec); err != nil {
		return err
	}
	if !c.ReuseX25519 {
		return nil
	}
	keys := u.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil {
		return errors.New("no hybrid X25519 key to reuse")
	}
	for _, extension := range u.Extensions {
		if shares, ok := extension.(*utls.KeyShareExtension); ok {
			for i := range shares.KeyShares {
				if shares.KeyShares[i].Group == utls.X25519 {
					shares.KeyShares[i].Data = keys.MlkemEcdhe.PublicKey().Bytes()
				}
			}
		}
	}
	keys.Ecdhe = keys.MlkemEcdhe
	return nil
}

// KeyShares are the key shares of a ClientHello record, by group.
func KeyShares(raw []byte) (map[uint16][]byte, error) {
	h, err := chromehello.Parse(raw)
	if err != nil {
		return nil, err
	}
	data := h.Data[0x0033]
	out := make(map[uint16][]byte)
	if len(data) < 2 {
		return out, nil
	}
	for k := 2; k+4 <= len(data); {
		group, size := uint16(data[k])<<8|uint16(data[k+1]), int(data[k+2])<<8|int(data[k+3])
		if k+4+size > len(data) {
			return nil, errors.New("key share cut short")
		}
		out[group] = data[k+4 : k+4+size]
		k += 4 + size
	}
	return out, nil
}

func reusesX25519(raw []byte) (bool, error) {
	shares, err := KeyShares(raw)
	if err != nil {
		return false, err
	}
	hybrid, x25519 := shares[uint16(utls.X25519MLKEM768)], shares[uint16(utls.X25519)]
	return len(hybrid) > 32 && len(x25519) == 32 && string(hybrid[len(hybrid)-32:]) == string(x25519), nil
}
