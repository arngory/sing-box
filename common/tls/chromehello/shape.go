package chromehello

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// Hello is a parsed ClientHello: what two ClientHellos of the same browser share. Per-connection values (random,
// session_id, key share data, GREASE values, the order of extensions, ECH GREASE payload) are left out or
// normalized, so the Shape of the core's hello equals the Shape of the captured one exactly.
type Hello struct {
	Ciphers    []uint16
	Extensions []uint16          // in the order sent
	Data       map[uint16][]byte // extension data
}

const (
	extSNI            = 0x0000
	extSupportedGroup = 0x000a
	extSigAlgs        = 0x000d
	extALPN           = 0x0010
	extPadding        = 0x0015
	extVersions       = 0x002b
	extKeyShare       = 0x0033
	extECH            = 0xfe0d
)

// Parse reads a ClientHello record (the 5-byte TLS header first) or a bare handshake message.
func Parse(raw []byte) (*Hello, error) {
	s := cryptobyte.String(raw)
	if len(raw) > 5 && raw[0] == 0x16 {
		var body cryptobyte.String
		if !s.Skip(3) || !s.ReadUint16LengthPrefixed(&body) {
			return nil, fmt.Errorf("bad TLS record")
		}
		s = body
	}
	var msgType uint8
	var msg cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != 1 || !s.ReadUint24LengthPrefixed(&msg) {
		return nil, fmt.Errorf("not a ClientHello")
	}
	var sessionID, ciphers, compression, extensions cryptobyte.String
	if !msg.Skip(2+32) || !msg.ReadUint8LengthPrefixed(&sessionID) || !msg.ReadUint16LengthPrefixed(&ciphers) ||
		!msg.ReadUint8LengthPrefixed(&compression) || !msg.ReadUint16LengthPrefixed(&extensions) {
		return nil, fmt.Errorf("bad ClientHello")
	}
	h := &Hello{Data: map[uint16][]byte{}}
	for !ciphers.Empty() {
		var c uint16
		ciphers.ReadUint16(&c)
		h.Ciphers = append(h.Ciphers, c)
	}
	for !extensions.Empty() {
		var id uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, fmt.Errorf("bad extension")
		}
		h.Extensions = append(h.Extensions, id)
		h.Data[id] = data
	}
	return h, nil
}

func greaseOr(v uint16) string {
	if IsGREASE(v) {
		return "GREASE"
	}
	return fmt.Sprintf("%04x", v)
}

func u16list(b []byte, prefix int) []string {
	if len(b) < prefix {
		return []string{"?"}
	}
	b = b[prefix:]
	var out []string
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, greaseOr(binary.BigEndian.Uint16(b[i:])))
	}
	return out
}

// Shape is the hello as text, one line per part, comparable between two ClientHellos.
func (h *Hello) Shape() string {
	var lines []string
	var ciphers []string
	for _, c := range h.Ciphers {
		ciphers = append(ciphers, greaseOr(c))
	}
	lines = append(lines, "ciphers "+strings.Join(ciphers, ","))
	var ids []string
	for _, id := range h.Extensions {
		if id == extSNI || id == extPadding {
			continue // depends on the server name and the hello's length
		}
		ids = append(ids, greaseOr(id))
	}
	sort.Strings(ids)
	lines = append(lines, "extensions "+strings.Join(ids, ","))
	for _, id := range h.Extensions {
		if IsGREASE(id) || id == extSNI || id == extPadding {
			continue
		}
		data := h.Data[id]
		var v string
		switch id {
		case extSupportedGroup, extSigAlgs:
			v = strings.Join(u16list(data, 2), ",")
		case extVersions:
			v = strings.Join(u16list(data, 1), ",")
		case extKeyShare:
			// groups and key lengths; the keys are new per connection
			var groups []string
			s := cryptobyte.String(data)
			var shares cryptobyte.String
			s.ReadUint16LengthPrefixed(&shares)
			for !shares.Empty() {
				var group uint16
				var key cryptobyte.String
				if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&key) {
					break
				}
				groups = append(groups, fmt.Sprintf("%s/%d", greaseOr(group), len(key)))
			}
			v = strings.Join(groups, ",")
		case extECH:
			v = "present" // GREASE ECH: random payload
		default:
			v = hex.EncodeToString(data)
		}
		lines = append(lines, fmt.Sprintf("%04x %s", id, v))
	}
	sort.Strings(lines[2:])
	return strings.Join(lines, "\n")
}

// JA4 is the JA4 fingerprint of the hello (FoxIO JA4: TCP, GREASE left out everywhere, also in
// signature_algorithms).
func (h *Hello) JA4() string {
	var ciphers, exts []string
	for _, c := range h.Ciphers {
		if !IsGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
	}
	sni := "i"
	alpn := "00"
	count := 0
	for _, id := range h.Extensions {
		if IsGREASE(id) {
			continue
		}
		count++
		switch id {
		case extSNI:
			sni = "d"
			continue
		case extALPN:
			if a := alpnFirst(h.Data[id]); len(a) > 0 {
				alpn = string(a[0]) + string(a[len(a)-1])
			}
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", id))
	}
	version := "13"
	sort.Strings(ciphers)
	sort.Strings(exts)
	var sigalgs []string
	for _, a := range u16list(h.Data[extSigAlgs], 2) {
		if a != "GREASE" {
			sigalgs = append(sigalgs, a)
		}
	}
	part := func(s string) string {
		if s == "" {
			return "000000000000"
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}
	c := strings.Join(exts, ",")
	if len(sigalgs) > 0 {
		c += "_" + strings.Join(sigalgs, ",")
	}
	nCiphers := min(len(ciphers), 99)
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", version, sni, nCiphers, min(count, 99), alpn,
		part(strings.Join(ciphers, ",")), part(c))
}

func alpnFirst(data []byte) string {
	s := cryptobyte.String(data)
	var list cryptobyte.String
	var proto cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !list.ReadUint8LengthPrefixed(&proto) {
		return ""
	}
	return string(proto)
}
