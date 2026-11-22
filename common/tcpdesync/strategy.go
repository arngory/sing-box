// Package tcpdesync shapes the first write of a TCP connection the way zapret's tpws and ByeDPI do, so that a DPI
// box reading the first segment or the first TLS record misses the server name (neko, arngory/niko
// docs/design/dpi.md §5.1). Only the cutting changes: TCP segments, TLS record headers, the order segments reach the
// path in (disorder) and an out-of-band byte the server's stack keeps out of the stream (oob). The server reads
// exactly the bytes the client wrote, so the TLS transcript hash is not touched.
//
// A strategy is a list of cuts at markers, each with a mode, and an optional list of TLS record cuts:
//
//   - split: the part is its own segment;
//   - disorder: the part goes out with TTL=1 (IPV6_UNICAST_HOPS=1) and dies on the first hop; the kernel sends it
//     again with the normal TTL after the parts behind it;
//   - oob: the part is followed by one byte sent with MSG_OOB; a server without SO_OOBINLINE drops it;
//   - disoob: oob with TTL=1.
//
// The mode of a cut is how the part that ends at it is sent; the rest after the last cut is sent normally.
package tcpdesync

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Mode is how one part of the first write is sent.
type Mode uint8

const (
	ModeSplit Mode = iota
	ModeDisorder
	ModeOOB
	ModeDisOOB
)

func (m Mode) String() string {
	switch m {
	case ModeSplit:
		return "split"
	case ModeDisorder:
		return "disorder"
	case ModeOOB:
		return "oob"
	case ModeDisOOB:
		return "disoob"
	default:
		return "mode(" + strconv.Itoa(int(m)) + ")"
	}
}

// LowTTL reports that the part is sent with TTL=1.
func (m Mode) LowTTL() bool { return m == ModeDisorder || m == ModeDisOOB }

// OutOfBand reports that the part is followed by an MSG_OOB byte.
func (m Mode) OutOfBand() bool { return m == ModeOOB || m == ModeDisOOB }

func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "split":
		return ModeSplit, nil
	case "disorder":
		return ModeDisorder, nil
	case "oob":
		return ModeOOB, nil
	case "disoob":
		return ModeDisOOB, nil
	case "fake":
		return 0, E.New("mode fake is not supported until 1.68")
	default:
		return 0, E.New("unknown mode: ", s)
	}
}

// Base is where a marker counts from.
type Base uint8

const (
	// BaseAbsolute: from the start of the first write, or from its end when the offset is negative (-1 = the last
	// byte).
	BaseAbsolute Base = iota
	// BaseHost: the first byte of the host name (TLS SNI or HTTP Host).
	BaseHost
	// BaseEndHost: the byte after the host name.
	BaseEndHost
	// BaseMidHost: the middle of the host name (ByeDPI's +sm).
	BaseMidHost
	// BaseSLD: the first byte of the second-level label (youtube in www.youtube.com).
	BaseSLD
	// BaseMidSLD: the middle of the second-level label.
	BaseMidSLD
	// BaseEndSLD: the byte after the second-level label.
	BaseEndSLD
	// BaseSNIExt: the first byte of the SNI extension's data (after its type and length).
	BaseSNIExt
)

var baseNames = map[string]Base{
	"host":    BaseHost,
	"sni":     BaseHost,
	"endhost": BaseEndHost,
	"midhost": BaseMidHost,
	"sld":     BaseSLD,
	"midsld":  BaseMidSLD,
	"endsld":  BaseEndSLD,
	"sniext":  BaseSNIExt,
}

func (b Base) String() string {
	switch b {
	case BaseAbsolute:
		return ""
	case BaseHost:
		return "host"
	case BaseEndHost:
		return "endhost"
	case BaseMidHost:
		return "midhost"
	case BaseSLD:
		return "sld"
	case BaseMidSLD:
		return "midsld"
	case BaseEndSLD:
		return "endsld"
	case BaseSNIExt:
		return "sniext"
	default:
		return "base(" + strconv.Itoa(int(b)) + ")"
	}
}

// maxOffset bounds marker offsets: a first write is at most one TLS record and a bit.
const maxOffset = 65535

// Marker is a position in the first write, as in zapret: a cut at position p goes before byte p.
type Marker struct {
	Base   Base
	Offset int
}

// ParseMarker parses "5", "-10", "sni", "sni+1", "midsld-2" and the like.
func ParseMarker(s string) (Marker, error) {
	text := strings.ToLower(strings.TrimSpace(s))
	if text == "" {
		return Marker{}, E.New("empty marker")
	}
	if n, err := strconv.Atoi(text); err == nil {
		if n > maxOffset || n < -maxOffset {
			return Marker{}, E.New("marker out of range: ", s)
		}
		return Marker{Base: BaseAbsolute, Offset: n}, nil
	}
	name, rest := text, ""
	if i := strings.IndexAny(text, "+-"); i >= 0 {
		name, rest = text[:i], text[i:]
	}
	base, ok := baseNames[name]
	if !ok {
		return Marker{}, E.New("unknown marker: ", s)
	}
	marker := Marker{Base: base}
	if rest != "" {
		if len(rest) < 2 || rest[1] < '0' || rest[1] > '9' {
			return Marker{}, E.New("bad marker offset: ", s)
		}
		n, err := strconv.Atoi(rest)
		if err != nil || n > maxOffset || n < -maxOffset {
			return Marker{}, E.New("bad marker offset: ", s)
		}
		marker.Offset = n
	}
	return marker, nil
}

func (m Marker) String() string {
	if m.Base == BaseAbsolute {
		return strconv.Itoa(m.Offset)
	}
	switch {
	case m.Offset > 0:
		return m.Base.String() + "+" + strconv.Itoa(m.Offset)
	case m.Offset < 0:
		return m.Base.String() + strconv.Itoa(m.Offset)
	default:
		return m.Base.String()
	}
}

// Split is a segment cut.
type Split struct {
	At   Marker
	Mode Mode
}

// Strategy is a parsed tcp_desync option. It is immutable and shared by the connections it applies to.
type Strategy struct {
	Splits  []Split
	TLSRec  []Marker
	OOBByte byte
}

const DefaultOOBByte = 'a'

// Parse parses a tcp_desync option (a route rule). nil gives nil.
func Parse(options *option.TCPDesyncOptions) (*Strategy, error) {
	return parse(options, "tcp_desync")
}

func parse(options *option.TCPDesyncOptions, name string) (*Strategy, error) {
	if options == nil {
		return nil, nil
	}
	if len(options.Fake) > 0 {
		return nil, E.New(name, ": fake is not supported until 1.68")
	}
	if len(options.Auto) > 0 {
		return nil, E.New(name, ": auto is not supported until 1.68")
	}
	if options.Use != "" {
		return nil, E.New(name, ": use is not supported until 1.68")
	}
	strategy := &Strategy{OOBByte: DefaultOOBByte}
	for i, split := range options.Split {
		at, err := ParseMarker(split.At)
		if err != nil {
			return nil, E.Cause(err, name, ": split[", i, "]")
		}
		mode, err := ParseMode(split.Mode)
		if err != nil {
			return nil, E.Cause(err, name, ": split[", i, "]")
		}
		strategy.Splits = append(strategy.Splits, Split{At: at, Mode: mode})
	}
	for i, rec := range options.TLSRec {
		at, err := ParseMarker(rec)
		if err != nil {
			return nil, E.Cause(err, name, ": tlsrec[", i, "]")
		}
		strategy.TLSRec = append(strategy.TLSRec, at)
	}
	switch len(options.OOBByte) {
	case 0:
	case 1:
		strategy.OOBByte = options.OOBByte[0]
	default:
		return nil, E.New(name, ": oob_byte must be one byte, got ", strconv.Quote(options.OOBByte))
	}
	if len(strategy.Splits) == 0 && len(strategy.TLSRec) == 0 {
		return nil, E.New(name, ": nothing to do: set split or tlsrec")
	}
	return strategy, nil
}

// ParseOutbound parses the desync option of a TLS outbound: the node's own handshake. Only split, oob and tlsrec
// are allowed there (design §5.4): a low-TTL part that the path does not drop where expected would sit in the
// node's stream and break REALITY.
func ParseOutbound(options *option.TCPDesyncOptions) (*Strategy, error) {
	strategy, err := parse(options, "tls.desync")
	if err != nil || strategy == nil {
		return nil, err
	}
	for i, split := range strategy.Splits {
		if split.Mode.LowTTL() {
			return nil, E.New("tls.desync: split[", i, "]: mode ", split.Mode, " is not allowed for outbound handshakes, only split and oob")
		}
	}
	return strategy, nil
}

// NeedsSocket reports that the strategy cuts segments, which needs the TCP socket itself.
func (s *Strategy) NeedsSocket() bool { return len(s.Splits) > 0 }

func (s *Strategy) String() string {
	var parts []string
	if len(s.Splits) > 0 {
		var splits []string
		for _, split := range s.Splits {
			splits = append(splits, split.At.String()+":"+split.Mode.String())
		}
		parts = append(parts, "split="+strings.Join(splits, ","))
	}
	if len(s.TLSRec) > 0 {
		var recs []string
		for _, rec := range s.TLSRec {
			recs = append(recs, rec.String())
		}
		parts = append(parts, "tlsrec="+strings.Join(recs, ","))
	}
	for _, split := range s.Splits {
		if split.Mode.OutOfBand() {
			parts = append(parts, "oob_byte="+strconv.QuoteRune(rune(s.OOBByte)))
			break
		}
	}
	return strings.Join(parts, " ")
}
