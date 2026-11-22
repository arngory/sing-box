package option

import (
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// TCPDesyncOptions is a strategy for the first write of a TCP connection
// (common/tcpdesync, neko; arngory/niko docs/design/dpi.md §5.1).
//
//	{"split": [{"at": "1", "mode": "split"}, {"at": "sni+1", "mode": "disoob"}], "tlsrec": ["sni+2"], "oob_byte": "a"}
type TCPDesyncOptions struct {
	// Split cuts the first write into TCP segments at markers. The mode of an entry is how the part that ends at
	// its marker is sent: split, disorder, oob or disoob.
	Split []TCPDesyncSplitOptions `json:"split,omitempty"`
	// TLSRec cuts the first TLS record into several records at markers, before the segment cuts.
	TLSRec badoption.Listable[string] `json:"tlsrec,omitempty"`
	// OOBByte is the byte sent out of band by the oob modes; empty = "a".
	OOBByte string `json:"oob_byte,omitempty"`

	// Fake, Auto and Use are reserved for 1.68 and rejected until then.
	Fake json.RawMessage `json:"fake,omitempty" schema:"omit"`
	Auto json.RawMessage `json:"auto,omitempty" schema:"omit"`
	Use  string          `json:"use,omitempty" schema:"omit"`
}

type TCPDesyncSplitOptions struct {
	// At is a marker: a number (negative = from the end) or host/sni, endhost, midhost, sld, midsld, endsld,
	// sniext, each with an optional +N/-N.
	At string `json:"at"`
	// Mode is split (default), disorder, oob or disoob.
	Mode string `json:"mode,omitempty" enum:"split,disorder,oob,disoob"`
}
