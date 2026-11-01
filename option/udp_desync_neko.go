package option

// UDPDesyncOptions shape the first datagrams of a QUIC client flow
// (common/udpdesync, neko).
type UDPDesyncOptions struct {
	// Prelude is the number of fake datagrams before the first real one (0-8).
	Prelude int `json:"prelude,omitempty"`
	// PreludeSNI makes the fakes QUIC Initials naming this server; empty = random bytes.
	PreludeSNI string `json:"prelude_sni,omitempty"`
	// PreludeTTL sends the fakes with this IP TTL so they expire before the server; 0 = default.
	PreludeTTL int `json:"prelude_ttl,omitempty"`
	// ReorderInitial sends the second QUIC Initial before the first.
	ReorderInitial bool `json:"reorder_initial,omitempty"`
}
