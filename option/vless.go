package option

type VLESSInboundOptions struct {
	ListenOptions
	Users []VLESSUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions   `json:"transport,omitempty"`
}

type VLESSUser struct {
	Name string `json:"name,omitempty"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type VLESSOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
	// Encryption enables the VLESS post-quantum layer (from sing-box-lx), beneath
	// the transport and independent of TLS:
	// "mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding>].<key>...";
	// empty or "none" leaves it off
	Encryption string      `json:"encryption,omitempty"`
	Network    NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
	PacketEncoding *string                   `json:"packet_encoding,omitempty"`
}
