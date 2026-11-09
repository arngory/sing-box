package option

type TrojanInboundOptions struct {
	ListenOptions
	Users []TrojanUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Fallback        *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex       *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport       *V2RayTransportOptions    `json:"transport,omitempty"`
}

type TrojanUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password"`
}

type TrojanOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string      `json:"password"`
	Network  NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions    `json:"transport,omitempty"`

	// neko: Trojan-Go extras
	TrojanGoShadowsocks *TrojanGoShadowsocksOptions `json:"trojan_go_shadowsocks,omitempty"`
	TrojanGoMux         bool                        `json:"trojan_go_mux,omitempty"`
}

// TrojanGoShadowsocksOptions is Trojan-Go's shadowsocks AEAD layer, under Trojan and over TLS/the transport.
type TrojanGoShadowsocksOptions struct {
	Method   string `json:"method,omitempty"`
	Password string `json:"password"`
}
