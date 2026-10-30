package option

// DNSTTOutboundOptions configures a dnstt client (neko): a TCP tunnel through DNS
// resolvers to a dnstt-server, which forwards every stream to its fixed upstream.
type DNSTTOutboundOptions struct {
	DialerOptions
	// the tunnel domain delegated to the dnstt server
	Domain string `json:"domain"`
	// the server's Noise public key, 64 hex digits
	PublicKey string `json:"public_key"`
	// "https://host/dns-query" (DoH), "tls://host[:853]" (DoT) or "udp://host[:53]"
	Resolver string `json:"resolver"`
	// TLS of the DoH or DoT connection to the resolver (server name, uTLS)
	TLS *OutboundTLSOptions `json:"tls,omitempty"`
}
