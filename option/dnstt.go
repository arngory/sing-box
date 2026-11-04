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
	// raycontrol dnsauth-v1: every query carries a tag of the device's key (neko)
	Auth *DNSTTAuthOptions `json:"auth,omitempty"`
}

// DNSTTAuthOptions is raycontrol dnsauth-v1 (docs/spec/dnsauth-v1.md): the tag key is derived from the device's
// SPA key for the node and the service.
type DNSTTAuthOptions struct {
	// the node's id, 32 hex digits
	NodeID string `json:"node_id"`
	// the service's number in the subscription (niko-svc)
	ServiceID uint16 `json:"service_id"`
	// the device's SPA key, 64 hex digits; or a reference the embedding app resolves (dnstt.DeviceKeys), so the
	// key stays out of the config
	DeviceKey    string `json:"device_key,omitempty"`
	DeviceKeyRef string `json:"device_key_ref,omitempty"`
}
