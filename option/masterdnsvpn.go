package option

// MasterDNSVPNOutboundOptions configures an embedded MasterDnsVPN client (neko), a DNS
// tunnel with its own server. In "socks5" mode the server connects to the requested
// destination, in "tcp" mode to its one fixed target.
type MasterDNSVPNOutboundOptions struct {
	DialerOptions
	Domains          []string `json:"domains"`
	Resolvers        []string `json:"resolvers"`
	EncryptionMethod int      `json:"encryption_method,omitempty"`
	EncryptionKey    string   `json:"encryption_key,omitempty"`
	// "socks5" (default) or "tcp", as the server's PROTOCOL_TYPE
	Mode string `json:"mode,omitempty"`
	// further client config keys, as in client_config.toml (PACKET_DUPLICATION_COUNT, ...)
	Extra map[string]any `json:"extra,omitempty"`
	// raycontrol mdseal-v1: "optional" or "required" as the node's link gives it (niko-mdseal), "" off; the key is
	// EncryptionKey's text
	Seal string `json:"seal,omitempty"`
	// raycontrol dnsauth for masterdns: the device's tag in every query, its key as dnstt's (AES-GCM methods 3-5)
	Auth *DNSTTAuthOptions `json:"auth,omitempty"`
}
