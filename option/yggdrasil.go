package option

import "github.com/sagernet/sing/common/json/badoption"

// YggdrasilEndpointOptions joins the Yggdrasil mesh network (neko): outbound to 200::/7
// addresses, inbound for connections to this node's address.
type YggdrasilEndpointOptions struct {
	// peering connections dial through these options (detour, interface binding)
	DialerOptions
	// ed25519 private key, 128 hex digits (seed and public key), as yggdrasil-go writes it
	PrivateKey string `json:"private_key"`
	// peer URIs: tls://host:port, tcp://, quic://, ws://, wss://, socks://
	Peers []string `json:"peers,omitempty"`
	// listen URIs for incoming peering, e.g. tls://0.0.0.0:0
	Listen            []string           `json:"listen,omitempty"`
	AllowedPublicKeys []string           `json:"allowed_public_keys,omitempty"`
	NodeInfo          map[string]any     `json:"node_info,omitempty"`
	NodeInfoPrivacy   bool               `json:"node_info_privacy,omitempty"`
	UDPTimeout        badoption.Duration `json:"udp_timeout,omitempty"`
}
