package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

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
	Listen            []string       `json:"listen,omitempty"`
	AllowedPublicKeys []string       `json:"allowed_public_keys,omitempty"`
	NodeInfo          map[string]any `json:"node_info,omitempty"`
	NodeInfoPrivacy   bool           `json:"node_info_privacy,omitempty"`
	// DebugPrivacy leaves the mesh's remote getSelf, getPeers and getTree unanswered: a node with a session to this
	// one does not learn its peers (neko, yggdrasil-go fork)
	DebugPrivacy bool `json:"debug_privacy,omitempty"`
	// InboundSources are the mesh addresses a connection to this node may come from (neko): set, any other sender
	// gets no answer at all (its packets never reach the stack, but the answers to what this node dialled), and a
	// new flow from it is dropped before its handshake; an empty list lets in none. Unset: every flow is taken, for
	// the route rules to decide
	InboundSources *badoption.Listable[netip.Prefix] `json:"inbound_sources,omitempty"`
	UDPTimeout     badoption.Duration                `json:"udp_timeout,omitempty"`
	// TLSFingerprint is the ClientHello of outgoing tls:// links: "" or "chrome" (uTLS, a browser
	// ClientHello), "go" (crypto/tls, as yggdrasil-go sends it)
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
}
