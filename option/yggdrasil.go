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
	// InboundListed lets in only InboundSources, the mesh addresses a connection to this node may come from (neko):
	// any other sender gets no answer at all (its packets never reach the stack, but the answers to what this node
	// dialled), and a new flow from it is dropped before its handshake; with no sources, none. Off: every flow is
	// taken, for the route rules to decide. A flag of its own: the options' parser drops an empty list
	InboundListed  bool                             `json:"inbound_listed,omitempty"`
	InboundSources badoption.Listable[netip.Prefix] `json:"inbound_sources,omitempty"`
	UDPTimeout     badoption.Duration               `json:"udp_timeout,omitempty"`
	// TLSFingerprint is the ClientHello of outgoing tls:// links: "" or "chrome" (uTLS, a browser
	// ClientHello), "go" (crypto/tls, as yggdrasil-go sends it)
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// Multicast finds this node's peers on the local network, as yggdrasil-go's multicast does (neko): on the
	// interfaces an entry names, a beacon sent and the others' heard, and a link to each node found that knows the
	// same password. The links dial as the peers' do (DialerOptions)
	Multicast []YggdrasilMulticastOptions `json:"multicast,omitempty"`
}

// YggdrasilMulticastOptions is one entry of yggdrasil-go's MulticastInterfaces (neko).
type YggdrasilMulticastOptions struct {
	// Interface is a regular expression of the interfaces' names, as "^wlan[0-9]+$"
	Interface string `json:"interface"`
	// Beacon: this node is announced there; Listen: the others' beacons are heard, and dialled
	Beacon bool `json:"beacon,omitempty"`
	Listen bool `json:"listen,omitempty"`
	// Port of the link listener a beacon offers; 0: any free one
	Port     uint16 `json:"port,omitempty"`
	Priority uint8  `json:"priority,omitempty"`
	// Password: only nodes that know it peer; at most 64 bytes, as yggdrasil-go takes it
	Password string `json:"password,omitempty"`
}
