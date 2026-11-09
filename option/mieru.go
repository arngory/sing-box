package option

import "github.com/sagernet/sing/common/json/badoption"

// MieruOutboundOptions is a mieru client (neko), github.com/enfein/mieru/v3's client API.
type MieruOutboundOptions struct {
	DialerOptions
	ServerOptions
	// more ports or port ranges of the server, "2000-2010" (or "2000:2010"), with or instead of server_port
	ServerPorts badoption.Listable[string] `json:"server_ports,omitempty"`
	// "tcp" (default) or "udp": how the client reaches the server
	Transport string      `json:"transport,omitempty"`
	Username  string      `json:"username"`
	Password  string      `json:"password"`
	Network   NetworkList `json:"network,omitempty"`
	// "off", "low", "middle" or "high" (or MULTIPLEXING_*); empty is mieru's default
	Multiplexing string `json:"multiplexing,omitempty"`
	// "standard" or "no_wait" (or HANDSHAKE_*); empty is mieru's default (standard)
	HandshakeMode string `json:"handshake_mode,omitempty"`
	// the base64 traffic pattern of mierus:// links (traffic-pattern=)
	TrafficPattern string `json:"traffic_pattern,omitempty"`
	// UDP transport only, 1280 to 1500; 0 is mieru's default (1400)
	MTU uint32 `json:"mtu,omitempty"`
}
