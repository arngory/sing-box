package option

import (
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type NaiveInboundOptions struct {
	ListenOptions
	Users                 []auth.User `json:"users,omitempty"`
	Network               NetworkList `json:"network,omitempty"`
	QUICCongestionControl string      `json:"quic_congestion_control,omitempty" enum:"bbr,cubic,reno"`
	InboundTLSOptionsContainer
}

type NaiveOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username                 string                   `json:"username,omitempty"`
	Password                 string                   `json:"password,omitempty"`
	InsecureConcurrency      int                      `json:"insecure_concurrency,omitempty"`
	ExtraHeaders             badoption.HTTPHeader     `json:"extra_headers,omitempty"`
	ReceiveWindow            *byteformats.MemoryBytes `json:"stream_receive_window,omitempty"`
	UDPOverTCP               *UDPOverTCPOptions       `json:"udp_over_tcp,omitempty"`
	QUIC                     bool                     `json:"quic,omitempty"`
	QUICCongestionControl    string                   `json:"quic_congestion_control,omitempty" enum:"bbr,bbr2,cubic,reno"`
	QUICSessionReceiveWindow *byteformats.MemoryBytes `json:"quic_session_receive_window,omitempty"`
	OutboundTLSOptionsContainer
	// neko: ping and traceroute through the node (raycontrol icmp-v1, icmp=1 in its links): the TUN hands the app's
	// echo requests to the outbound, which carries them on a stream to icmp.niko.arpa:0
	ICMP bool `json:"icmp,omitempty"`
	// neko: a TCP dial returns only after the proxy's answer to its CONNECT, which a server that takes the request
	// header niko-ack: 1 sends once it has reached the destination (raycontrol naive-uot-v1 §4.1, niko-ack=1 in its
	// links): a refused or unreachable destination fails the dial with its reason. The header goes with every
	// CONNECT
	AwaitDial bool `json:"await_dial,omitempty"`
	// neko: over QUIC, take a server whose chain verifies against a locally trusted root, one of the file the
	// SSL_CERT_FILE environment variable names (Linux, Android). Without it Chromium wants a root of its own list
	// over QUIC, as Chrome does, while over HTTP/2 it takes such a root either way. The chain, the name and the
	// key pins are checked as before; with tls.certificate it changes nothing.
	QUICLocallyTrustedRoots bool `json:"quic_locally_trusted_roots,omitempty"`
}
