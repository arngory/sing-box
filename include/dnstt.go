//go:build with_dnstt

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/dnstt"
)

func registerDNSTTOutbound(registry *outbound.Registry) {
	dnstt.RegisterOutbound(registry)
}
