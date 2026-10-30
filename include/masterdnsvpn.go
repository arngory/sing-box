//go:build with_masterdnsvpn

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/masterdnsvpn"
)

func registerMasterDNSVPNOutbound(registry *outbound.Registry) {
	masterdnsvpn.RegisterOutbound(registry)
}
